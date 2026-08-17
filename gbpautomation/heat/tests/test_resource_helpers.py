#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from unittest import mock

from gbpautomation.heat.engine.clients.os import grouppolicy as client_plugin
from gbpautomation.heat.engine.resources import gbpresource
from gbpautomation.heat.engine.resources import servicechain
from heat.common import exception
from neutronclient.common import exceptions
from testtools import TestCase


class GBPResourceTest(TestCase):

    def test_validate_properties(self):
        self.assertIsNone(gbpresource.GBPResource.validate_properties({}))
        self.assertEqual(
            'name not allowed in value_specs',
            gbpresource.GBPResource.validate_properties(
                {'name': 'resource', 'value_specs': {'name': 'override'}}))

    def test_validate_deprecated_property(self):
        gbpresource.GBPResource._validate_depr_property_required(
            {'current': 'value', 'deprecated': None}, 'current', 'deprecated')
        self.assertRaises(
            exception.ResourcePropertyConflict,
            gbpresource.GBPResource._validate_depr_property_required,
            {'current': 'value', 'deprecated': 'value'}, 'current',
            'deprecated')
        self.assertRaises(
            exception.StackValidationFailed,
            gbpresource.GBPResource._validate_depr_property_required,
            {'current': None, 'deprecated': None}, 'current', 'deprecated')

    def test_prepare_properties(self):
        properties = {
            'name': None,
            'description': 'description',
            'value_specs': {'custom': 'value'}
        }
        self.assertEqual(
            {'name': 'resource', 'description': 'description',
             'custom': 'value'},
            gbpresource.GBPResource.prepare_properties(properties, 'resource'))

    def test_is_built(self):
        self.assertFalse(gbpresource.GBPResource.is_built({'status': 'BUILD'}))
        self.assertTrue(gbpresource.GBPResource.is_built({'status': 'ACTIVE'}))
        self.assertTrue(gbpresource.GBPResource.is_built({'status': 'DOWN'}))
        self.assertRaises(
            exception.ResourceInError,
            gbpresource.GBPResource.is_built, {'status': 'ERROR'})
        self.assertRaises(
            exception.ResourceUnknownStatus,
            gbpresource.GBPResource.is_built, {'status': 'UNKNOWN'})

    def test_resolve_attribute(self):
        instance = object.__new__(gbpresource.GBPResource)
        instance._show_resource = mock.Mock(
            return_value={'id': 'resource-id', 'state': 'ACTIVE'})
        self.assertEqual(
            {'id': 'resource-id', 'state': 'ACTIVE'},
            instance._resolve_attribute('show'))
        self.assertEqual('ACTIVE', instance._resolve_attribute('state'))

        instance._show_resource.side_effect = exceptions.NotFound()
        instance.client_plugin = mock.Mock()
        instance.client_plugin().ignore_not_found = mock.Mock()
        self.assertIsNone(instance._resolve_attribute('state'))

    def test_confirm_delete_and_check_delete_complete(self):
        instance = object.__new__(gbpresource.GBPResource)
        with mock.patch.object(gbpresource.scheduler, 'TaskRunner') as runner:
            task = mock.Mock()
            task.step.return_value = True
            runner.return_value = task
            self.assertIs(task, instance._delete_task())
            task.start.assert_called_once_with()
        self.assertTrue(instance.check_delete_complete(task))
        task.step.assert_called_once_with()
        self.assertTrue(instance.check_delete_complete(None))


class GBPClientPluginTest(TestCase):

    def test_exception_predicates(self):
        plugin = object.__new__(client_plugin.GBPClientPlugin)
        self.assertTrue(plugin.is_not_found(exceptions.NotFound()))
        self.assertTrue(plugin.is_not_found(
            exceptions.NeutronClientException(status_code=404)))
        self.assertFalse(plugin.is_not_found(Exception()))
        self.assertTrue(plugin.is_conflict(
            exceptions.NeutronClientException(status_code=409)))
        self.assertFalse(plugin.is_conflict(Exception()))
        self.assertTrue(plugin.is_over_limit(
            exceptions.NeutronClientException(status_code=413)))
        self.assertFalse(plugin.is_over_limit(Exception()))


class ServiceChainResourceTest(TestCase):

    def test_resource_lifecycle_methods(self):
        resources = (
            (servicechain.ServiceChainNode, 'servicechain_node',
             'servicechain_node', {'name': 'node'}),
            (servicechain.ServiceChainSpec, 'servicechain_spec',
             'servicechain_spec', {'name': 'spec'}),
            (servicechain.ServiceProfile, 'service_profile',
             'service_profile', {'name': 'profile'}),
        )

        for (resource_class, resource_name, resource_key,
             properties) in resources:
            instance = object.__new__(resource_class)
            instance.properties = properties
            instance.resource_id = 'resource-id'
            instance.grouppolicy = mock.Mock()
            instance.resource_id_set = mock.Mock()
            instance.client_plugin = mock.Mock()
            instance.client_plugin().ignore_not_found = mock.Mock()
            client = instance.grouppolicy()
            create_method = getattr(client, 'create_' + resource_name)
            create_method.return_value = {
                resource_key: {'id': 'resource-id'}}

            instance.handle_create()
            instance.resource_id_set.assert_called_once_with('resource-id')
            create_method.assert_called_once_with(
                {resource_key: properties})

            show_method = getattr(client, 'show_' + resource_name)
            show_method.return_value = {
                resource_key: {'id': 'resource-id'}}
            self.assertEqual(
                {'id': 'resource-id'}, instance._show_resource())
            show_method.assert_called_once_with('resource-id')

            delete_method = getattr(client, 'delete_' + resource_name)
            instance._delete_task = mock.Mock(return_value='delete-task')
            self.assertEqual('delete-task', instance.handle_delete())
            delete_method.assert_called_once_with('resource-id')

            delete_method.reset_mock()
            delete_method.side_effect = servicechain.NeutronClientException(
                status_code=404)
            self.assertIsNone(instance.handle_delete())
            instance.client_plugin().ignore_not_found.assert_called_once()

            update_method = getattr(client, 'update_' + resource_name)
            instance.handle_update(None, None, {'name': 'updated'})
            update_method.assert_called_once_with(
                'resource-id', {resource_key: {'name': 'updated'}})

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

import copy

from unittest import mock

import six

from gbpautomation.heat.engine.resources import grouppolicy
from gbpclient.v2_0 import client as gbpclient
from heat.common import exception
from heat.common import template_format
from heat.tests.common import HeatTestCase

from heat.engine import scheduler
from heat.tests import utils


application_policy_group_template = '''
{
  "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Template to test GBP application policy group",
  "Parameters" : {},
  "Resources" : {
    "application_policy_group": {
      "Type": "OS::GroupBasedPolicy::ApplicationPolicyGroup",
      "Properties": {
        "name": "test-application-policy-group",
        "description": "test APG resource",
        "shared": True
      }
    }
  }
}
'''


policy_target_template = '''
{
  "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Template to test neutron policy target resource",
  "Parameters" : {},
  "Resources" : {
    "policy_target": {
      "Type": "OS::GroupBasedPolicy::PolicyTarget",
      "Properties": {
        "name": "test-policy-target",
        "policy_target_group_id": "ptg-id",
        "description": "test policy target resource",
        "port_id": "some-port-id",
        "fixed_ips": [{
          "subnet_id": "test-subnet",
          "ip_address": "10.0.3.21"
        }]
      }
    }
  }
}
'''


policy_target_no_port_no_fixed_ip_template = '''
{
  "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Template to test neutron policy target resource",
  "Parameters" : {},
  "Resources" : {
    "policy_target": {
      "Type": "OS::GroupBasedPolicy::PolicyTarget",
      "Properties": {
        "name": "test-policy-target",
        "policy_target_group_id": "ptg-id",
        "description": "test policy target resource",
      }
    }
  }
}
'''

policy_target_group_template = '''
{
  "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Template to test neutron policy target group resource",
  "Parameters" : {},
  "Resources" : {
    "policy_target_group": {
      "Type": "OS::GroupBasedPolicy::PolicyTargetGroup",
      "Properties": {
        "name": "test-policy-target-group",
        "description": "test policy target group resource",
        "l2_policy_id": "l2-policy-id",
        "provided_policy_rule_sets": [
            {"policy_rule_set_id": "policy_rule_set1",
             "policy_rule_set_scope": "scope1"},
            {"policy_rule_set_id": "policy_rule_set2",
             "policy_rule_set_scope": "scope2"}
        ],
        "consumed_policy_rule_sets": [
            {"policy_rule_set_id": "policy_rule_set3",
             "policy_rule_set_scope": "scope3"},
            {"policy_rule_set_id": "policy_rule_set4",
             "policy_rule_set_scope": "scope4"}
        ],
        "shared": True,
        "intra_ptg_allow": False
      }
    }
  }
}
'''

policy_target_group_with_apg_template = '''
{
  "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Template to test neutron policy target group resource",
  "Parameters" : {},
  "Resources" : {
    "policy_target_group": {
      "Type": "OS::GroupBasedPolicy::PolicyTargetGroup",
      "Properties": {
        "name": "test-policy-target-group",
        "description": "test policy target group resource",
        "application_policy_group_id": "apg-id",
        "l2_policy_id": "l2-policy-id",
        "provided_policy_rule_sets": [
            {"policy_rule_set_id": "policy_rule_set1",
             "policy_rule_set_scope": "scope1"},
            {"policy_rule_set_id": "policy_rule_set2",
             "policy_rule_set_scope": "scope2"}
        ],
        "consumed_policy_rule_sets": [
            {"policy_rule_set_id": "policy_rule_set3",
             "policy_rule_set_scope": "scope3"},
            {"policy_rule_set_id": "policy_rule_set4",
             "policy_rule_set_scope": "scope4"}
        ],
        "shared": True,
        "intra_ptg_allow": False
      }
    }
  }
}
'''

l2_policy_template = '''
{
  "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Template to test neutron l2 policy",
  "Parameters" : {},
  "Resources" : {
    "l2_policy": {
      "Type": "OS::GroupBasedPolicy::L2Policy",
      "Properties": {
        "name": "test-l2-policy",
        "description": "test L2 policy resource",
        "l3_policy_id": "l3-policy-id",
        "shared": True,
        "reuse_bd": "other-l2p",
        "network_id": "network-id"
      }
    }
  }
}
'''

l3_policy_template = '''
{
  "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Template to test neutron l3 policy",
  "Parameters" : {},
  "Resources" : {
    "l3_policy": {
      "Type": "OS::GroupBasedPolicy::L3Policy",
      "Properties": {
        "name": "test-l3-policy",
        "description": "test L3 policy resource",
        "ip_version": "4",
        "ip_pool": "10.20.20.0",
        "external_segments": [
            {"external_segment_id": "es1",
             "allocated_address": "1.1.1.1"},
        ],
        "subnet_prefix_length": 24,
        "shared": True
      }
    }
  }
}
'''

policy_classifier_template = '''
{
 "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Template to test neutron policy classifier",
  "Parameters" : {},
  "Resources" : {
  "policy_classifier": {
      "Type": "OS::GroupBasedPolicy::PolicyClassifier",
      "Properties": {
                "name": "test-policy-classifier",
                "description": "test policy classifier resource",
                "protocol": "tcp",
                "port_range": "8000-9000",
                "direction": "bi",
                "shared": True
      }
    }
  }
}
'''

policy_action_template = '''
{
 "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Template to test neutron policy action",
  "Parameters" : {},
  "Resources" : {
  "policy_action": {
      "Type": "OS::GroupBasedPolicy::PolicyAction",
      "Properties": {
                "name": "test-policy-action",
                "description": "test policy action resource",
                "action_type": "redirect",
                "action_value": "7890",
                "shared": True
      }
    }
  }
}
'''

policy_rule_template = '''
{
 "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Template to test neutron policy rule",
  "Parameters" : {},
  "Resources" : {
  "policy_rule": {
      "Type": "OS::GroupBasedPolicy::PolicyRule",
      "Properties": {
          "name": "test-policy-rule",
          "description": "test policy rule resource",
          "enabled": True,
          "policy_classifier_id": "7890",
          "policy_actions": ['3456', '1234'],
          "shared": True
      }
    }
  }
}
'''

policy_rule_set_template = '''
{
 "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Template to test policy rule set",
  "Parameters" : {},
  "Resources" : {
  "policy_rule_set": {
      "Type": "OS::GroupBasedPolicy::PolicyRuleSet",
      "Properties": {
          "name": "test-policy-rule-set",
          "description": "test policy rule set resource",
          "parent_id": "3456",
          "child_policy_rule_sets": ["7890", "1234"],
          "policy_rules": ["2345", "6789"],
          "shared": True
      }
    }
  }
}
'''

network_service_policy_template = '''
{
 "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Template to test network service policy",
  "Parameters" : {},
  "Resources" : {
  "network_service_policy": {
      "Type": "OS::GroupBasedPolicy::NetworkServicePolicy",
      "Properties": {
          "name": "test-nsp",
          "description": "test NSP resource",
          "network_service_params": [{'type': 'ip_single', 'name': 'vip',
                                      'value': 'self_subnet'}],
          "shared": True
      }
    }
  }
}
'''

external_policy_template = '''
{
 "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Template to test external policy",
  "Parameters" : {},
  "Resources" : {
  "external_policy": {
      "Type": "OS::GroupBasedPolicy::ExternalPolicy",
      "Properties": {
          "name": "test-ep",
          "description": "test EP resource",
          "external_segments": ['1234'],
          "provided_policy_rule_sets": [{
              "policy_rule_set_id": '2345',
              "policy_rule_set_scope": "scope1"
          },
          {
              "policy_rule_set_id": '8901',
              "policy_rule_set_scope": "scope2"
          }],
          "consumed_policy_rule_sets": [{
              "policy_rule_set_id": '9012',
              "policy_rule_set_scope": "scope3"
          },
          {
              "policy_rule_set_id": '9210',
              "policy_rule_set_scope": "scope4"
          }],
          "shared": True
      }
    }
  }
}
'''

external_segment_template = '''
{
 "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Template to test external segment",
  "Parameters" : {},
  "Resources" : {
  "external_segment": {
      "Type": "OS::GroupBasedPolicy::ExternalSegment",
      "Properties": {
          "name": "test-es",
          "description": "test ES resource",
          "ip_version": '6',
          "cidr": "192.168.0.0/24",
          "subnet_id": "some-subnet-id",
          "external_routes": [{
              "destination": "0.0.0.0/0",
              "nexthop": "null"
              }
          ],
          "port_address_translation": True,
          "shared": True
      }
    }
  }
}
'''

nat_pool_template = '''
{
 "AWSTemplateFormatVersion" : "2010-09-09",
  "Description" : "Template to test NAT pool",
  "Parameters" : {},
  "Resources" : {
  "nat_pool": {
      "Type": "OS::GroupBasedPolicy::NATPool",
      "Properties": {
          "name": "test-nat-pool",
          "description": "test NP resource",
          "ip_version": '6',
          "ip_pool": "192.168.0.0/24",
          "external_segment_id": '1234',
          "shared": True
      }
    }
  }
}
'''


class ApplicationPolicyGroupTest(HeatTestCase):

    def setUp(self):
        super(ApplicationPolicyGroupTest, self).setUp()
        self.mock_create = mock.patch(
            'gbpclient.v2_0.client.Client.create_application_policy_group')
        self.mock_delete = mock.patch(
            'gbpclient.v2_0.client.Client.delete_application_policy_group')
        self.mock_show = mock.patch(
            'gbpclient.v2_0.client.Client.show_application_policy_group')
        self.mock_update = mock.patch(
            'gbpclient.v2_0.client.Client.update_application_policy_group')
        self.mock_create.start()
        self.mock_delete.start()
        self.mock_show.start()
        self.mock_update.start()
        self.stub_keystoneclient()

    def tearDown(self):
        self.mock_create.stop()
        self.mock_delete.stop()
        self.mock_show.stop()
        self.mock_update.stop()
        super(ApplicationPolicyGroupTest, self).tearDown()

    def create_application_policy_group(self):
        call_dict = {
            'application_policy_group': {
                "name": "test-application-policy-group",
                "description": "test APG resource",
                "shared": True
            }
        }
        tdict = {'application_policy_group': {'id': '5678'}}
        gbpclient.Client.create_application_policy_group.return_value = tdict

        ret_val = gbpclient.Client.create_application_policy_group(call_dict)
        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])
        self.assertEqual(tdict, ret_val)

        snippet = template_format.parse(application_policy_group_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        return grouppolicy.ApplicationPolicyGroup(
            'application_policy_group',
            resource_defns['application_policy_group'], self.stack)

    def test_create(self):
        rsrc = self.create_application_policy_group()
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual((rsrc.CREATE, rsrc.COMPLETE), rsrc.state)

    def test_create_failed(self):
        call_dict = {
            'application_policy_group': {
                "name": "test-application-policy-group",
                "description": "test APG resource",
                "shared": True
            }
        }
        exc = grouppolicy.NeutronClientException()
        gbpclient.Client.create_application_policy_group.side_effect = exc

        snippet = template_format.parse(application_policy_group_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        rsrc = grouppolicy.ApplicationPolicyGroup(
            'application_policy_group',
            resource_defns['application_policy_group'], self.stack)

        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.create))
        self.assertEqual(
            'NeutronClientException: resources.application_policy_group: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.CREATE, rsrc.FAILED), rsrc.state)

        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])

    def test_delete(self):
        gbpclient.Client.delete_application_policy_group('5678')
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.show_application_policy_group.side_effect = exc

        rsrc = self.create_application_policy_group()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_show = self.mock_show.get_original()[0]
        _mocked_show.assert_has_calls([expected])

    def test_delete_already_gone(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.delete_application_policy_group.side_effect = exc

        rsrc = self.create_application_policy_group()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_delete_failed(self):
        exc = grouppolicy.NeutronClientException(status_code=400)
        gbpclient.Client.delete_application_policy_group.side_effect = exc

        rsrc = self.create_application_policy_group()
        scheduler.TaskRunner(rsrc.create)()
        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.delete))
        self.assertEqual(
            'NeutronClientException: resources.application_policy_group: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.DELETE, rsrc.FAILED), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_update(self):
        rsrc = self.create_application_policy_group()
        call_dict = {'application_policy_group': {'name': 'new name'}}
        scheduler.TaskRunner(rsrc.create)()

        update_template = copy.deepcopy(rsrc.t)
        update_template._properties['name'] = 'new name'
        scheduler.TaskRunner(rsrc.update, update_template)()

        expected = mock.call('5678', call_dict)
        _mocked_update = self.mock_update.get_original()[0]
        _mocked_update.assert_has_calls([expected])


class PolicyTargetTest(HeatTestCase):

    def setUp(self):
        super(PolicyTargetTest, self).setUp()
        self.mock_create = mock.patch(
            'gbpclient.v2_0.client.Client.create_policy_target')
        self.mock_delete = mock.patch(
            'gbpclient.v2_0.client.Client.delete_policy_target')
        self.mock_show = mock.patch(
            'gbpclient.v2_0.client.Client.show_policy_target')
        self.mock_update = mock.patch(
            'gbpclient.v2_0.client.Client.update_policy_target')
        self.mock_create.start()
        self.mock_delete.start()
        self.mock_show.start()
        self.mock_update.start()
        self.stub_keystoneclient()

    def tearDown(self):
        self.mock_create.stop()
        self.mock_delete.stop()
        self.mock_show.stop()
        self.mock_update.stop()
        super(PolicyTargetTest, self).tearDown()

    def create_policy_target(self):
        call_dict = {
            'policy_target': {
                'name': 'test-policy-target',
                'policy_target_group_id': 'ptg-id',
                "description": "test policy target resource",
                "port_id": "some-port-id",
                'fixed_ips': [
                    {'subnet_id': 'test-subnet', 'ip_address': '10.0.3.21'}
                ],
            }
        }
        tdict = {'policy_target': {'id': '5678'}}
        gbpclient.Client.create_policy_target.return_value = tdict

        ret_val = gbpclient.Client.create_policy_target(call_dict)
        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])
        self.assertEqual(tdict, ret_val)

        snippet = template_format.parse(policy_target_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        return grouppolicy.PolicyTarget(
            'policy_target', resource_defns['policy_target'], self.stack)

    def test_create(self):
        rsrc = self.create_policy_target()
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual((rsrc.CREATE, rsrc.COMPLETE), rsrc.state)

    def create_policy_target_no_port_no_fixed_ip(self):
        call_dict = {
            'policy_target': {
                'name': 'test-policy-target',
                'policy_target_group_id': 'ptg-id',
                "description": "test policy target resource",
            }
        }
        tdict = {'policy_target': {'id': '5678'}}
        gbpclient.Client.create_policy_target.return_value = tdict

        ret_val = gbpclient.Client.create_policy_target(call_dict)
        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])
        self.assertEqual(tdict, ret_val)

        snippet = template_format.parse(
            policy_target_no_port_no_fixed_ip_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        return grouppolicy.PolicyTarget(
            'policy_target', resource_defns['policy_target'], self.stack)

    def test_create_no_port_no_fixed_ip(self):
        rsrc = self.create_policy_target_no_port_no_fixed_ip()
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual((rsrc.CREATE, rsrc.COMPLETE), rsrc.state)

    def test_create_failed(self):
        call_dict = {
            'policy_target': {
                'name': 'test-policy-target',
                'policy_target_group_id': 'ptg-id',
                "description": "test policy target resource",
                "port_id": "some-port-id",
                'fixed_ips': [
                    {'subnet_id': 'test-subnet', 'ip_address': '10.0.3.21'}
                ],
            }
        }
        exc = grouppolicy.NeutronClientException()
        gbpclient.Client.create_policy_target.side_effect = exc

        snippet = template_format.parse(policy_target_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        rsrc = grouppolicy.PolicyTarget(
            'policy_target', resource_defns['policy_target'], self.stack)

        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.create))
        self.assertEqual(
            'NeutronClientException: resources.policy_target: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.CREATE, rsrc.FAILED), rsrc.state)

        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])

    def test_delete(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.show_policy_target.side_effect = exc

        rsrc = self.create_policy_target()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_show = self.mock_show.get_original()[0]
        _mocked_show.assert_has_calls([expected])

    def test_delete_already_gone(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.delete_policy_target.side_effect = exc

        rsrc = self.create_policy_target()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_delete_failed(self):
        exc = grouppolicy.NeutronClientException(status_code=400)
        gbpclient.Client.delete_policy_target.side_effect = exc

        rsrc = self.create_policy_target()
        scheduler.TaskRunner(rsrc.create)()
        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.delete))
        self.assertEqual(
            'NeutronClientException: resources.policy_target: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.DELETE, rsrc.FAILED), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_attribute(self):
        rsrc = self.create_policy_target()
        tdict = {'policy_target': {'port_id': '1234'}}
        gbpclient.Client.show_policy_target.return_value = tdict
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual('1234', rsrc.FnGetAtt('port_id'))

        expected = mock.call('5678')
        _mocked_show = self.mock_show.get_original()[0]
        _mocked_show.assert_has_calls([expected])

    def test_attribute_failed(self):
        rsrc = self.create_policy_target()
        scheduler.TaskRunner(rsrc.create)()
        error = self.assertRaises(exception.InvalidTemplateAttribute,
                                  rsrc.FnGetAtt, 'l2_policy_id')
        self.assertEqual(
            'The Referenced Attribute (policy_target l2_policy_id) is '
            'incorrect.', six.text_type(error))

    def test_update(self):
        rsrc = self.create_policy_target()
        call_dict = {
            'policy_target': {
                'policy_target_group_id': 'ptg_id_update'}}
        scheduler.TaskRunner(rsrc.create)()

        update_template = copy.deepcopy(rsrc.t)
        update_template._properties['policy_target_group_id'] = (
            'ptg_id_update')
        scheduler.TaskRunner(rsrc.update, update_template)()

        expected = mock.call('5678', call_dict)
        _mocked_update = self.mock_update.get_original()[0]
        _mocked_update.assert_has_calls([expected])


class PolicyTargetGroupTest(HeatTestCase):

    def setUp(self):
        super(PolicyTargetGroupTest, self).setUp()
        self.mock_create = mock.patch(
            'gbpclient.v2_0.client.Client.create_policy_target_group')
        self.mock_delete = mock.patch(
            'gbpclient.v2_0.client.Client.delete_policy_target_group')
        self.mock_show = mock.patch(
            'gbpclient.v2_0.client.Client.show_policy_target_group')
        self.mock_update = mock.patch(
            'gbpclient.v2_0.client.Client.update_policy_target_group')
        self.mock_create.start()
        self.mock_delete.start()
        self.mock_show.start()
        self.mock_update.start()
        self.stub_keystoneclient()

    def tearDown(self):
        self.mock_create.stop()
        self.mock_delete.stop()
        self.mock_show.stop()
        self.mock_update.stop()
        super(PolicyTargetGroupTest, self).tearDown()

    def create_policy_target_group(self):
        call_dict = {
            "policy_target_group": {
                "name": "test-policy-target-group",
                "description": "test policy target group resource",
                "l2_policy_id": "l2-policy-id",
                "provided_policy_rule_sets": {
                    "policy_rule_set1": "scope1",
                    "policy_rule_set2": "scope2"
                },
                "consumed_policy_rule_sets": {
                    "policy_rule_set3": "scope3",
                    "policy_rule_set4": "scope4"
                },
                "shared": True,
                "intra_ptg_allow": False
            }
        }
        tdict = {'policy_target_group': {'id': '5678'}}
        gbpclient.Client.create_policy_target_group.return_value = tdict

        ret_val = gbpclient.Client.create_policy_target_group(call_dict)
        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])
        self.assertEqual(tdict, ret_val)

        snippet = template_format.parse(policy_target_group_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        return grouppolicy.PolicyTargetGroup(
            'policy_target_group', resource_defns['policy_target_group'],
            self.stack)

    def create_policy_target_group_with_apg(self):
        call_dict = {
            "policy_target_group": {
                "name": "test-policy-target-group",
                "description": "test policy target group resource",
                "application_policy_group_id": "apg-id",
                "l2_policy_id": "l2-policy-id",
                "provided_policy_rule_sets": {
                    "policy_rule_set1": "scope1",
                    "policy_rule_set2": "scope2"
                },
                "consumed_policy_rule_sets": {
                    "policy_rule_set3": "scope3",
                    "policy_rule_set4": "scope4"
                },
                "shared": True,
                "intra_ptg_allow": False
            }
        }
        tdict = {'policy_target_group': {'id': '5678'}}
        gbpclient.Client.create_policy_target_group.return_value = tdict

        ret_val = gbpclient.Client.create_policy_target_group(call_dict)
        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])
        self.assertEqual(tdict, ret_val)

        snippet = template_format.parse(policy_target_group_with_apg_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        return grouppolicy.PolicyTargetGroup(
            'policy_target_group', resource_defns['policy_target_group'],
            self.stack)

    def test_create(self):
        rsrc = self.create_policy_target_group()
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual((rsrc.CREATE, rsrc.COMPLETE), rsrc.state)

    def test_create_with_apg(self):
        rsrc = self.create_policy_target_group_with_apg()
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual((rsrc.CREATE, rsrc.COMPLETE), rsrc.state)

    def test_create_failed(self):
        call_dict = {
            "policy_target_group": {
                "name": "test-policy-target-group",
                "description": "test policy target group resource",
                "l2_policy_id": "l2-policy-id",
                "provided_policy_rule_sets": {
                    "policy_rule_set1": "scope1",
                    "policy_rule_set2": "scope2"
                },
                "consumed_policy_rule_sets": {
                    "policy_rule_set3": "scope3",
                    "policy_rule_set4": "scope4"
                },
                "shared": True,
                "intra_ptg_allow": False
            }
        }
        exc = grouppolicy.NeutronClientException()
        gbpclient.Client.create_policy_target_group.side_effect = exc

        snippet = template_format.parse(policy_target_group_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        rsrc = grouppolicy.PolicyTargetGroup(
            'policy_target_group', resource_defns['policy_target_group'],
            self.stack)

        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.create))
        self.assertEqual(
            'NeutronClientException: resources.policy_target_group: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.CREATE, rsrc.FAILED), rsrc.state)

        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])

    def test_delete(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.show_policy_target_group.side_effect = exc

        rsrc = self.create_policy_target_group()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_show = self.mock_show.get_original()[0]
        _mocked_show.assert_has_calls([expected])

    def test_delete_already_gone(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.delete_policy_target_group.side_effect = exc

        rsrc = self.create_policy_target_group()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_delete_failed(self):
        exc = grouppolicy.NeutronClientException(status_code=400)
        gbpclient.Client.delete_policy_target_group.side_effect = exc

        rsrc = self.create_policy_target_group()
        scheduler.TaskRunner(rsrc.create)()
        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.delete))
        self.assertEqual(
            'NeutronClientException: resources.policy_target_group: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.DELETE, rsrc.FAILED), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_update(self):
        rsrc = self.create_policy_target_group()
        call_dict = {
            'policy_target_group': {
                'l2_policy_id': 'l2_id_update',
                'provided_policy_rule_sets': {
                    'policy_rule_set1': 'scope1',
                    'policy_rule_set2': 'scope2',
                    'policy_rule_set5': 'scope5'
                },
                'consumed_policy_rule_sets': {
                    'policy_rule_set3': 'scope3',
                    'policy_rule_set4': 'scope4',
                    'policy_rule_set6': 'scope6'
                },
                'intra_ptg_allow': True
            }
        }
        scheduler.TaskRunner(rsrc.create)()

        update_template = copy.deepcopy(rsrc.t)
        update_template._properties['l2_policy_id'] = 'l2_id_update'
        update_template._properties['provided_policy_rule_sets'] = [
            {'policy_rule_set_id': 'policy_rule_set1',
             'policy_rule_set_scope': 'scope1'},
            {'policy_rule_set_id': 'policy_rule_set2',
             'policy_rule_set_scope': 'scope2'},
            {'policy_rule_set_id': 'policy_rule_set5',
             'policy_rule_set_scope': 'scope5'}
        ]
        update_template._properties['consumed_policy_rule_sets'] = [
            {'policy_rule_set_id': 'policy_rule_set3',
             'policy_rule_set_scope': 'scope3'},
            {'policy_rule_set_id': 'policy_rule_set4',
             'policy_rule_set_scope': 'scope4'},
            {'policy_rule_set_id': 'policy_rule_set6',
             'policy_rule_set_scope': 'scope6'}
        ]
        update_template._properties['intra_ptg_allow'] = True
        scheduler.TaskRunner(rsrc.update, update_template)()

        expected = mock.call('5678', call_dict)
        _mocked_update = self.mock_update.get_original()[0]
        _mocked_update.assert_has_calls([expected])


class L2PolicyTest(HeatTestCase):

    def setUp(self):
        super(L2PolicyTest, self).setUp()
        self.mock_create = mock.patch(
            'gbpclient.v2_0.client.Client.create_l2_policy')
        self.mock_delete = mock.patch(
            'gbpclient.v2_0.client.Client.delete_l2_policy')
        self.mock_show = mock.patch(
            'gbpclient.v2_0.client.Client.show_l2_policy')
        self.mock_update = mock.patch(
            'gbpclient.v2_0.client.Client.update_l2_policy')
        self.mock_create.start()
        self.mock_delete.start()
        self.mock_show.start()
        self.mock_update.start()
        self.stub_keystoneclient()

    def tearDown(self):
        self.mock_create.stop()
        self.mock_delete.stop()
        self.mock_show.stop()
        self.mock_update.stop()
        super(L2PolicyTest, self).tearDown()

    def create_l2_policy(self):
        call_dict = {
            'l2_policy': {
                "name": "test-l2-policy",
                "description": "test L2 policy resource",
                "l3_policy_id": "l3-policy-id",
                "shared": True,
                "reuse_bd": "other-l2p",
                "network_id": "network-id",
            }
        }
        tdict = {'l2_policy': {'id': '5678'}}
        gbpclient.Client.create_l2_policy.return_value = tdict

        ret_val = gbpclient.Client.create_l2_policy(call_dict)
        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])
        self.assertEqual(tdict, ret_val)

        snippet = template_format.parse(l2_policy_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        return grouppolicy.L2Policy(
            'l2_policy', resource_defns['l2_policy'], self.stack)

    def test_create(self):
        rsrc = self.create_l2_policy()
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual((rsrc.CREATE, rsrc.COMPLETE), rsrc.state)

    def test_create_failed(self):
        call_dict = {
            'l2_policy': {
                "name": "test-l2-policy",
                "description": "test L2 policy resource",
                "l3_policy_id": "l3-policy-id",
                "shared": True,
                "reuse_bd": "other-l2p",
                "network_id": "network-id",
            }
        }
        exc = grouppolicy.NeutronClientException()
        gbpclient.Client.create_l2_policy.side_effect = exc

        snippet = template_format.parse(l2_policy_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        rsrc = grouppolicy.L2Policy(
            'l2_policy', resource_defns['l2_policy'], self.stack)

        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.create))
        self.assertEqual(
            'NeutronClientException: resources.l2_policy: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.CREATE, rsrc.FAILED), rsrc.state)

        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])

    def test_delete(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.show_l2_policy.side_effect = exc

        rsrc = self.create_l2_policy()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_show = self.mock_show.get_original()[0]
        _mocked_show.assert_has_calls([expected])

    def test_delete_already_gone(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.delete_l2_policy.side_effect = exc

        rsrc = self.create_l2_policy()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_delete_failed(self):
        exc = grouppolicy.NeutronClientException(status_code=400)
        gbpclient.Client.delete_l2_policy.side_effect = exc

        rsrc = self.create_l2_policy()
        scheduler.TaskRunner(rsrc.create)()
        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.delete))
        self.assertEqual(
            'NeutronClientException: resources.l2_policy: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.DELETE, rsrc.FAILED), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_update(self):
        rsrc = self.create_l2_policy()
        call_dict = {'l2_policy': {'l3_policy_id': 'l3_id_update'}}
        scheduler.TaskRunner(rsrc.create)()

        update_template = copy.deepcopy(rsrc.t)
        update_template._properties['l3_policy_id'] = 'l3_id_update'
        scheduler.TaskRunner(rsrc.update, update_template)()

        expected = mock.call('5678', call_dict)
        _mocked_update = self.mock_update.get_original()[0]
        _mocked_update.assert_has_calls([expected])


class L3PolicyTest(HeatTestCase):

    def setUp(self):
        super(L3PolicyTest, self).setUp()
        self.mock_create = mock.patch(
            'gbpclient.v2_0.client.Client.create_l3_policy')
        self.mock_delete = mock.patch(
            'gbpclient.v2_0.client.Client.delete_l3_policy')
        self.mock_show = mock.patch(
            'gbpclient.v2_0.client.Client.show_l3_policy')
        self.mock_update = mock.patch(
            'gbpclient.v2_0.client.Client.update_l3_policy')
        self.mock_create.start()
        self.mock_delete.start()
        self.mock_show.start()
        self.mock_update.start()
        self.stub_keystoneclient()

    def tearDown(self):
        self.mock_create.stop()
        self.mock_delete.stop()
        self.mock_show.stop()
        self.mock_update.stop()
        super(L3PolicyTest, self).tearDown()

    def create_l3_policy(self):
        call_dict = {
            'l3_policy': {
                "name": "test-l3-policy",
                "description": "test L3 policy resource",
                "ip_version": "4",
                "ip_pool": "10.20.20.0",
                "subnet_prefix_length": 24,
                "external_segments": {"es1": "1.1.1.1"},
                "shared": True
            }
        }
        tdict = {'l3_policy': {'id': '5678'}}
        gbpclient.Client.create_l3_policy.return_value = tdict

        ret_val = gbpclient.Client.create_l3_policy(call_dict)
        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])
        self.assertEqual(tdict, ret_val)

        snippet = template_format.parse(l3_policy_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        return grouppolicy.L3Policy(
            'l3_policy', resource_defns['l3_policy'], self.stack)

    def test_create(self):
        rsrc = self.create_l3_policy()
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual((rsrc.CREATE, rsrc.COMPLETE), rsrc.state)

    def test_create_failed(self):
        call_dict = {
            'l3_policy': {
                "name": "test-l3-policy",
                "description": "test L3 policy resource",
                "ip_version": "4",
                "ip_pool": "10.20.20.0",
                "subnet_prefix_length": 24,
                "external_segments": {"es1": "1.1.1.1"},
                "shared": True
            }
        }
        exc = grouppolicy.NeutronClientException()
        gbpclient.Client.create_l3_policy.side_effect = exc

        snippet = template_format.parse(l3_policy_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        rsrc = grouppolicy.L3Policy(
            'l3_policy', resource_defns['l3_policy'], self.stack)

        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.create))
        self.assertEqual(
            'NeutronClientException: resources.l3_policy: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.CREATE, rsrc.FAILED), rsrc.state)

        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])

    def test_delete(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.show_l3_policy.side_effect = exc

        rsrc = self.create_l3_policy()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_show = self.mock_show.get_original()[0]
        _mocked_show.assert_has_calls([expected])

    def test_delete_already_gone(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.delete_l3_policy.side_effect = exc

        rsrc = self.create_l3_policy()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_delete_failed(self):
        exc = grouppolicy.NeutronClientException(status_code=400)
        gbpclient.Client.delete_l3_policy.side_effect = exc

        rsrc = self.create_l3_policy()
        scheduler.TaskRunner(rsrc.create)()
        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.delete))
        self.assertEqual(
            'NeutronClientException: resources.l3_policy: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.DELETE, rsrc.FAILED), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_update(self):
        rsrc = self.create_l3_policy()
        call_dict = {
            'l3_policy': {
                'subnet_prefix_length': 28,
                'external_segments': {'es2': '2.1.1.1'}}}
        scheduler.TaskRunner(rsrc.create)()

        update_template = copy.deepcopy(rsrc.t)
        update_template._properties['subnet_prefix_length'] = 28
        update_template._properties['external_segments'] = [
            {'external_segment_id': 'es2',
             'allocated_address': '2.1.1.1'}]
        scheduler.TaskRunner(rsrc.update, update_template)()

        expected = mock.call('5678', call_dict)
        _mocked_update = self.mock_update.get_original()[0]
        _mocked_update.assert_has_calls([expected])


class PolicyClassifierTest(HeatTestCase):

    def setUp(self):
        super(PolicyClassifierTest, self).setUp()
        self.mock_create = mock.patch(
            'gbpclient.v2_0.client.Client.create_policy_classifier')
        self.mock_delete = mock.patch(
            'gbpclient.v2_0.client.Client.delete_policy_classifier')
        self.mock_show = mock.patch(
            'gbpclient.v2_0.client.Client.show_policy_classifier')
        self.mock_update = mock.patch(
            'gbpclient.v2_0.client.Client.update_policy_classifier')
        self.mock_create.start()
        self.mock_delete.start()
        self.mock_show.start()
        self.mock_update.start()
        self.stub_keystoneclient()

    def tearDown(self):
        self.mock_create.stop()
        self.mock_delete.stop()
        self.mock_show.stop()
        self.mock_update.stop()
        super(PolicyClassifierTest, self).tearDown()

    def create_policy_classifier(self):
        call_dict = {
            'policy_classifier': {
                "name": "test-policy-classifier",
                "description": "test policy classifier resource",
                "protocol": "tcp",
                "port_range": "8000-9000",
                "direction": "bi",
                "shared": True
            }
        }
        tdict = {'policy_classifier': {'id': '5678'}}
        gbpclient.Client.create_policy_classifier.return_value = tdict

        ret_val = gbpclient.Client.create_policy_classifier(call_dict)
        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])
        self.assertEqual(tdict, ret_val)

        snippet = template_format.parse(policy_classifier_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        return grouppolicy.PolicyClassifier(
            'policy_classifier', resource_defns['policy_classifier'],
            self.stack)

    def test_create(self):
        rsrc = self.create_policy_classifier()
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual((rsrc.CREATE, rsrc.COMPLETE), rsrc.state)

    def test_create_failed(self):
        call_dict = {
            'policy_classifier': {
                "name": "test-policy-classifier",
                "description": "test policy classifier resource",
                "protocol": "tcp",
                "port_range": "8000-9000",
                "direction": "bi",
                "shared": True
            }
        }
        exc = grouppolicy.NeutronClientException()
        gbpclient.Client.create_policy_classifier.side_effect = exc

        snippet = template_format.parse(policy_classifier_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        rsrc = grouppolicy.PolicyClassifier(
            'policy_classifier', resource_defns['policy_classifier'],
            self.stack)

        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.create))
        self.assertEqual(
            'NeutronClientException: resources.policy_classifier: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.CREATE, rsrc.FAILED), rsrc.state)

        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])

    def test_delete(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.show_policy_classifier.side_effect = exc

        rsrc = self.create_policy_classifier()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_show = self.mock_show.get_original()[0]
        _mocked_show.assert_has_calls([expected])

    def test_delete_already_gone(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.delete_policy_classifier.side_effect = exc

        rsrc = self.create_policy_classifier()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_delete_failed(self):
        exc = grouppolicy.NeutronClientException(status_code=400)
        gbpclient.Client.delete_policy_classifier.side_effect = exc

        rsrc = self.create_policy_classifier()
        scheduler.TaskRunner(rsrc.create)()
        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.delete))
        self.assertEqual(
            'NeutronClientException: resources.policy_classifier: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.DELETE, rsrc.FAILED), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_update(self):
        rsrc = self.create_policy_classifier()
        call_dict = {'policy_classifier': {'protocol': 'udp'}}
        scheduler.TaskRunner(rsrc.create)()

        update_template = copy.deepcopy(rsrc.t)
        update_template._properties['protocol'] = 'udp'
        scheduler.TaskRunner(rsrc.update, update_template)()

        expected = mock.call('5678', call_dict)
        _mocked_update = self.mock_update.get_original()[0]
        _mocked_update.assert_has_calls([expected])


class PolicyActionTest(HeatTestCase):

    def setUp(self):
        super(PolicyActionTest, self).setUp()
        self.mock_create = mock.patch(
            'gbpclient.v2_0.client.Client.create_policy_action')
        self.mock_delete = mock.patch(
            'gbpclient.v2_0.client.Client.delete_policy_action')
        self.mock_show = mock.patch(
            'gbpclient.v2_0.client.Client.show_policy_action')
        self.mock_update = mock.patch(
            'gbpclient.v2_0.client.Client.update_policy_action')
        self.mock_create.start()
        self.mock_delete.start()
        self.mock_show.start()
        self.mock_update.start()
        self.stub_keystoneclient()

    def tearDown(self):
        self.mock_create.stop()
        self.mock_delete.stop()
        self.mock_show.stop()
        self.mock_update.stop()
        super(PolicyActionTest, self).tearDown()

    def create_policy_action(self):
        call_dict = {
            'policy_action': {
                "name": "test-policy-action",
                "description": "test policy action resource",
                "action_type": "redirect",
                "action_value": "7890",
                "shared": True
            }
        }
        tdict = {'policy_action': {'id': '5678'}}
        gbpclient.Client.create_policy_action.return_value = tdict

        ret_val = gbpclient.Client.create_policy_action(call_dict)
        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])
        self.assertEqual(tdict, ret_val)

        snippet = template_format.parse(policy_action_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        return grouppolicy.PolicyAction(
            'policy_action', resource_defns['policy_action'], self.stack)

    def test_create(self):
        rsrc = self.create_policy_action()
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual((rsrc.CREATE, rsrc.COMPLETE), rsrc.state)

    def test_create_failed(self):
        call_dict = {
            'policy_action': {
                "name": "test-policy-action",
                "description": "test policy action resource",
                "action_type": "redirect",
                "action_value": "7890",
                "shared": True
            }
        }
        exc = grouppolicy.NeutronClientException()
        gbpclient.Client.create_policy_action.side_effect = exc

        snippet = template_format.parse(policy_action_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        rsrc = grouppolicy.PolicyAction(
            'policy_action', resource_defns['policy_action'], self.stack)

        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.create))
        self.assertEqual(
            'NeutronClientException: resources.policy_action: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.CREATE, rsrc.FAILED), rsrc.state)

        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])

    def test_delete(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.show_policy_action.side_effect = exc

        rsrc = self.create_policy_action()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_show = self.mock_show.get_original()[0]
        _mocked_show.assert_has_calls([expected])

    def test_delete_already_gone(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.delete_policy_action.side_effect = exc

        rsrc = self.create_policy_action()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_delete_failed(self):
        exc = grouppolicy.NeutronClientException(status_code=400)
        gbpclient.Client.delete_policy_action.side_effect = exc

        rsrc = self.create_policy_action()
        scheduler.TaskRunner(rsrc.create)()
        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.delete))
        self.assertEqual(
            'NeutronClientException: resources.policy_action: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.DELETE, rsrc.FAILED), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_update(self):
        rsrc = self.create_policy_action()
        call_dict = {'policy_action': {'action_type': 'allow'}}
        scheduler.TaskRunner(rsrc.create)()

        update_template = copy.deepcopy(rsrc.t)
        update_template._properties['action_type'] = 'allow'
        scheduler.TaskRunner(rsrc.update, update_template)()

        expected = mock.call('5678', call_dict)
        _mocked_update = self.mock_update.get_original()[0]
        _mocked_update.assert_has_calls([expected])


class PolicyRuleTest(HeatTestCase):

    def setUp(self):
        super(PolicyRuleTest, self).setUp()
        self.mock_create = mock.patch(
            'gbpclient.v2_0.client.Client.create_policy_rule')
        self.mock_delete = mock.patch(
            'gbpclient.v2_0.client.Client.delete_policy_rule')
        self.mock_show = mock.patch(
            'gbpclient.v2_0.client.Client.show_policy_rule')
        self.mock_update = mock.patch(
            'gbpclient.v2_0.client.Client.update_policy_rule')
        self.mock_create.start()
        self.mock_delete.start()
        self.mock_show.start()
        self.mock_update.start()
        self.stub_keystoneclient()

    def tearDown(self):
        self.mock_create.stop()
        self.mock_delete.stop()
        self.mock_show.stop()
        self.mock_update.stop()
        super(PolicyRuleTest, self).tearDown()

    def create_policy_rule(self):
        call_dict = {
            'policy_rule': {
                "name": "test-policy-rule",
                "description": "test policy rule resource",
                "enabled": True,
                "policy_classifier_id": "7890",
                "policy_actions": ['3456', '1234'],
                "shared": True
            }
        }
        tdict = {'policy_rule': {'id': '5678'}}
        gbpclient.Client.create_policy_rule.return_value = tdict

        ret_val = gbpclient.Client.create_policy_rule(call_dict)
        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])
        self.assertEqual(tdict, ret_val)

        snippet = template_format.parse(policy_rule_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        return grouppolicy.PolicyRule(
            'policy_rule', resource_defns['policy_rule'], self.stack)

    def test_create(self):
        rsrc = self.create_policy_rule()
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual((rsrc.CREATE, rsrc.COMPLETE), rsrc.state)

    def test_create_failed(self):
        call_dict = {
            'policy_rule': {
                "name": "test-policy-rule",
                "description": "test policy rule resource",
                "enabled": True,
                "policy_classifier_id": "7890",
                "policy_actions": ['3456', '1234'],
                "shared": True
            }
        }
        exc = grouppolicy.NeutronClientException()
        gbpclient.Client.create_policy_rule.side_effect = exc

        snippet = template_format.parse(policy_rule_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        rsrc = grouppolicy.PolicyRule(
            'policy_rule', resource_defns['policy_rule'], self.stack)

        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.create))
        self.assertEqual(
            'NeutronClientException: resources.policy_rule: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.CREATE, rsrc.FAILED), rsrc.state)

        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])

    def test_delete(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.show_policy_rule.side_effect = exc

        rsrc = self.create_policy_rule()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_show = self.mock_show.get_original()[0]
        _mocked_show.assert_has_calls([expected])

    def test_delete_already_gone(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.delete_policy_rule.side_effect = exc

        rsrc = self.create_policy_rule()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_delete_failed(self):
        exc = grouppolicy.NeutronClientException(status_code=400)
        gbpclient.Client.delete_policy_rule.side_effect = exc

        rsrc = self.create_policy_rule()
        scheduler.TaskRunner(rsrc.create)()
        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.delete))
        self.assertEqual(
            'NeutronClientException: resources.policy_rule: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.DELETE, rsrc.FAILED), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_update(self):
        rsrc = self.create_policy_rule()
        call_dict = {'policy_rule': {'enabled': False}}
        scheduler.TaskRunner(rsrc.create)()

        update_template = copy.deepcopy(rsrc.t)
        update_template._properties['enabled'] = False
        scheduler.TaskRunner(rsrc.update, update_template)()

        expected = mock.call('5678', call_dict)
        _mocked_update = self.mock_update.get_original()[0]
        _mocked_update.assert_has_calls([expected])


class PolicyRuleSetTest(HeatTestCase):

    def setUp(self):
        super(PolicyRuleSetTest, self).setUp()
        self.mock_create = mock.patch(
            'gbpclient.v2_0.client.Client.create_policy_rule_set')
        self.mock_delete = mock.patch(
            'gbpclient.v2_0.client.Client.delete_policy_rule_set')
        self.mock_show = mock.patch(
            'gbpclient.v2_0.client.Client.show_policy_rule_set')
        self.mock_update = mock.patch(
            'gbpclient.v2_0.client.Client.update_policy_rule_set')
        self.mock_create.start()
        self.mock_delete.start()
        self.mock_show.start()
        self.mock_update.start()
        self.stub_keystoneclient()

    def tearDown(self):
        self.mock_create.stop()
        self.mock_delete.stop()
        self.mock_show.stop()
        self.mock_update.stop()
        super(PolicyRuleSetTest, self).tearDown()

    def create_policy_rule_set(self):
        call_dict = {
            'policy_rule_set': {
                "name": "test-policy-rule-set",
                "description": "test policy rule set resource",
                "parent_id": "3456",
                "child_policy_rule_sets": ["7890", "1234"],
                "policy_rules": ["2345", "6789"],
                "shared": True
            }
        }
        tdict = {'policy_rule_set': {'id': '5678'}}
        gbpclient.Client.create_policy_rule_set.return_value = tdict

        ret_val = gbpclient.Client.create_policy_rule_set(call_dict)
        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])
        self.assertEqual(tdict, ret_val)

        snippet = template_format.parse(policy_rule_set_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        return grouppolicy.PolicyRuleSet(
            'policy_rule_set', resource_defns['policy_rule_set'], self.stack)

    def test_create(self):
        rsrc = self.create_policy_rule_set()
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual((rsrc.CREATE, rsrc.COMPLETE), rsrc.state)

    def test_create_failed(self):
        call_dict = {
            'policy_rule_set': {
                "name": "test-policy-rule-set",
                "description": "test policy rule set resource",
                "parent_id": "3456",
                "child_policy_rule_sets": ["7890", "1234"],
                "policy_rules": ["2345", "6789"],
                "shared": True
            }
        }
        exc = grouppolicy.NeutronClientException()
        gbpclient.Client.create_policy_rule_set.side_effect = exc

        snippet = template_format.parse(policy_rule_set_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        rsrc = grouppolicy.PolicyRuleSet(
            'policy_rule_set', resource_defns['policy_rule_set'], self.stack)

        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.create))
        self.assertEqual(
            'NeutronClientException: resources.policy_rule_set: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.CREATE, rsrc.FAILED), rsrc.state)

        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])

    def test_delete(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.show_policy_rule_set.side_effect = exc

        rsrc = self.create_policy_rule_set()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_show = self.mock_show.get_original()[0]
        _mocked_show.assert_has_calls([expected])

    def test_delete_already_gone(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.delete_policy_rule_set.side_effect = exc

        rsrc = self.create_policy_rule_set()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_delete_failed(self):
        exc = grouppolicy.NeutronClientException(status_code=400)
        gbpclient.Client.delete_policy_rule_set.side_effect = exc

        rsrc = self.create_policy_rule_set()
        scheduler.TaskRunner(rsrc.create)()
        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.delete))
        self.assertEqual(
            'NeutronClientException: resources.policy_rule_set: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.DELETE, rsrc.FAILED), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_update(self):
        rsrc = self.create_policy_rule_set()
        call_dict = {'policy_rule_set': {'child_policy_rule_sets': ["1234"]}}
        scheduler.TaskRunner(rsrc.create)()

        update_template = copy.deepcopy(rsrc.t)
        update_template._properties['child_policy_rule_sets'] = ["1234"]
        scheduler.TaskRunner(rsrc.update, update_template)()

        expected = mock.call('5678', call_dict)
        _mocked_update = self.mock_update.get_original()[0]
        _mocked_update.assert_has_calls([expected])


class NetworkServicePolicyTest(HeatTestCase):

    def setUp(self):
        super(NetworkServicePolicyTest, self).setUp()
        self.mock_create = mock.patch(
            'gbpclient.v2_0.client.Client.create_network_service_policy')
        self.mock_delete = mock.patch(
            'gbpclient.v2_0.client.Client.delete_network_service_policy')
        self.mock_show = mock.patch(
            'gbpclient.v2_0.client.Client.show_network_service_policy')
        self.mock_update = mock.patch(
            'gbpclient.v2_0.client.Client.update_network_service_policy')
        self.mock_create.start()
        self.mock_delete.start()
        self.mock_show.start()
        self.mock_update.start()
        self.stub_keystoneclient()

    def tearDown(self):
        self.mock_create.stop()
        self.mock_delete.stop()
        self.mock_show.stop()
        self.mock_update.stop()
        super(NetworkServicePolicyTest, self).tearDown()

    def create_network_service_policy(self):
        call_dict = {
            'network_service_policy': {
                "name": "test-nsp",
                "description": "test NSP resource",
                "network_service_params": [
                    {'type': 'ip_single', 'name': 'vip',
                     'value': 'self_subnet'}],
                "shared": True
            }
        }
        tdict = {'network_service_policy': {'id': '5678'}}
        gbpclient.Client.create_network_service_policy.return_value = tdict

        ret_val = gbpclient.Client.create_network_service_policy(call_dict)
        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])
        self.assertEqual(tdict, ret_val)

        snippet = template_format.parse(network_service_policy_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        return grouppolicy.NetworkServicePolicy(
            'network_service_policy',
            resource_defns['network_service_policy'], self.stack)

    def test_create(self):
        rsrc = self.create_network_service_policy()
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual((rsrc.CREATE, rsrc.COMPLETE), rsrc.state)

    def test_create_failed(self):
        call_dict = {
            'network_service_policy': {
                "name": "test-nsp",
                "description": "test NSP resource",
                "network_service_params": [
                    {'type': 'ip_single', 'name': 'vip',
                     'value': 'self_subnet'}],
                "shared": True
            }
        }
        exc = grouppolicy.NeutronClientException()
        gbpclient.Client.create_network_service_policy.side_effect = exc

        snippet = template_format.parse(network_service_policy_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        rsrc = grouppolicy.NetworkServicePolicy(
            'network_service_policy',
            resource_defns['network_service_policy'], self.stack)

        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.create))
        self.assertEqual(
            'NeutronClientException: resources.network_service_policy: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.CREATE, rsrc.FAILED), rsrc.state)

        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])

    def test_delete(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.show_network_service_policy.side_effect = exc

        rsrc = self.create_network_service_policy()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_show = self.mock_show.get_original()[0]
        _mocked_show.assert_has_calls([expected])

    def test_delete_already_gone(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.delete_network_service_policy.side_effect = exc

        rsrc = self.create_network_service_policy()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_delete_failed(self):
        exc = grouppolicy.NeutronClientException(status_code=400)
        gbpclient.Client.delete_network_service_policy.side_effect = exc

        rsrc = self.create_network_service_policy()
        scheduler.TaskRunner(rsrc.create)()
        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.delete))
        self.assertEqual(
            'NeutronClientException: resources.network_service_policy: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.DELETE, rsrc.FAILED), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_update(self):
        rsrc = self.create_network_service_policy()
        call_dict = {
            'network_service_policy':
                {'network_service_params': [{'name': 'vip-update'}]}}
        scheduler.TaskRunner(rsrc.create)()

        update_template = copy.deepcopy(rsrc.t)
        update_template._properties['network_service_params'] = [
            {'name': 'vip-update'}]
        scheduler.TaskRunner(rsrc.update, update_template)()

        expected = mock.call('5678', call_dict)
        _mocked_update = self.mock_update.get_original()[0]
        _mocked_update.assert_has_calls([expected])


class ExternalPolicyTest(HeatTestCase):

    def setUp(self):
        super(ExternalPolicyTest, self).setUp()
        self.mock_create = mock.patch(
            'gbpclient.v2_0.client.Client.create_external_policy')
        self.mock_delete = mock.patch(
            'gbpclient.v2_0.client.Client.delete_external_policy')
        self.mock_show = mock.patch(
            'gbpclient.v2_0.client.Client.show_external_policy')
        self.mock_update = mock.patch(
            'gbpclient.v2_0.client.Client.update_external_policy')
        self.mock_create.start()
        self.mock_delete.start()
        self.mock_show.start()
        self.mock_update.start()
        self.stub_keystoneclient()

    def tearDown(self):
        self.mock_create.stop()
        self.mock_delete.stop()
        self.mock_show.stop()
        self.mock_update.stop()
        super(ExternalPolicyTest, self).tearDown()

    def create_external_policy(self):
        call_dict = {
            'external_policy': {
                "name": "test-ep",
                "description": "test EP resource",
                "external_segments": ['1234'],
                "provided_policy_rule_sets": {
                    '2345': "scope1",
                    '8901': "scope2"
                },
                "consumed_policy_rule_sets": {
                    '9012': "scope3",
                    '9210': "scope4"
                },
                "shared": True
            }
        }
        tdict = {'external_policy': {'id': '5678'}}
        gbpclient.Client.create_external_policy.return_value = tdict

        ret_val = gbpclient.Client.create_external_policy(call_dict)
        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])
        self.assertEqual(tdict, ret_val)

        snippet = template_format.parse(external_policy_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        return grouppolicy.ExternalPolicy(
            'external_policy',
            resource_defns['external_policy'], self.stack)

    def test_create(self):
        rsrc = self.create_external_policy()
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual((rsrc.CREATE, rsrc.COMPLETE), rsrc.state)

    def test_create_failed(self):
        call_dict = {
            'external_policy': {
                "name": "test-ep",
                "description": "test EP resource",
                "external_segments": ['1234'],
                "provided_policy_rule_sets": {
                    '2345': "scope1",
                    '8901': "scope2"
                },
                "consumed_policy_rule_sets": {
                    '9012': "scope3",
                    '9210': "scope4"
                },
                "shared": True
            }
        }
        exc = grouppolicy.NeutronClientException()
        gbpclient.Client.create_external_policy.side_effect = exc

        snippet = template_format.parse(external_policy_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        rsrc = grouppolicy.ExternalPolicy(
            'external_policy',
            resource_defns['external_policy'], self.stack)

        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.create))
        self.assertEqual(
            'NeutronClientException: resources.external_policy: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.CREATE, rsrc.FAILED), rsrc.state)

        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])

    def test_delete(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.show_external_policy.side_effect = exc

        rsrc = self.create_external_policy()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_show = self.mock_show.get_original()[0]
        _mocked_show.assert_has_calls([expected])

    def test_delete_already_gone(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.delete_external_policy.side_effect = exc

        rsrc = self.create_external_policy()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_delete_failed(self):
        exc = grouppolicy.NeutronClientException(status_code=400)
        gbpclient.Client.delete_external_policy.side_effect = exc

        rsrc = self.create_external_policy()
        scheduler.TaskRunner(rsrc.create)()
        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.delete))
        self.assertEqual(
            'NeutronClientException: resources.external_policy: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.DELETE, rsrc.FAILED), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_update(self):
        rsrc = self.create_external_policy()
        call_dict = {
            'external_policy': {
                'external_segments': ['9876'],
                'provided_policy_rule_sets': {
                    '2345': 'scope1',
                    '8901': 'scope2',
                    '1122': 'scope5'},
                'consumed_policy_rule_sets': {
                    '9012': 'scope3',
                    '9210': 'scope4',
                    '9900': 'scope6'
                }
            }}
        scheduler.TaskRunner(rsrc.create)()

        update_template = copy.deepcopy(rsrc.t)
        update_template._properties['external_segments'] = [
            '9876']
        update_template._properties['provided_policy_rule_sets'] = [
            {'policy_rule_set_id': '2345',
             'policy_rule_set_scope': 'scope1'},
            {'policy_rule_set_id': '8901',
             'policy_rule_set_scope': 'scope2'},
            {'policy_rule_set_id': '1122',
             'policy_rule_set_scope': 'scope5'}
        ]
        update_template._properties['consumed_policy_rule_sets'] = [
            {'policy_rule_set_id': '9012',
             'policy_rule_set_scope': 'scope3'},
            {'policy_rule_set_id': '9210',
             'policy_rule_set_scope': 'scope4'},
            {'policy_rule_set_id': '9900',
             'policy_rule_set_scope': 'scope6'}
        ]
        scheduler.TaskRunner(rsrc.update, update_template)()

        expected = mock.call('5678', call_dict)
        _mocked_update = self.mock_update.get_original()[0]
        _mocked_update.assert_has_calls([expected])


class ExternalSegmentTest(HeatTestCase):

    def setUp(self):
        super(ExternalSegmentTest, self).setUp()
        self.mock_create = mock.patch(
            'gbpclient.v2_0.client.Client.create_external_segment')
        self.mock_delete = mock.patch(
            'gbpclient.v2_0.client.Client.delete_external_segment')
        self.mock_show = mock.patch(
            'gbpclient.v2_0.client.Client.show_external_segment')
        self.mock_update = mock.patch(
            'gbpclient.v2_0.client.Client.update_external_segment')
        self.mock_create.start()
        self.mock_delete.start()
        self.mock_show.start()
        self.mock_update.start()
        self.stub_keystoneclient()

    def tearDown(self):
        self.mock_create.stop()
        self.mock_delete.stop()
        self.mock_show.stop()
        self.mock_update.stop()
        super(ExternalSegmentTest, self).tearDown()

    def create_external_segment(self):
        call_dict = {
            'external_segment': {
                "name": "test-es",
                "description": "test ES resource",
                "ip_version": '6',
                "cidr": "192.168.0.0/24",
                "subnet_id": "some-subnet-id",
                "external_routes": [{
                    "destination": "0.0.0.0/0",
                    "nexthop": "null"
                }],
                "port_address_translation": True,
                "shared": True
            }
        }
        tdict = {'external_segment': {'id': '5678'}}
        gbpclient.Client.create_external_segment.return_value = tdict

        ret_val = gbpclient.Client.create_external_segment(call_dict)
        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])
        self.assertEqual(tdict, ret_val)

        snippet = template_format.parse(external_segment_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        return grouppolicy.ExternalSegment(
            'external_segment',
            resource_defns['external_segment'], self.stack)

    def test_create(self):
        rsrc = self.create_external_segment()
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual((rsrc.CREATE, rsrc.COMPLETE), rsrc.state)

    def test_create_failed(self):
        call_dict = {
            'external_segment': {
                "name": "test-es",
                "description": "test ES resource",
                "ip_version": '6',
                "cidr": "192.168.0.0/24",
                "subnet_id": "some-subnet-id",
                "external_routes": [{
                    "destination": "0.0.0.0/0",
                    "nexthop": "null"
                }],
                "port_address_translation": True,
                "shared": True
            }
        }
        exc = grouppolicy.NeutronClientException()
        gbpclient.Client.create_external_segment.side_effect = exc

        snippet = template_format.parse(external_segment_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        rsrc = grouppolicy.ExternalSegment(
            'external_segment',
            resource_defns['external_segment'], self.stack)

        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.create))
        self.assertEqual(
            'NeutronClientException: resources.external_segment: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.CREATE, rsrc.FAILED), rsrc.state)

        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])

    def test_delete(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.show_external_segment.side_effect = exc

        rsrc = self.create_external_segment()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_show = self.mock_show.get_original()[0]
        _mocked_show.assert_has_calls([expected])

    def test_delete_already_gone(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.delete_external_segment.side_effect = exc

        rsrc = self.create_external_segment()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_delete_failed(self):
        exc = grouppolicy.NeutronClientException(status_code=400)
        gbpclient.Client.delete_external_segment.side_effect = exc

        rsrc = self.create_external_segment()
        scheduler.TaskRunner(rsrc.create)()
        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.delete))
        self.assertEqual(
            'NeutronClientException: resources.external_segment: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.DELETE, rsrc.FAILED), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_update(self):
        rsrc = self.create_external_segment()
        call_dict = {'external_segment': {"port_address_translation": False}}
        scheduler.TaskRunner(rsrc.create)()

        update_template = copy.deepcopy(rsrc.t)
        update_template._properties['port_address_translation'] = False
        scheduler.TaskRunner(rsrc.update, update_template)()

        expected = mock.call('5678', call_dict)
        _mocked_update = self.mock_update.get_original()[0]
        _mocked_update.assert_has_calls([expected])


class NATPoolTest(HeatTestCase):

    def setUp(self):
        super(NATPoolTest, self).setUp()
        self.mock_create = mock.patch(
            'gbpclient.v2_0.client.Client.create_nat_pool')
        self.mock_delete = mock.patch(
            'gbpclient.v2_0.client.Client.delete_nat_pool')
        self.mock_show = mock.patch(
            'gbpclient.v2_0.client.Client.show_nat_pool')
        self.mock_update = mock.patch(
            'gbpclient.v2_0.client.Client.update_nat_pool')
        self.mock_create.start()
        self.mock_delete.start()
        self.mock_show.start()
        self.mock_update.start()
        self.stub_keystoneclient()

    def tearDown(self):
        self.mock_create.stop()
        self.mock_delete.stop()
        self.mock_show.stop()
        self.mock_update.stop()
        super(NATPoolTest, self).tearDown()

    def create_nat_pool(self):
        call_dict = {
            'nat_pool': {
                "name": "test-nat-pool",
                "description": "test NP resource",
                "ip_version": '6',
                "ip_pool": "192.168.0.0/24",
                "external_segment_id": '1234',
                "shared": True
            }
        }
        tdict = {'nat_pool': {'id': '5678'}}
        gbpclient.Client.create_nat_pool.return_value = tdict

        ret_val = gbpclient.Client.create_nat_pool(call_dict)
        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])
        self.assertEqual(tdict, ret_val)

        snippet = template_format.parse(nat_pool_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        return grouppolicy.NATPool(
            'nat_pool',
            resource_defns['nat_pool'], self.stack)

    def test_create(self):
        rsrc = self.create_nat_pool()
        scheduler.TaskRunner(rsrc.create)()
        self.assertEqual((rsrc.CREATE, rsrc.COMPLETE), rsrc.state)

    def test_create_failed(self):
        call_dict = {
            'nat_pool': {
                "name": "test-nat-pool",
                "description": "test NP resource",
                "ip_version": '6',
                "ip_pool": "192.168.0.0/24",
                "external_segment_id": '1234',
                "shared": True
            }
        }
        exc = grouppolicy.NeutronClientException()
        gbpclient.Client.create_nat_pool.side_effect = exc

        snippet = template_format.parse(nat_pool_template)
        self.stack = utils.parse_stack(snippet)
        resource_defns = self.stack.t.resource_definitions(self.stack)
        rsrc = grouppolicy.NATPool(
            'nat_pool',
            resource_defns['nat_pool'], self.stack)

        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.create))
        self.assertEqual(
            'NeutronClientException: resources.nat_pool: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.CREATE, rsrc.FAILED), rsrc.state)

        expected = mock.call(call_dict)
        _mocked_create = self.mock_create.get_original()[0]
        _mocked_create.assert_has_calls([expected])

    def test_delete(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.show_nat_pool.side_effect = exc

        rsrc = self.create_nat_pool()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_show = self.mock_show.get_original()[0]
        _mocked_show.assert_has_calls([expected])

    def test_delete_already_gone(self):
        exc = grouppolicy.NeutronClientException(status_code=404)
        gbpclient.Client.delete_nat_pool.side_effect = exc

        rsrc = self.create_nat_pool()
        scheduler.TaskRunner(rsrc.create)()
        scheduler.TaskRunner(rsrc.delete)()
        self.assertEqual((rsrc.DELETE, rsrc.COMPLETE), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_delete_failed(self):
        exc = grouppolicy.NeutronClientException(status_code=400)
        gbpclient.Client.delete_nat_pool.side_effect = exc

        rsrc = self.create_nat_pool()
        scheduler.TaskRunner(rsrc.create)()
        error = self.assertRaises(exception.ResourceFailure,
                                  scheduler.TaskRunner(rsrc.delete))
        self.assertEqual(
            'NeutronClientException: resources.nat_pool: '
            'An unknown exception occurred.',
            six.text_type(error))
        self.assertEqual((rsrc.DELETE, rsrc.FAILED), rsrc.state)

        expected = mock.call('5678')
        _mocked_delete = self.mock_delete.get_original()[0]
        _mocked_delete.assert_has_calls([expected])

    def test_update(self):
        rsrc = self.create_nat_pool()
        call_dict = {'nat_pool': {"external_segment_id": '9876'}}
        scheduler.TaskRunner(rsrc.create)()

        update_template = copy.deepcopy(rsrc.t)
        update_template._properties['external_segment_id'] = '9876'
        scheduler.TaskRunner(rsrc.update, update_template)()

        expected = mock.call('5678', call_dict)
        _mocked_update = self.mock_update.get_original()[0]
        _mocked_update.assert_has_calls([expected])

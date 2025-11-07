from oslo_service import backend

# Prevent oslo_service backend reinitialization conflict
try:
    backend.init_backend(backend.BackendType.THREADING)
except backend.BackendAlreadySelected:
    pass

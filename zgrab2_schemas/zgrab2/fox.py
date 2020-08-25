# zschema sub-schema for zgrab2's fox module
# Registers zgrab2-fox globally, and fox with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

fox_scan_response = SubRecord({
    'result': SubRecord({
        'is_fox': Boolean(),
        'version': String(),
        'id': Unsigned32BitInteger(),
        'hostname': String(),
        'host_address': String(),
        'app_name': String(),
        'app_version': String(),
        'vm_name': String(),
        'vm_version': String(),
        'os_name': String(),
        'os_version': String(),
        'station_name': String(),
        'language': String(),
        'time_zone': String(),
        'host_id': String(),
        'vm_uuid': String(),
        'brand_id': String(),
        'sys_info': String(),
        'agent_auth_type': String(),
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema('zgrab2-fox', fox_scan_response)

zgrab2.register_scan_response_type('fox', fox_scan_response)

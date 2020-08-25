# zschema sub-schema for zgrab2's siemens module
# Registers zgrab2-siemens globally, and siemens with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

siemens_scan_response = SubRecord({
    'result': SubRecord({
        'is_s7': Boolean(),
        'system': String(),
        'module': String(),
        'plant_id': String(),
        'copyright': String(),
        'serial_number': String(),
        'module_type': String(),
        'reserved_for_os': String(),
        'memory_serial_number': String(),
        'cpu_profile': String(),
        'oem_id': String(),
        'location': String(),
        'module_id': String(),
        'hardware': String(),
        'firmware': String(),
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema('zgrab2-siemens', siemens_scan_response)

zgrab2.register_scan_response_type('siemens', siemens_scan_response)

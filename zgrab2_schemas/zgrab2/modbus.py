# zschema sub-schema for zgrab2's modbus module
# Registers zgrab2-modbus globally, and modbus with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

mei_object_names = [
    'vendor',
    'product_code',
    'revision',
    'vendor_url',
    'product_name',
    'model_name',
    'user_application_name',
]

# IDs without an explicit name are encoded as oid_(decimal id).
mei_object_set = SubRecord({
    i < len(mei_object_names) and mei_object_names[i]
    or 'oid_' + str(i): String()
    for i in range(0, 256)
})

mei_response = SubRecord({
    'conformity_level': Unsigned8BitInteger(),
    'more_follows': Boolean(),
    'next_object_id': Unsigned8BitInteger(),
    'object_count': Unsigned8BitInteger(),
    'objects': mei_object_set,
})

exception_response = SubRecord({
    'exception_function': Unsigned8BitInteger(),
    'exception_type': Unsigned8BitInteger(),
})

modbus_scan_response = SubRecord({
    'result': SubRecord({
        'length': Unsigned16BitInteger(),
        'unit_id': Unsigned8BitInteger(),
        'function_code': Unsigned8BitInteger(),
        'raw_response': Binary(),
        'mei_response': mei_response,
        'exception_response': exception_response,
        'raw': Binary(),
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema('zgrab2-modbus', modbus_scan_response)

zgrab2.register_scan_response_type('modbus', modbus_scan_response)

# zschema sub-schema for zgrab2's #{MODULE_NAME} module
# Registers zgrab2-#{MODULE_NAME} globally, and #{MODULE_NAME} with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
import zgrab2

#{MODULE_NAME}_scan_response = SubRecord({
    "result": SubRecord({
        # TODO FIXME IMPLEMENT SCHEMA
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-#{MODULE_NAME}", #{MODULE_NAME}_scan_response)

zgrab2.register_scan_response_type("#{MODULE_NAME}", #{MODULE_NAME}_scan_response)

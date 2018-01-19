# zschema sub-schema for zgrab2's chargen module
# Registers zgrab2-chargen globally, and chargen with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import schemas.zcrypto as zcrypto
import schemas.zgrab2 as zgrab2

chargen_scan_response = SubRecord({
    "result": SubRecord({
        # TODO FIXME IMPLEMENT SCHEMA
    })
}, extends = zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-chargen", chargen_scan_response)

zgrab2.register_scan_response_type("chargen", chargen_scan_response)

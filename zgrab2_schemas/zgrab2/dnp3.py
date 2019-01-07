# zschema sub-schema for zgrab2's dnp3 module
# Registers zgrab2-dnp3 globally, and dnp3 with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

dnp3_scan_response = SubRecord({
    "result": SubRecord({
        "is_dnp3": Boolean(),
        "raw_response": Binary(),
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-dnp3", dnp3_scan_response)

zgrab2.register_scan_response_type("dnp3", dnp3_scan_response)

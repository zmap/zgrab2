# zschema sub-schema for zgrab2's ntp module
# Registers zgrab2-ntp globally, and ntp with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import schemas.zcrypto as zcrypto
import schemas.zgrab2 as zgrab2

ntp_scan_response = SubRecord({
    "result": SubRecord({
        "version": Unsigned8BitInteger(),
        "time": String()
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-ntp", ntp_scan_response)

zgrab2.register_scan_response_type("ntp", ntp_scan_response)

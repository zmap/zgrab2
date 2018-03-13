# zschema sub-schema for zgrab2's telnet module
# Registers zgrab2-telnet globally, and telnet with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import schemas.zcrypto as zcrypto
import schemas.zgrab2 as zgrab2

telnet_scan_response = SubRecord({
    "result": SubRecord({
        "Banner": String(),
        "Will": ListOf(String()),
        "Do": ListOf(String()),
        "Wont": ListOf(String()),
        "Dont": ListOf(String()),
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-telnet", telnet_scan_response)

zgrab2.register_scan_response_type("telnet", telnet_scan_response)

# zschema sub-schema for zgrab2's telnet module
# Registers zgrab2-telnet globally, and telnet with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

telnet_option = SubRecord({
    "name": String(),
    "value": Unsigned16BitInteger(),
})

telnet_scan_response = SubRecord({
    "result": SubRecord({
        "banner": String(),
        "will": ListOf(telnet_option),
        "do": ListOf(telnet_option),
        "wont": ListOf(telnet_option),
        "dont": ListOf(telnet_option),
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-telnet", telnet_scan_response)

zgrab2.register_scan_response_type("telnet", telnet_scan_response)

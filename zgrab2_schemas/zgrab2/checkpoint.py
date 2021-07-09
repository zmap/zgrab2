# zschema sub-schema for zgrab2's checkpoint module
# Registers zgrab2-checkpoint globally, and checkpoint with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
import zgrab2

checkpoint_scan_response = SubRecord({
    "result": SubRecord({
        "firewall_host": String(),
        "host": String()
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-checkpoint", checkpoint_scan_response)

zgrab2.register_scan_response_type("checkpoint", checkpoint_scan_response)

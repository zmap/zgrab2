# zschema sub-schema for zgrab2's banner module
# Registers zgrab2-banner globally, and banner with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

# modules/banner/scanner.go - Results
banner_scan_response = SubRecord({
    "result": SubRecord({
        "banner": String(),
        "length": Unsigned32BitInteger(),
        "tls": zgrab2.tls_log,
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-banner", banner_scan_response)

zgrab2.register_scan_response_type("banner", banner_scan_response)

# zschema sub-schema for zgrab2's smtp module
# Registers zgrab2-smtp globally, and smtp with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

smtp_scan_response = SubRecord({
    "result": SubRecord({
        "banner": String(),
        "ehlo": String(),
        "helo": String(),
        "help": String(),
        "starttls": String(),
        "quit": String(),
        "tls": zgrab2.tls_log,
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-smtp", smtp_scan_response)

zgrab2.register_scan_response_type("smtp", smtp_scan_response)

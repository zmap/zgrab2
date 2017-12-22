# zschema sub-schema for zgrab2's postgres module
# Registers zgrab2-postgres globally, and postgres with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import schemas.zcrypto as zcrypto
import schemas.zgrab2 as zgrab2

postgres_scan_response = SubRecord({
    "result": SubRecord({
        "is_ssl": Boolean(),
        "tls": zgrab2.tls_log,
        # TODO: These fields will probably change
        "startup_response": String(),
        "supported_versions": String()
    })
}, extends = zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-postgres", postgres_scan_response)

zgrab2.register_scan_response_type("postgres", postgres_scan_response)

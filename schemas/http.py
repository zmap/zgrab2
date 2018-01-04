# zschema sub-schema for zgrab2's http module
# Registers zgrab2-http globally, and http with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import schemas.zcrypto as zcrypto
import schemas.zgrab2 as zgrab2

http_scan_response = SubRecord({
    "result": SubRecord({
        # TODO FIXME IMPLEMENT SCHEMA
    })
}, extends = zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-http", http_scan_response)

zgrab2.register_scan_response_type("http", http_scan_response)

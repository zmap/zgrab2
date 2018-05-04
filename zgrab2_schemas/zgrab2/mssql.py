# zschema sub-schema for zgrab2's mssql module
# Registers zgrab2-mssql globally, and mssql with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
import zgrab2

ENCRYPT_MODES = [
  "ENCRYPT_OFF",
  "ENCRYPT_ON",
  "ENCRYPT_NOT_SUP",
  "ENCRYPT_REQ",
  "UNKNOWN"
]

unknown_prelogin_option = SubRecord({
    "token": Unsigned8BitInteger(),
    "value": Binary(),
})

prelogin_options = SubRecord({
    "version": SubRecord({
        "major": Unsigned8BitInteger(),
        "minor": Unsigned8BitInteger(),
        "build_number": Unsigned16BitInteger(),
    }),
    "encrypt_mode": Enum(values=ENCRYPT_MODES),
    "instance": String(),
    "thread_id": Unsigned32BitInteger(),
    "mars": Unsigned8BitInteger(),
    "trace_id": Binary(),
    "fed_auth_required": Unsigned8BitInteger(),
    "nonce": Binary(),
    "unknown": ListOf(unknown_prelogin_option),
})

mssql_scan_response = SubRecord({
    "result": SubRecord({
        "version": String(),
        "instance_name": String(),
        "prelogin_options": prelogin_options,
        "tls": zgrab2.tls_log,
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-mssql", mssql_scan_response)

zgrab2.register_scan_response_type("mssql", mssql_scan_response)

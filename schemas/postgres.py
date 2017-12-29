# zschema sub-schema for zgrab2's postgres module
# Registers zgrab2-postgres globally, and postgres with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import schemas.zcrypto as zcrypto
import schemas.zgrab2 as zgrab2

postgres_error = SubRecord({
    "severity": String(required = True),
    "severity_v": String(),
    "code": String(required = True),
    "message": String(),
    "detail": String(),
    "hint": String(),
    "position": String(),
    "internal_position": String(),
    "internal_query": String(),
    "where": String(),
    "schema": String(),
    "table": String(),
    "data": String(),
    "file": String(),
    "line": String(),
    "routine": String(),
})

AUTH_MODES = [
  "kerberos_v5",
  "password_cleartext",
  "password_md5",
  "scm_credentials",
  "gss",
  "sspi",
  "sasl",
  "ok",
  "gss-continue",
  "sasl-continue",
  "sasl-final"
]

postgres_auth_mode = SubRecord({
  "mode": Enum(values = AUTH_MODES, required = True),
  "Payload": Binary(),
})

postgres_key_data = SubRecord({
  "process_id": Unsigned32BitInteger(), 
  "secret_key": Unsigned32BitInteger(),
})



postgres_scan_response = SubRecord({
    "result": SubRecord({
        "tls": zgrab2.tls_log,
        "supported_versions": String(),
        "protocol_error": postgres_error,
        "startup_error": postgres_error,
        "is_ssl": Boolean(required = True),
        "authentication_mode": postgres_auth_mode,
        "server_parameters": String(), # TODO FIXME: This is currendly an unconstrained map
        "backend_key_data": postgres_key_data,
        "transaction_status": String(),
    })
}, extends = zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-postgres", postgres_scan_response)

zgrab2.register_scan_response_type("postgres", postgres_scan_response)

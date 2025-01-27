# zschema sub-schema for zgrab2's postgres module
# Registers zgrab2-postgres globally, and postgres with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

# modules/postgres/scanner.go - decodeError() (TODO: Currently an unconstrained
# map[string]string; it is possible to get "unknown (0x%x)" fields, but it
# would probably be proper to reject those at this point)

# These are defined in detail at
#   https://www.postgresql.org/docs/10/static/protocol-error-fields.html
postgres_error = SubRecord(
    {
        "severity": WhitespaceAnalyzedString(),
        "severity_v": WhitespaceAnalyzedString(),
        "code": WhitespaceAnalyzedString(),
        "message": WhitespaceAnalyzedString(),
        "detail": WhitespaceAnalyzedString(),
        "hint": WhitespaceAnalyzedString(),
        "position": WhitespaceAnalyzedString(),
        "internal_position": WhitespaceAnalyzedString(),
        "internal_query": WhitespaceAnalyzedString(),
        "where": WhitespaceAnalyzedString(),
        "schema": WhitespaceAnalyzedString(),
        "table": WhitespaceAnalyzedString(),
        "data": WhitespaceAnalyzedString(),
        "constraint": WhitespaceAnalyzedString(),
        "file": WhitespaceAnalyzedString(),
        "line": WhitespaceAnalyzedString(),
        "routine": WhitespaceAnalyzedString(),
        "_unknown_error_tag": WhitespaceAnalyzedString(),
    }
)

# modules/postgres/scanner.go - decodeAuthMode()
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
    "sasl-final",
]

# modules/postgres/scanner.go: AuthenticationMode
postgres_auth_mode = SubRecord(
    {
        "mode": Enum(values=AUTH_MODES, required=False),  # this gets lifted
        "Payload": Binary(),
    }
)

# modules/postgres/scanner.go: BackendKeyData
postgres_key_data = SubRecord(
    {
        "process_id": Unsigned32BitInteger(),
        "secret_key": Unsigned32BitInteger(),
    }
)

# modules/postgres/scanner.go: PostgresResults
postgres_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "tls": zgrab2.tls_log,
                "supported_versions": WhitespaceAnalyzedString(),
                "protocol_error": postgres_error,
                "startup_error": postgres_error,
                "is_ssl": Boolean(),
                "authentication_mode": postgres_auth_mode,
                # TODO FIXME: This is currendly an unconstrained map[string]string
                "server_parameters": WhitespaceAnalyzedString(),
                "backend_key_data": postgres_key_data,
                "transaction_status": WhitespaceAnalyzedString(),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-postgres", postgres_scan_response)

zgrab2.register_scan_response_type("postgres", postgres_scan_response)

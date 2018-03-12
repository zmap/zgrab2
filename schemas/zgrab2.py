from zschema.leaves import *
from zschema.compounds import *
import zschema.registry
from collections import defaultdict

# Base / shared schema types for zgrab2

import schemas.zcrypto as zcrypto

# Map of protocol-name -> protocl-schema. This is wrapped in a SubRecord
# Protocols are responsible for calling register_scan_response_type(protocol_name, schema).
# Failure to do so will result in a validation exception for any scan results containing that protocol.
# NOTE: Scans with custom names will cause the validator to fail.
# TODO: Can this be somehow replaced with the main registry?
scan_response_types = {}

# Placeholder / RFU. Many mysql fields are only included in debug mode.
def DebugOnly(childType):
    return childType

# zgrab2/processing.go: Grab
grab_result = Record({
    "ip": IPv4Address(required = False),
    "domain": String(required = False),
    "data": SubRecord(scan_response_types, required = True),
})

# zgrab2/module.go: const SCAN_*
STATUS_VALUES = [
  "success",
  "connection-refused",
  "connection-timeout",
  "connection-closed",
  "io-timeout",
  "protocol-error",
  "application-error",
  "unknown-error"
]

# zgrab2/module.go: ScanResponse
base_scan_response = SubRecord({
    "status": Enum(values = STATUS_VALUES, required = True),
    "protocol": String(required = True),
    "timestamp": DateTime(required = True),
    "result": SubRecord({}, required = False), # This is overridden by the protocols' implementations
    "error": String(required = False)
    # TODO: error_component? domain?
})

# zgrab2/tls.go: TLSLog
tls_log = SubRecord({
    "handshake_log": zcrypto.tls_handshake,
    "heartbleed_log": zcrypto.heartbleed_log
})

# Register a schema type for responses with the given name.
def register_scan_response_type(name, schema):
    scan_response_types[name] = schema

zschema.registry.register_schema("zgrab2", grab_result)


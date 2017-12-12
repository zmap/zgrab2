from zschema.leaves import *
from zschema.compounds import *
import zschema.registry
from collections import defaultdict

# Base / shared schema types for zgrab2

# TODO: just import schemas.zcrypto when its exports are properly renamed
from schemas.zcrypto import *

# Map of protocol-name -> protocl-schema. This is wrapped in a SubRecord
# Protocols are responsible for calling register_result_type(protocol_name, schema).
# Failure to do so will result in a validation exception for any scan results containing that protocol.
# NOTE: Scans with custom names will cause the validator to fail.
# TODO: It seems like this should be doable with the zschema.registry?
zgrab2_result_types = {}

# Placeholder / RFU. Many mysql fields are only included in debug mode.
def DebugOnly(childType):
    return childType

# zgrab2/processing.go: Grab
zgrab2_outer = Record({
    "ip": IPv4Address(required = True),
    "data": SubRecord(zgrab2_result_types, required = True),
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
zgrab2_protocol_base = SubRecord({
    "status": Enum(values = STATUS_VALUES, required = True), # TODO: make an enum
    "time": DateTime(required=True), # TODO: time->timestamp
    "result": SubRecord({}, required = False), # This is overridden by the protocols' implementations
    "error": String(required = False)
    # TODO: error_component? domain?
})

# zgrab2/tls.go: TLSLog
zgrab2_tls_log = SubRecord({
    "handshake_log": zgrab_tls,
    "heartbleed_log": zcrypto_heartbleed_log
})

def register_result_type(name, schema):
    zgrab2_result_types[name] = schema

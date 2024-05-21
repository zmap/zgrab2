from zschema.leaves import *
from zschema.compounds import *
import zschema.registry
from collections import defaultdict

# Base / shared schema types for zgrab2

import zcrypto_schemas.zcrypto as zcrypto

# Map of protocol-name -> protocl-schema. This is wrapped in a SubRecord
# Protocols are responsible for calling register_scan_response_type(protocol_name, schema).
# Failure to do so will result in a validation exception for any scan results containing that protocol.
# NOTE: Scans with custom names will cause the validator to fail.
# TODO: Can this be somehow replaced with the main registry?
scan_response_types = {}


# Placeholder / RFU. Many mysql fields are only included in debug mode.
def DebugOnly(childType):
    return childType


# Get a dict of all keys, mapping key -> true
def FlagsSet(keys, **kwargs):
    return SubRecord({key: Boolean() for key in keys}, **kwargs)


# zgrab2/processing.go: Grab
grab_result = Record(
    {
        # TODO: ip may be required; see https://github.com/zmap/zgrab2/issues/104
        "ip": IPv4Address(required=False, doc="The IP address of the target."),
        "domain": String(
            required=False, doc="The domain name of the target, if available."
        ),
        "data": SubRecord(scan_response_types, doc="The scan data for this host."),
    }
)

# zgrab2/module.go: const SCAN_*
STATUS_VALUES = [
    "success",
    "connection-refused",
    "connection-timeout",
    "connection-closed",
    "io-timeout",
    "protocol-error",
    "application-error",
    "unknown-error",
]

# zgrab2/module.go: ScanResponse
base_scan_response = SubRecord(
    {
        "status": Enum(values=STATUS_VALUES, doc="The status of the request."),
        "protocol": String(doc="The identifier of the protocol being scanned."),
        "timestamp": DateTime(doc="The time the scan was started."),
        "result": SubRecord(
            {}, required=False
        ),  # This is overridden by the protocols' implementations
        "error": String(
            required=False,
            doc="If the status was not success, error may contain information about the failure.",
        ),
        # TODO: error_component? domain?
    }
)

# zgrab2/tls.go: TLSLog
tls_log = SubRecord(
    {
        "handshake_log": zcrypto.TLSHandshake(doc="The TLS handshake log."),
        "heartbleed_log": zcrypto.HeartbleedLog(
            doc="The heartbleed scan log, if heartbleed scanning was enabled; otherwise, absent."
        ),
    }
)


# Register a schema type for responses with the given name.
def register_scan_response_type(name, schema):
    scan_response_types[name] = schema


zschema.registry.register_schema("zgrab2", grab_result)

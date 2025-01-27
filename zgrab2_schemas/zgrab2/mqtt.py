# zschema sub-schema for zgrab2's MQTT module
# Registers zgrab2-mqtt globally, and mqtt with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

from . import zgrab2

# Schema for ScanResults struct
mqtt_scan_response = SubRecord(
    {
        "session_present": Boolean(),
        "connect_return_code": Unsigned32BitInteger(),
        "response": String(),
        "tls": zgrab2.tls_log,
    }
)

mqtt_scan = SubRecord(
    {
        "result": mqtt_scan_response,
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-mqtt", mqtt_scan)
zgrab2.register_scan_response_type("mqtt", mqtt_scan)

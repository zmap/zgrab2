# zschema sub-schema for zgrab2's Socks5 module
# Registers zgrab2-socks5 globally, and socks5 with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

from . import zgrab2

# Schema for ScanResults struct
socks5_response_explanation = SubRecord(
    {
        "Version": String(),
        "Reply": String(),
        "Reserved": String(),
        "Address Type": String(),
        "Bound Address": String(),
        "Bound Port": String(),
    }
)

socks5_scan_response = SubRecord(
    {
        "version": String(),
        "method_selection": String(),
        "connection_response": String(),
        "connection_response_explanation": socks5_response_explanation,
    }
)

socks5_scan = SubRecord(
    {
        "result": socks5_scan_response,
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-socks5", socks5_scan)
zgrab2.register_scan_response_type("socks5", socks5_scan)

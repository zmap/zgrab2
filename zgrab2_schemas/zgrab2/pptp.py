# zschema sub-schema for zgrab2's PPTP module
# Registers zgrab2-pptp globally, and pptp with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

from . import zgrab2

# Schema for ScanResults struct
pptp_scan_response = SubRecord(
    {
        "banner": String(),
        "control_message": String(),
        "protocol_version": Unsigned16BitInteger(),
        "result_code": Unsigned8BitInteger(),
        "error_code": Unsigned8BitInteger(),
        "framing_capability": Unsigned32BitInteger(),
        "bearer_capability": Unsigned32BitInteger(),
        "maximum_channels": Unsigned16BitInteger(),
        "firmware_revision": Unsigned16BitInteger(),
        "hostname": String(),
        "vendor": String(),
    }
)

pptp_scan = SubRecord(
    {
        "result": pptp_scan_response,
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-pptp", pptp_scan)
zgrab2.register_scan_response_type("pptp", pptp_scan)

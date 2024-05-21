# zschema sub-schema for zgrab2's ntp module
# Registers zgrab2-ntp globally, and ntp with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

ntp_short = SubRecord(
    {
        "seconds": Unsigned16BitInteger(),
        "fraction": Unsigned16BitInteger(),
    }
)

ntp_long = SubRecord(
    {
        "seconds": Unsigned32BitInteger(),
        "fraction": Unsigned32BitInteger(),
    }
)

ntp_header = SubRecord(
    {
        "leap_indicator": Unsigned8BitInteger(),
        "version": Unsigned8BitInteger(),
        "mode": Unsigned8BitInteger(),
        "stratum": Unsigned8BitInteger(),
        "poll": Signed8BitInteger(),
        "precision": Signed8BitInteger(),
        "root_delay": ntp_short,
        "root_dispersion": ntp_short,
        "reference_id": Binary(),
        "reference_timestamp": ntp_long,
        "origin_timestamp": ntp_long,
        "receive_timestamp": ntp_long,
        "transmit_timestamp": ntp_long,
    }
)

mode7_header = SubRecord(
    {
        "is_response": Boolean(),
        "has_more": Boolean(),
        "version": Unsigned8BitInteger(),
        "mode": Unsigned8BitInteger(),
        "is_authenticated": Boolean(),
        "sequence_number": Unsigned8BitInteger(),
        "implementation_number": String(),
        "request_code": String(),
        "error": String(),
        "num_items": Unsigned16BitInteger(),
        "mbz": Unsigned8BitInteger(),
        "item_size": Unsigned16BitInteger(),
    }
)

ntp_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "version": Unsigned8BitInteger(),
                "time": String(),
                "time_response": ntp_header,
                "monlist_response": Binary(),
                "monlist_header": mode7_header,
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-ntp", ntp_scan_response)

zgrab2.register_scan_response_type("ntp", ntp_scan_response)

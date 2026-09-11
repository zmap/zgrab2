from zschema.compounds import SubRecord
from zschema.leaves import Boolean, Signed32BitInteger, String, Unsigned32BitInteger
import zschema.registry

from . import zgrab2


snmp_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "is_snmp": Boolean(),
                "version": String(),
                "probe": String(),
                "role": String(),
                "community": String(),
                "port": Unsigned32BitInteger(),
                "request_id": Signed32BitInteger(),
                "error_status": Signed32BitInteger(),
                "error_index": Signed32BitInteger(),
                "raw_response_length": Unsigned32BitInteger(),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-snmp", snmp_scan_response)
zgrab2.register_scan_response_type("snmp", snmp_scan_response)

# zschema sub-schema for zgrab2's codesysv3 module (protocol name "codesys3")
# Registers zgrab2-codesys3 globally, and codesys3 with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

from . import zgrab2

codesys3_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "vendor_name": String(),
                "device_name": String(),
                "node_name": String(),
                "serial_number": String(),
                "target_type": Unsigned32BitInteger(),
                "target_id": Unsigned32BitInteger(),
                "target_version": Unsigned32BitInteger(),
                "target_version_str": String(),
                "flags": Unsigned32BitInteger(),
                "max_channels": Unsigned16BitInteger(),
                "intel_byte_order": Boolean(),
                "blk_drv_type": Unsigned8BitInteger(),
                "request_id": Unsigned32BitInteger(),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-codesys3", codesys3_scan_response)

zgrab2.register_scan_response_type("codesys3", codesys3_scan_response)

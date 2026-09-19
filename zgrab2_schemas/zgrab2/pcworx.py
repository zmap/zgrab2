# zschema sub-schema for zgrab2's pcworx module
# Registers zgrab2-pcworx globally, and pcworx with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

from . import zgrab2

pcworx_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "plc_type": String(),
                "model_number": String(),
                "firmware_version": String(),
                "firmware_date": String(),
                "firmware_time": String(),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-pcworx", pcworx_scan_response)

zgrab2.register_scan_response_type("pcworx", pcworx_scan_response)

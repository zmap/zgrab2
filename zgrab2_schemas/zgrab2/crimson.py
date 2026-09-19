# zschema sub-schema for zgrab2's crimson module
# Registers zgrab2-crimson globally, and crimson with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

from . import zgrab2

crimson_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "manufacturer": String(),
                "model": String(),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-crimson", crimson_scan_response)

zgrab2.register_scan_response_type("crimson", crimson_scan_response)

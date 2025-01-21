# zschema sub-schema for zgrab2's bacnet module
# Registers zgrab2-bacnet globally, and bacnet with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas
from . import zgrab2

bacnet_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "is_bacnet": Boolean(),
                "instance_number": Unsigned32BitInteger(),
                "vendor_id": Unsigned16BitInteger(),
                "vendor_name": String(),
                "firmware_revision": String(),
                "application_software_revision": String(),
                "object_name": String(),
                "model_name": String(),
                "description": String(),
                "location": String(),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-bacnet", bacnet_scan_response)

zgrab2.register_scan_response_type("bacnet", bacnet_scan_response)

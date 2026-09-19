# zschema sub-schema for zgrab2's proconos module
# Registers zgrab2-proconos globally, and proconos with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

from . import zgrab2

proconos_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "os_version": String(),
                "version": String(),
                "plc": String(),
                "project": String(),
                "source": String(),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-proconos", proconos_scan_response)

zgrab2.register_scan_response_type("proconos", proconos_scan_response)

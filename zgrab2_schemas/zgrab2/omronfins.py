# zschema sub-schema for zgrab2's omronfins module
# Registers zgrab2-omronfins globally, and omronfins with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

from . import zgrab2

omronfins_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "response_code_val": String(),
                "response_code": Unsigned16BitInteger(),
                "controller_model": String(),
                "controller_version": String(),
                "for_system_use": String(),
                "program_area_size": Unsigned16BitInteger(),
                "io_msize": Unsigned8BitInteger(),
                "no_dm_size": Unsigned16BitInteger(),
                "time_counter": Unsigned8BitInteger(),
                "expansion_dm_size": Unsigned8BitInteger(),
                "no_of_transitions": Unsigned16BitInteger(),
                "memory_card_type": Unsigned8BitInteger(),
                "memory_card_type_val": String(),
                "memory_card_size": Unsigned16BitInteger(),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-omronfins", omronfins_scan_response)

zgrab2.register_scan_response_type("omronfins", omronfins_scan_response)

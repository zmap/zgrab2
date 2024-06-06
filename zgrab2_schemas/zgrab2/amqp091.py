# zschema sub-schema for zgrab2's AMQP091 module
# Registers zgrab2-amqp091 globally, and amqp091 with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

from . import zgrab2

# Schema for connectionTune struct
connection_tune = SubRecord(
    {
        "channel_max": Unsigned32BitInteger(),
        "frame_max": Unsigned32BitInteger(),
        "heartbeat": Unsigned32BitInteger(),
    }
)

# Schema for knownServerProperties struct
known_server_properties = SubRecord(
    {
        "product": String(),
        "version": String(),
        "platform": String(),
        "copyright": String(),
        "information": String(),
        "unknown_props": String(),
    }
)

# Schema for Result struct
result_schema = SubRecord(
    {
        "result": SubRecord(
            {
                "failure": String(),
                "version_major": Unsigned32BitInteger(),
                "version_minor": Unsigned32BitInteger(),
                "server_properties": known_server_properties,
                "locales": ListOf(String()),
                "auth_success": Boolean(),
                "tune": connection_tune,
                "tls": zgrab2.tls_log,
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-amqp091", result_schema)
zgrab2.register_scan_response_type("amqp091", result_schema)

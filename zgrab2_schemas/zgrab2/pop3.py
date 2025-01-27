# zschema sub-schema for zgrab2's pop3 module
# Registers zgrab2-pop3 globally, and pop3 with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

pop3_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "banner": String(doc="The POP3 banner."),
                "noop": String(doc="The server's response to the NOOP command."),
                "help": String(doc="The server's response to the HELP command."),
                "starttls": String(
                    doc="The server's response to the STARTTLS command."
                ),
                "quit": String(doc="The server's response to the QUIT command."),
                "tls": zgrab2.tls_log,
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-pop3", pop3_scan_response)

zgrab2.register_scan_response_type("pop3", pop3_scan_response)

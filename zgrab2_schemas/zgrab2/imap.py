# zschema sub-schema for zgrab2's imap module
# Registers zgrab2-imap globally, and imap with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

imap_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "banner": String(doc="The IMAP banner."),
                "starttls": String(
                    doc="The server's response to the STARTTLS command."
                ),
                "close": String(doc="The server's response to the CLOSE command."),
                "tls": zgrab2.tls_log,
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-imap", imap_scan_response)

zgrab2.register_scan_response_type("imap", imap_scan_response)

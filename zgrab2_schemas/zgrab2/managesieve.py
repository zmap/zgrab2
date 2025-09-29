# zschema sub-schema for zgrab2's managesieve module
# Registers zgrab2-managesieve globally, and managesieve with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

managesieve_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "banner": String(doc="The ManageSieve banner."),
                "capabilities": ListOf(String(doc="A capability advertised by the server.")),
                "sieve_version": String(doc="The Sieve version advertised by the server."),
                "implementation": String(doc="The server implementation string."),
                "starttls_supported": Boolean(),
                "auth_mechanisms": ListOf(String(doc="Supported SASL authentication mechanism.")),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-managesieve", managesieve_scan_response)

zgrab2.register_scan_response_type("managesieve", managesieve_scan_response)
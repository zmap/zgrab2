# zschema sub-schema for zgrab2's rdp module
# Registers zgrab2-rdp globally, and rdp with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

# modules/rdp/scanner.go - Results
rdp_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "os_version": String(),
                "target_name": String(),
                "netbios_computer_name": String(),
                "netbios_domain_name": String(),
                "dns_computer_name": String(),
                "dns_domain_name": String(),
                "tls": zgrab2.tls_log,
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-rdp", rdp_scan_response)

zgrab2.register_scan_response_type("rdp", rdp_scan_response)

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
                "selected_protocol": String(),
                "negotiation_flags": SubRecord(
                    {
                        "extended_client_data_supported": Boolean(),
                        "dynvc_gfx_protocol_supported": Boolean(),
                        "restricted_admin_mode_supported": Boolean(),
                        "redirected_authentication_mode_supported": Boolean(),
                    }
                ),
                "failure_code": String(),
                "ntlm": zgrab2.ntlm_info,
                "tls": zgrab2.tls_log,
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-rdp", rdp_scan_response)

zgrab2.register_scan_response_type("rdp", rdp_scan_response)

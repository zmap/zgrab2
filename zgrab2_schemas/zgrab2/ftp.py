# zschema sub-schema for zgrab2's ftp module
# Registers zgrab2-ftp globally, and ftp with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

# modules/ftp.go - FTPScanResults
ftp_scan_response = SubRecord({
    "result": SubRecord({
        "tls": zgrab2.tls_log,
        "banner": String(),
        "auth_tls": String(),
        "auth_ssl": String(),
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-ftp", ftp_scan_response)

zgrab2.register_scan_response_type("ftp", ftp_scan_response)

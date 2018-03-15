# zschema sub-schema for zgrab2's smb module
# Registers zgrab2-smb globally, and smb with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import schemas.zcrypto as zcrypto
import schemas.zgrab2 as zgrab2

smb_scan_response = SubRecord({
    "result": SubRecord({
        "smbv1_support": Boolean(),
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-smb", smb_scan_response)

zgrab2.register_scan_response_type("smb", smb_scan_response)

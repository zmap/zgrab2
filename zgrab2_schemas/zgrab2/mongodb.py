# zschema sub-schema for zgrab2's mongodb module
# Registers zgrab2-mongodb globally, and mongodb with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
import zgrab2

mongodb_scan_response = SubRecord({
    "result": SubRecord({
        "Version": String(doc="Version of mongodb server"),
        "GitVersion": String(doc="Git Version of mongodb server"),
        "BuildEnvironment": SubRecord({
            "Distmod": String(),
            "Distarch": String(),
            "Cc": String(),
            "CcFlags": String(),
            "Cxx": String(),
            "CxxFlags": String(),
            "LinkFlags": String(),
            "TargetArch": String(),
            "TargetOS": String()})
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-mongodb", mongodb_scan_response)

zgrab2.register_scan_response_type("mongodb", mongodb_scan_response)

# zschema sub-schema for zgrab2's inetd module
# Registers zgrab2-inetd globally, and inetd with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import schemas.zcrypto as zcrypto
import schemas.zgrab2 as zgrab2

services = ( "chargen", "echo", "daytime", "time" )

inetd_scan_response = SubRecord({
    "result": SubRecord({
        "output_size": Unsigned32BitInteger(),
        "output_data": String(),
    })
}, extends = zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-inetd", inetd_scan_response)

for service in services:
    zgrab2.register_scan_response_type(service, inetd_scan_response)

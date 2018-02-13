# zschema sub-schema for zgrab2's redis module
# Registers zgrab2-redis globally, and redis with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import schemas.zcrypto as zcrypto
import schemas.zgrab2 as zgrab2

redis_scan_response = SubRecord({
    "result": SubRecord({
        "commands": ListOf(String()),
        "raw_command_output": ListOf(Binary()),
        "ping_response": String(),
        "info_response": String(),
        "auth_response": String(),
        "nonexistent_response": String(),
        "quit_response": String(),
        "version": String(),
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-redis", redis_scan_response)

zgrab2.register_scan_response_type("redis", redis_scan_response)

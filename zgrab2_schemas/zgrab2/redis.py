# zschema sub-schema for zgrab2's redis module
# Registers zgrab2-redis globally, and redis with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

redis_scan_response = SubRecord({
    "result": SubRecord({
        "commands": ListOf(String(), doc="The list of commands actually sent to the server, serialized in inline format, like 'PING' or 'AUTH somePassword'."),
        "raw_command_output": ListOf(Binary(), doc="The raw output returned by the server for each command sent; the indices match those of commands."),
        "ping_response": String(doc="The response from the PING command; should either be \"PONG\" or an authentication error.", examples=[
            "PONG",
            "(Error: NOAUTH Authentication required.)",
        ]),
        "info_response": String(doc="The response from the INFO command. Should be a series of key:value pairs separated by CRLFs.", examples=[
            "# Server\r\nredis_version:4.0.7\r\nkey2:value2\r\n",
            "(Error: NOAUTH Authentication required.)",
        ]),
        "auth_response": String(doc="The response from the AUTH command, if sent."),
        "nonexistent_response": String("The response from the NONEXISTENT command.", examples=[
            "(Error: ERR unknown command 'NONEXISTENT')",
        ]),
        "quit_response": String(doc="The response to the QUIT command.", examples=["OK"]),
        "version": String(doc="The version string, read from the the info_response (if available)."),
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-redis", redis_scan_response)

zgrab2.register_scan_response_type("redis", redis_scan_response)

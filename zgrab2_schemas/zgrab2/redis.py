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
        "nonexistent_response": String(doc="The response from the NONEXISTENT command.", examples=[
            "(Error: ERR unknown command 'NONEXISTENT')",
        ]),
        "quit_response": String(doc="The response to the QUIT command.", examples=["OK"]),
        "version": String(doc="The version string, read from the the info_response (if available)."),
        "major": Unsigned32BitInteger(doc="Major is the version's major number."),
        "minor": Unsigned32BitInteger(doc="Minor is the version's minor number."),
        "patchlevel": Unsigned32BitInteger(doc="Patchlevel is the version's patchlevel number."),
        "os": String(doc="The OS the Redis server is running, read from the the info_response (if available)."),
        "mode": String(doc="The mode the Redis server is running (standalone or cluster), read from the the info_response (if available)."),
        "git_sha1": String(doc="The Sha-1 Git commit hash the Redis server used."),
        "build_id": String(doc="The Build ID of the Redis server."),
        "arch_bits": String(doc="The architecture bits (32 or 64) the Redis server used to build."),
        "gcc_version": String(doc="The version of the GCC compiler used to compile the Redis server."),
        "mem_allocator": String(doc="The memory allocator."),
        "uptime_in_seconds": Unsigned32BitInteger(doc="The number of seconds since Redis server start."),
        "used_memory": Unsigned32BitInteger(doc="The total number of bytes allocated by Redis using its allocator."),
        "total_connections_received": Unsigned32BitInteger(doc="The total number of connections accepted by the server."),
        "total_commands_processed": Unsigned32BitInteger(doc="The total number of commands processed by the server."),
        "custom_responses": ListOf(SubRecord({
            "command": String(doc="The command portion of the command sent."),
            "arguments": String(doc="The arguments portion of the command sent."),
            "response": String(doc="The response from the sent command and arguments."),
        }), doc="The responses from the user-passed custom commands."),
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-redis", redis_scan_response)

zgrab2.register_scan_response_type("redis", redis_scan_response)

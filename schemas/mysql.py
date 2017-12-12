from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

from schemas.zcrypto import *
from schemas.zgrab2 import *

# zgrab2/lib/mysql/mysql.go: ConnectionLogEntry
zgrab2_mysql_packet = SubRecord({
    "length": DebugOnly(Unsigned32BitInteger()),
    "sequence_number": DebugOnly(Unsigned8BitInteger()),
    "raw": DebugOnly(String()),
    "parsed": SubRecord({})
})

zgrab2_mysql_server_status_flags = {
		"SERVER_STATUS_IN_TRANS": Boolean(),
		"SERVER_STATUS_AUTOCOMMIT": Boolean(),
		"SERVER_MORE_RESULTS_EXISTS": Boolean(),
		"SERVER_QUERY_NO_GOOD_INDEX_USED": Boolean(),
		"SERVER_QUERY_NO_INDEX_USED": Boolean(),
		"SERVER_STATUS_CURSOR_EXISTS": Boolean(),
		"SERVER_STATUS_LAST_ROW_SENT": Boolean(),
		"SERVER_STATUS_DB_DROPPED": Boolean(),
		"SERVER_STATUS_NO_BACKSLASH_ESCAPES": Boolean(),
		"SERVER_STATUS_METADATA_CHANGED": Boolean(),
		"SERVER_QUERY_WAS_SLOW": Boolean(),
		"SERVER_PS_OUT_PARAMS": Boolean(),
		"SERVER_STATUS_IN_TRANS_READONLY": Boolean(),
		"SERVER_SESSION_STATE_CHANGED": Boolean()
}

zgrab2_mysql_capability_flags = {
		"CLIENT_LONG_PASSWORD": Boolean(),
		"CLIENT_FOUND_ROWS": Boolean(),
		"CLIENT_LONG_FLAG": Boolean(),
		"CLIENT_CONNECT_WITH_DB": Boolean(),
		"CLIENT_NO_SCHEMA": Boolean(),
		"CLIENT_COMPRESS": Boolean(),
		"CLIENT_ODBC": Boolean(),
		"CLIENT_LOCAL_FILES": Boolean(),
		"CLIENT_IGNORE_SPACE": Boolean(),
		"CLIENT_PROTOCOL_41": Boolean(),
		"CLIENT_INTERACTIVE": Boolean(),
		"CLIENT_SSL": Boolean(),
		"CLIENT_IGNORE_SIGPIPE": Boolean(),
		"CLIENT_TRANSACTIONS": Boolean(),
		"CLIENT_RESERVED": Boolean(),
		"CLIENT_SECURE_CONNECTION": Boolean(),
		"CLIENT_MULTI_STATEMENTS": Boolean(),
		"CLIENT_MULTI_RESULTS": Boolean(),
		"CLIENT_PS_MULTI_RESULTS": Boolean(),
		"CLIENT_PLUGIN_AUTH": Boolean(),
		"CLIENT_CONNECT_ATTRS": Boolean(),
		"CLIENT_PLUGIN_AUTH_LEN_ENC_CLIENT_DATA": Boolean(),
		"CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS": Boolean(),
		"CLIENT_SESSION_TRACK": Boolean(),
		"CLIENT_DEPRECATED_EOF": Boolean()
}

# zgrab2/lib/mysql/mysql.go: HandshakePacket
zgrab2_mysql_handshake = SubRecord({
    "parsed": SubRecord({
        "protocol_version": Unsigned8BitInteger(required = True),
        "server_version": String(required = True),
        "connection_id": DebugOnly(Unsigned32BitInteger()),
        "auth_plugin_data_part_1": DebugOnly(Binary()),
        "capability_flags": SubRecord(zgrab2_mysql_capability_flags, required = True),
        "character_set": DebugOnly(Unsigned8BitInteger()),
        "short_handshake": DebugOnly(Boolean()),
        "status_flags": SubRecord(zgrab2_mysql_server_status_flags, required = False),
        "auth_plugin_data_len": DebugOnly(Unsigned8BitInteger()),
        "reserved": DebugOnly(Binary()),
        "auth_plugin_data_part_2": DebugOnly(Binary()),
        "auth_plugin_name": DebugOnly(String())
    })
}, extends = zgrab2_mysql_packet)

# zgrab2/lib/mysql/mysql.go: OKPacket
zgrab2_mysql_ok = SubRecord({
    "parsed": SubRecord({
        "header": DebugOnly(Unsigned8BitInteger()),
        "affected_rows": DebugOnly(Signed64BitInteger()), # FIXME: Unsigned 64-bit integers not supported...? 
        "last_insert_id": Signed64BitInteger(),
        "status_flags": SubRecord(zgrab2_mysql_server_status_flags, required = False),
        "warnings": Unsigned16BitInteger(),
        "info": String(),
        "session_state_changes": DebugOnly(String())
    })
}, extends = zgrab2_mysql_packet)

# zgrab2/lib/mysql/mysql.go: ERRPacket
zgrab2_mysql_error = SubRecord({
    "parsed": SubRecord({
        "header": DebugOnly(Unsigned8BitInteger()),
        "error_code": Unsigned16BitInteger(),
        "sql_state_marker": DebugOnly(Integer()),
        "sql_state": DebugOnly(String()),
        "error_message": String()
    })
}, extends = zgrab2_mysql_packet)

# zgrab2/lib/mysql/mysql.go: SSLRequestPacket
zgrab2_mysql_ssl_request = SubRecord({
    "parsed": SubRecord({
        "capability_flags": SubRecord(zgrab2_mysql_capability_flags, required = True),
        "max_packet_size": DebugOnly(Unsigned32BitInteger()),
        "character_set": DebugOnly(Unsigned8BitInteger()),
        "reserved": DebugOnly(Binary())
    })
}, extends = zgrab2_mysql_packet)

# zgrab2/modules/mysql.go: MySQLScanResults
zgrab2_mysql = SubRecord({
    "result": SubRecord({
        "tls": zgrab2_tls_log,
        "handshake": zgrab2_mysql_handshake,
        "error": zgrab2_mysql_error,
        "ssl_request": zgrab2_mysql_ssl_request
    })
}, extends = zgrab2_protocol_base)

zschema.registry.register_schema("zgrab-mysql", zgrab2_mysql)

register_result_type('mysql', zgrab2_mysql)

if __name__ == '__main__':
    from subprocess import call
    schema_types = ['bigquery', 'elasticsearch', 'json', 'text', 'flat']
    for name in zschema.registry.all_schemas():
        for schema_type in schema_types:
            cmd = ["zschema", schema_type, __file__ + ":" + name]
            call(cmd)

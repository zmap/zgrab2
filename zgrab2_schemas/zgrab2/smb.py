# zschema sub-schema for zgrab2's smb module
# Registers zgrab2-smb globally, and smb with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

header_log = {
    "protocol_id": Binary(),
    "status": Unsigned32BitInteger(),
    "command": Unsigned16BitInteger(),
    "credits": Unsigned16BitInteger(),
    "flags": Unsigned32BitInteger(),
}


# Return a (shallow) copy of base, with the fields of new merged atop it
def extended(base, new):
    copy = {k: v for k, v in base.items()}
    for k, v in new.items():
        copy[k] = v
    return copy


negotiate_log = SubRecord(
    extended(
        header_log,
        {
            "security_mode": Unsigned16BitInteger(),
            "dialect_revision": Unsigned16BitInteger(),
            "server_guid": Binary(),
            "capabilities": Unsigned32BitInteger(),
            "system_time": Unsigned32BitInteger(),
            "server_start_time": Unsigned32BitInteger(),
            "authentication_types": ListOf(String()),
        },
    )
)

session_setup_log = SubRecord(
    extended(
        header_log,
        {
            "setup_flags": Unsigned16BitInteger(),
            "target_name": String(),
            "negotiate_flags": Unsigned32BitInteger(),
        },
    )
)


smb_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "smbv1_support": Boolean(),
                "smb_version": SubRecord(
                    {
                        "major": Unsigned8BitInteger(doc="Major version"),
                        "minor": Unsigned8BitInteger(doc="Minor version"),
                        "revision": Unsigned8BitInteger(doc="Protocol Revision"),
                        "version_string": String(doc="Full SMB Version String"),
                    }
                ),
                "native_os": String(doc="Operating system claimed by server"),
                "ntlm": String(doc="Native LAN Manager"),
                "group_name": String(doc="Group name"),
                "smb_capabilities": SubRecord(
                    {
                        "smb_dfs_support": Boolean(
                            doc="Server supports Distributed File System"
                        ),
                        "smb_leasing_support": Boolean(doc="Server supports Leasing"),
                        "smb_multicredit_support": Boolean(
                            doc="Server supports multi-credit operations"
                        ),
                        "smb_multchan_support": Boolean(
                            doc="Server supports multiple channels per session"
                        ),
                        "smb_persistent_handle_support": Boolean(
                            doc="Server supports persistent handles"
                        ),
                        "smb_directory_leasing_support": Boolean(
                            doc="Server supports directory leasing"
                        ),
                        "smb_encryption_support": Boolean(
                            doc="Server supports encryption"
                        ),
                    },
                    doc="Capabilities flags for the connection. See [MS-SMB2] Sect. 2.2.4.",
                ),
                "negotiation_log": negotiate_log,
                "has_ntlm": Boolean(
                    doc="Server supports the NTLM authentication method"
                ),
                "session_setup_log": session_setup_log,
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-smb", smb_scan_response)

zgrab2.register_scan_response_type("smb", smb_scan_response)

# zschema sub-schema for zgrab2's oracle module
# Registers zgrab2-oracle globally, and oracle with the main zgrab2 schema.

from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

FlagsSet = zgrab2.FlagsSet

global_service_options = [
    "BROKEN_CONNECT_NOTIFY",
    "PACKET_CHECKSUM",
    "HEADER_CHECKSUM",
    "FULL_DUPLEX",
    "HALF_DUPLEX",
    "UNKNOWN_0100",
    "UNKNOWN_0080",
    "UNKNOWN_0040",
    "UNKNOWN_0020",
    "DIRECT_IO",
    "ATTENTION_PROCESSING",
    "CAN_RECEIVE_ATTENTION",
    "CAN_SEND_ATTENTION",
    "UNKNOWN_0001",
]

connect_flags = [
    "SERVICES_WANTED",
    "INTERCHANGE_INVOLVED",
    "SERVICES_ENABLED",
    "SERVICES_LINKED_IN",
    "SERVICES_REQUIRED",
    "UNKNOWN_20",
    "UNKNOWN_40",
    "UNKNOWN_80",
]

nsn_services = [
    "Authentication",
    "Encryption",
    "DataIntegrity",
    "Supervisor",
]

descriptor_entry = SubRecord({
    "key": WhitespaceAnalyzedString(doc="The dot-separated path to the descriptor", examples=["DESCRIPTION.ERR", "DESCRIPTION.CONNECT_DATA.CID.PROGRAM"]),
    "value": WhitespaceAnalyzedString(doc="The descriptor value."),
})

oracle_scan_response = SubRecord({
    "result": SubRecord({
        "handshake": SubRecord({
            "accept_version": Unsigned16BitInteger(doc="The protocol version number from the Accept packet."),
            "global_service_options": FlagsSet(global_service_options, doc="Set of flags that the server returns in the Accept packet."),
            "connect_flags0": FlagsSet(connect_flags, doc="The first set of ConnectFlags returned in the Accept packet."),
            "connect_flags1": FlagsSet(connect_flags, doc="The second set of ConnectFlags returned in the Accept packet."),
            "did_resend": Boolean(doc="True if the server sent a Resend packet request in response to the client's first Connect packet."),
            "redirect_target_raw": WhitespaceAnalyzedString(doc="The connect descriptor returned by the server in the Redirect packet, if one is sent. Otherwise, omitted.", examples=[
                "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=theServiceName)(CID=(PROGRAM=zgrab2)(HOST=targethost)(USER=targetuser)))(ADDRESS=(PROTOCOL=TCP)(HOST=1.2.3.4)(PORT=1521)))"
            ]),
            "redirect_target": ListOf(descriptor_entry, doc="The parsed connect descriptor returned by the server in the redirect packet, if one is sent. Otherwise, omitted. The parsed descriptor is a list of objects with key and value, where the keys strings like 'DESCRIPTION.CONNECT_DATA.SERVICE_NAME'."),
            "refuse_error_raw": WhitespaceAnalyzedString(doc="The data from the Refuse packet returned by the server; it is empty if the server does not return a Refuse packet.", examples=[
                "(DESCRIPTION=(ERR=1153)(VSNNUM=186647040)(ERROR_STACK=(ERROR=(CODE=1153)(EMFI=4)(ARGS='()'))(ERROR=(CODE=303)(EMFI=1))))"
            ]),
            "refuse_error": ListOf(descriptor_entry, doc="The parsed descriptor returned by the server in the Refuse packet; it is empty if the server does not return a Refuse packet. The keys are strings like 'DESCRIPTION.ERROR_STACK.ERROR.CODE'."),
            "refuse_version": WhitespaceAnalyzedString(doc="The parsed DESCRIPTION.VSNNUM field from the RefuseError descriptor returned by the server in the Refuse packet, in dotted-decimal format.", examples=["11.2.0.2.0"]),
            "refuse_reason_app": WhitespaceAnalyzedString(doc="The 'AppReason' returned by the server in the RefusePacket, as an 8-bit unsigned hex string. Omitted if the server did not send a Refuse packet.", examples=["0x22", "0x04"]),
            "refuse_reason_sys": WhitespaceAnalyzedString(doc="The 'SysReason' returned by the server in the RefusePacket, as an 8-bit unsigned hex string. Omitted if the server did not send a Refuse packet.", examples=["0x00", "0x04"]),
            "nsn_version": WhitespaceAnalyzedString(doc="The ReleaseVersion string (in dotted-decimal format) in the root of the Native Service Negotiation packet.", examples=["11.2.0.2.0"]),
            "nsn_service_versions": SubRecord({
                service: WhitespaceAnalyzedString() for service in nsn_services
            }, doc="A map from the native Service Negotation service names to the ReleaseVersion (in dotted-decimal format) in that service packet."),
        }, doc="The log of the Oracle / TDS handshake process."),
        "tls": zgrab2.tls_log,
    })
}, extends=zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-oracle", oracle_scan_response)

zgrab2.register_scan_response_type("oracle", oracle_scan_response)

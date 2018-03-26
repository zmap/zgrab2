# zschema sub-schema for zgrab2's oracle module
# Registers zgrab2-oracle globally, and oracle with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import schemas.zcrypto as zcrypto
import schemas.zgrab2 as zgrab2

# Get a dict of all keys, mapping key -> true 
def flagsSet(keys):
    return SubRecord({
        key: Boolean() for key in keys
    })

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

parsed_descriptor = ListOf(SubRecord({
    "key": String(),
    "value": String(),
}))

oracle_scan_response = SubRecord({
    "result": SubRecord({
        "handshake": SubRecord({
            "accept_version": Unsigned16BitInteger(),
            "global_service_options": flagsSet(global_service_options),
            "connect_flags0": flagsSet(connect_flags),
            "connect_flags1": flagsSet(connect_flags),
            "did_resend": Boolean(),
            "redirect_target_raw": String(),
            "redirect_target": parsed_descriptor,
            "refuse_error_raw": String(),
            "refuse_error": parsed_descriptor,
            "refuse_version": String(),
            "refuse_reason_app": String(),
            "refuse_reason_sys": String(),
            "nsn_version": String(),
            "nsn_service_versions": SubRecord({
                service: String() for service in nsn_services
            }),
        }),
        "tls": zgrab2.tls_log,
    })
}, extends = zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-oracle", oracle_scan_response)

zgrab2.register_scan_response_type("oracle", oracle_scan_response)

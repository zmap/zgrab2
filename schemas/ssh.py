# zschema sub-schema for zgrab2's ssh module (modules/ssh.go)
# Registers zgrab2-ssh globally, and ssh with the main zgrab2 schema.

from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

from schemas.zcrypto import *
import schemas.zgrab2 as zgrab2

# zgrab2/lib/ssh/messages.go: (Json)kexInitMsg
zgrab2_ssh_kex_init_message = SubRecord({
    "cookie": Binary(),
    "kex_algorithms":ListOf(String()),
    "host_key_algorithms":ListOf(String()),
    "client_to_server_ciphers":ListOf(String()),
    "server_to_client_ciphers":ListOf(String()),
    "client_to_server_macs":ListOf(String()),
    "server_to_client_macs":ListOf(String()),
    "client_to_server_compression":ListOf(String()),
    "server_to_client_compression":ListOf(String()),
    "client_to_server_languages":ListOf(String()),
    "server_to_client_languages":ListOf(String()),
    "first_kex_follows":Boolean(),
    "reserved":Unsigned32BitInteger(),
})

# zgrab2/lib/ssh/log.go: EndpointId
zgrab2_ssh_endpoint_id = SubRecord({
    "raw": String(),
    "version": String(),
    "software": String(),
    "comment": String()
})

# zgrab2/lib/ssh/kex.go: kexResult
zgrab2_ssh_kex_result = SubRecord({
    "H": Binary(),
    "K": Binary(),
    "session_id": Binary()
})

# zgrab2/lib/ssh/keys.go: ed25519PublicKey
ed25519_public_key = SubRecord({
    "public_bytes":Binary(),
})

# zgrab2/lib/ssh/certs.go: JsonSignature
xssh_signature = SubRecord({
    "parsed":SubRecord({
        "algorithm":String(),
        "value":Binary(),
    }),
    "raw":Binary(),
})

# zgrab/ztools/keys/ecdhe.go: ECDHPrivateParams
golang_crypto_param = SubRecord({
    "value":Binary(),
    "length":Unsigned32BitInteger()
})

# zgrab2/lib/ssh/log.go: HandshakeLog
# TODO: Can ssh re-use any of the generic TLS model?
ssh_scan_response = SubRecord({
    "result": SubRecord({
        "server_id":SubRecord({
            "raw":AnalyzedString(),
            "version":String(),
            "software":AnalyzedString(),
            "comment":AnalyzedString(),
        }),
        "client_id": zgrab2_ssh_endpoint_id,
        "server_key_exchange": zgrab2_ssh_kex_init_message,
        "client_key_exchange": zgrab2_ssh_kex_init_message,
        "algorithm_selection":SubRecord({
            "dh_kex_algorithm":String(),
            "host_key_algorithm":String(),
            "client_to_server_alg_group": SubRecord({
                "cipher":String(),
                "mac":String(),
                "compression":String(),
            }),
            "server_to_client_alg_group": SubRecord({
                "cipher":String(),
                "mac":String(),
                "compression":String(),
            }),
        }),
        "key_exchange": SubRecord({
            "curve25519_sha256_params": SubRecord({
                "server_public": Binary(),
            }),
            "ecdh_params": SubRecord({
                "server_public": SubRecord({
                    "x": golang_crypto_param,
                    "y": golang_crypto_param,
                }),
            }),
            "dh_params": SubRecord({
                "prime": golang_crypto_param,
                "generator": golang_crypto_param,
                "server_public": golang_crypto_param,
            }),
            "server_signature":xssh_signature,
            "server_host_key":SubRecord({
                "raw":Binary(),
                "algorithm":String(),
                "fingerprint_sha256":String(),
                "rsa_public_key":rsa_public_key,
                "dsa_public_key":dsa_public_key,
                "ecdsa_public_key":ecdsa_public_key,
                "ed25519_public_key":ed25519_public_key,
                "certkey_public_key":SubRecord({
                    "nonce":Binary(),
                    "key":SubRecord({
                        "raw":Binary(),
                        "fingerprint_sha256":String(),
                        "algorithm":String(),
                        "rsa_public_key":rsa_public_key,
                        "dsa_public_key":dsa_public_key,
                        "ecdsa_public_key":ecdsa_public_key,
                        "ed25519_public_key":ed25519_public_key,
                    }),
                    "serial":String(),
                    "cert_type":SubRecord({
                        "id":Unsigned32BitInteger(),
                        "name":String(),
                    }),
                    "key_id":String(),
                    "valid_principals":ListOf(String()),
                    "validity":SubRecord({
                        "valid_after":DateTime(doc="Timestamp of when certificate is first valid. Timezone is UTC."),
                        "valid_before":DateTime(doc="Timestamp of when certificate expires. Timezone is UTC."),
                        "length":Signed64BitInteger(),
                    }),
                    "reserved":Binary(),
                    "signature_key":SubRecord({
                        "raw":Binary(),
                        "fingerprint_sha256":String(),
                        "algorithm":String(),
                        "rsa_public_key":rsa_public_key,
                        "dsa_public_key":dsa_public_key,
                        "ecdsa_public_key":ecdsa_public_key,
                        "ed25519_public_key":ed25519_public_key,
                    }),
                    "signature":xssh_signature,
                    "parse_error":String(),
                    "extensions":SubRecord({
                        "known":SubRecord({
                            "permit_X11_forwarding":String(),
                            "permit_agent_forwarding":String(),
                            "permit_port_forwarding":String(),
                            "permit_pty":String(),
                            "permit_user_rc":String(),
                        }),
                        "unknown":ListOf(String()),
                    }),
                    "critical_options":SubRecord({
                        "known":SubRecord({
                            "force_command":String(),
                            "source_address":String(),
                        }),
                        "unknown":ListOf(String()),
                    })
                }),
            }),
        }),
        "userauth":ListOf(String()),
        "crypto": zgrab2_ssh_kex_result
    })
}, extends = zgrab2.base_scan_response)

zschema.registry.register_schema("zgrab2-ssh", ssh_scan_response)
zgrab2.register_scan_response_type('ssh', ssh_scan_response)

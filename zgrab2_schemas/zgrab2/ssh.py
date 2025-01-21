# zschema sub-schema for zgrab2's ssh module (modules/ssh.go)
# Registers zgrab2-ssh globally, and ssh with the main zgrab2 schema.

from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

# NOTE: Despite the fact that we have e.g. "supportedHostKeyAlgos",
# "allSupportedCiphers", etc, including a different value is not syntactically
# incorrect...so all of the following algorithm identifiers are Strings with
# examples=[...], rather tha Enums with values=[...].

# lib/ssh/common.go -- allSupportedKexAlgos
KexAlgorithm = String.with_args(
    doc="An ssh key exchange algorithm identifier, named according to section 6 of https://www.ietf.org/rfc/rfc4251.txt; see https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-15 for standard values.",
    examples=[
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "curve25519-sha256@libssh.org",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group-exchange-sha256",
    ],
)

KexAlgorithms = ListOf.with_args(KexAlgorithm())

# Defined in lib/ssh/common.go -- supportedHostKeyAlgos, though they are
# generated via PublicKey.Type()
KeyAlgorithm = String.with_args(
    doc="An ssh public key algorithm identifier, named according to section 6 of https://www.ietf.org/rfc/rfc4251.txt; see https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-19 for standard values.",
    examples=[
        "ssh-rsa-cert-v01@openssh.com",
        "ssh-dss-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        "ssh-ed25519-cert-v01@openssh.com",
        "ssh-rsa",
        "ssh-dss",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "ssh-ed25519",
    ],
)

KeyAlgorithms = ListOf.with_args(KeyAlgorithm())

# From lib/ssh/common.go -- allSupportedCiphers
CipherAlgorithm = String.with_args(
    doc="An ssh cipher algorithm identifier, named according to section 6 of https://www.ietf.org/rfc/rfc4251.txt; see https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-16 for standard values.",
    examples=[
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-gcm@openssh.com",
        "aes128-cbc",
        "3des-cbc",
        "arcfour256",
        "arcfour128",
        "arcfour",
    ],
)

CipherAlgorithms = ListOf.with_args(CipherAlgorithm())

# From lib/ssh/common.go -- supportedMACs.
MACAlgorithm = String.with_args(
    doc="An ssh MAC algorithm identifier, named according to section 6 of https://www.ietf.org/rfc/rfc4251.txt; see https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-18 for standard values.",
    examples=["hmac-sha2-256", "hmac-sha1", "hmac-sha1-96"],
)
MACAlgorithms = ListOf.with_args(MACAlgorithm())

# From lib/ssh/common.go -- supportedCompressions
CompressionAlgorithm = String.with_args(
    doc="An ssh compression algorithm identifier, named according to section 6 of https://www.ietf.org/rfc/rfc4251.txt; see https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-20 for standard values.",
    examples=["none", "zlib"],
)
CompressionAlgorithms = ListOf.with_args(CompressionAlgorithm())

LanguageTag = String.with_args(
    doc="A language tag, as defined in https://www.ietf.org/rfc/rfc3066.txt."
)
LanguageTags = ListOf.with_args(
    LanguageTag(), doc="A name-list of language tags in order of preference."
)

# zgrab2/lib/ssh/messages.go: (Json)kexInitMsg
KexInitMessage = SubRecordType(
    {
        "cookie": Binary(),
        "kex_algorithms": KexAlgorithms(
            doc="Key exchange algorithms used in the handshake."
        ),
        "host_key_algorithms": KeyAlgorithms(
            doc="Asymmetric key algorithms for the host key supported by the client."
        ),
        "client_to_server_ciphers": CipherAlgorithms(),
        "server_to_client_ciphers": CipherAlgorithms(),
        "client_to_server_macs": MACAlgorithms(),
        "server_to_client_macs": MACAlgorithms(),
        "client_to_server_compression": CompressionAlgorithms(),
        "server_to_client_compression": CompressionAlgorithms(),
        "client_to_server_languages": LanguageTags(),
        "server_to_client_languages": LanguageTags(),
        "first_kex_follows": Boolean(),
        "reserved": Unsigned32BitInteger(),
        "serverHaSSH": String(),
    }
)

# zgrab2/lib/ssh/log.go: EndpointId
EndpointID = SubRecordType(
    {
        "raw": String(),
        "version": String(),
        "software": String(),
        "comment": String(),
    }
)

# This could be merged into a single class with e.g. an analyzed param,
# but it's probably clearer to just duplicate it.
AnalyzedEndpointID = SubRecordType(
    {
        "raw": AnalyzedString(),
        "version": String(),
        "software": AnalyzedString(),
        "comment": AnalyzedString(),
    }
)

# zgrab2/lib/ssh/kex.go: kexResult
KexResult = SubRecordType({"H": Binary(), "K": Binary(), "session_id": Binary()})

# zgrab2/lib/ssh/keys.go: ed25519PublicKey
ED25519PublicKey = SubRecordType(
    {
        "public_bytes": Binary(),
    }
)

# zgrab2/lib/ssh/kex.go: curve25519sha256JsonLogParameters (via curve25519sha256)
Curve25519SHA256Params = SubRecordType(
    {
        "client_public": Binary(required=False),
        "client_private": Binary(required=False),
        "server_public": Binary(required=False),
    }
)

# zgrab2/lib/ssh/certs.go: JsonSignature
Signature = SubRecordType(
    {
        "parsed": SubRecord(
            {
                "algorithm": KeyAlgorithm(),
                "value": Binary(),
            }
        ),
        "raw": Binary(),
        "h": Binary(),
    }
)

# lib/ssh/kex.go: PublicKeyJsonLog, sans the certkey_public_key (since that would create a loop)
SSHPublicKey = SubRecordType(
    {
        "raw": Binary(),
        "fingerprint_sha256": String(),
        # TODO: Enum? Obviously must serialize to one of rsa/dsa/ecdsa/ed25519_public_key...
        "algorithm": String(),
        # For compatiblity with ztag
        "key_algorithm": String(),
        "rsa_public_key": zcrypto.RSAPublicKey(),
        "dsa_public_key": zcrypto.DSAPublicKey(),
        "ecdsa_public_key": zcrypto.ECDSAPublicKey(),
        "ed25519_public_key": ED25519PublicKey(),
    }
)

# lib/ssh/certs.go: JsonCertType
CertType = SubRecordType(
    {
        "id": Unsigned32BitInteger(
            doc="The numerical certificate type value. 1 identifies user certificates, 2 identifies host certificates."
        ),
        "name": Enum(
            values=["USER", "HOST", "unknown"],
            doc="The human-readable name for the certificate type.",
        ),
    }
)

# lib/ssh/certs.go: JsonCertificate
SSHPublicKeyCert = SubRecord.with_args(
    {
        # TODO: Use / include our cert type here, or maybe somewhere else in the response?
        "certkey_public_key": SubRecord(
            {
                "nonce": Binary(),
                # Note that this is not recursive, since SSHPublicKey() does not include certkey_public_key.
                "key": SSHPublicKey(),
                "serial": String(
                    doc="The certificate serial number, encoded as a base-10 string."
                ),
                "cert_type": CertType(),
                "key_id": String(
                    doc="A free-form text field filled in by the CA at the time of signing, intended to identify the principal in log messages."
                ),
                "valid_principals": ListOf(
                    String(),
                    doc="Names for which this certificate is valid; hostnames for cert_type=HOST certificates and usernames for cert_type=USER certificates.",
                ),
                "validity": SubRecord(
                    {
                        "valid_after": DateTime(
                            doc="Timestamp of when certificate is first valid. Timezone is UTC."
                        ),
                        "valid_before": DateTime(
                            doc="Timestamp of when certificate expires. Timezone is UTC."
                        ),
                        "length": Signed64BitInteger(),
                    }
                ),
                "reserved": Binary(),
                "signature_key": SSHPublicKey(),
                "signature": Signature(),
                "parse_error": String(),
                "extensions": SubRecord(
                    {
                        "known": SubRecord(
                            {
                                "permit_X11_forwarding": String(),
                                "permit_agent_forwarding": String(),
                                "permit_port_forwarding": String(),
                                "permit_pty": String(),
                                "permit_user_rc": String(),
                            }
                        ),
                        "unknown": ListOf(String()),
                    }
                ),
                "critical_options": SubRecord(
                    {
                        "known": SubRecord(
                            {
                                "force_command": String(),
                                "source_address": String(),
                            }
                        ),
                        "unknown": ListOf(String()),
                    }
                ),
            }
        )
    },
    extends=SSHPublicKey(),
)


# zgrab2/lib/ssh/common.go: directionAlgorithms
DirectionAlgorithms = SubRecordType(
    {
        "cipher": CipherAlgorithm(),
        "mac": MACAlgorithm(),
        "compression": CompressionAlgorithm(),
    }
)

# zgrab2/lib/ssh/kex.go: interface kexAlgorithm
# Searching usages of kexAlgorithm turns up:
#   - dhGroup: dh_params, server_signature, server_host_key
#   - ecdh: ecdh_params, server_signature, server_host_key
#   - curve25519sha256: curve25519_sha256_params, server_signature, server_host_key
#   - dhGEXSHA: dh_params, server_signature, server_host_key
KeyExchange = SubRecordType(
    {
        "curve25519_sha256_params": Curve25519SHA256Params(),
        "ecdh_params": zcrypto.ECDHParams(),
        "dh_params": zcrypto.DHParams(),
        "server_signature": Signature(),
        "server_host_key": SSHPublicKeyCert(),
    }
)

# zgrab2/lib/ssh/common.go: algorithms (aux in MarshalJSON)
AlgorithmSelection = SubRecordType(
    {
        "dh_kex_algorithm": KexAlgorithm(),
        "host_key_algorithm": KeyAlgorithm(),
        "client_to_server_alg_group": DirectionAlgorithms(),
        "server_to_client_alg_group": DirectionAlgorithms(),
    }
)

# zgrab2/lib/ssh/log.go: HandshakeLog
# TODO: Can ssh re-use any of the generic TLS model?
ssh_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "banner": WhitespaceAnalyzedString(),
                "server_id": AnalyzedEndpointID(),
                "client_id": EndpointID(),
                "server_key_exchange": KexInitMessage(),
                "client_key_exchange": KexInitMessage(),
                "algorithm_selection": AlgorithmSelection(),
                "key_exchange": KeyExchange(),
                "userauth": ListOf(String()),
                "crypto": KexResult(),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-ssh", ssh_scan_response)
zgrab2.register_scan_response_type("ssh", ssh_scan_response)

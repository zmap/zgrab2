from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

# Mostly copied from zmap/zgrab/zgrab_schema.py
# Since the struct -> json mappings are defined in zcrypto, it seems like it
# would make sense to have this schema defined there

# For items in x509/pkix/pkix.go, there is a corresponding struct in
# x509/pkix/json.go, prefixed with "aux" (e.g. Name -> auxName)

# TODO FIXME: zcrypto is not the right place for this.
# Was previously using AnalyzedString(es_include_raw=True),
class CensysString(WhitespaceAnalyzedString):
    "default type for any strings in Censys"
    INCLUDE_RAW = True

# x509/pkix/pkix.go: Name
distinguished_name = SubRecord({
    "serial_number": ListOf(String()),
    "common_name": ListOf(CensysString()),
    "surname": ListOf(CensysString()),
    "country": ListOf(CensysString()),
    "locality": ListOf(CensysString()),
    "province": ListOf(CensysString()),
    "street_address": ListOf(CensysString()),
    "organization": ListOf(CensysString()),
    "organizational_unit": ListOf(CensysString()),
    "postal_code": ListOf(String()),
    "domain_component": ListOf(CensysString()),
    "email_address": ListOf(CensysString()),
    "given_name": ListOf(CensysString()),
    # EV Fields
    # Commented out 2017-08-18 due to ES analyzer mismatch:
    # Data with these fields got into the IPv4 index before the ES mapping
    # was updated, and ES automatically chose a different analyzer.
    # "jurisdiction_country":ListOf(CensysString()),
    # "jurisdiction_locality":ListOf(CensysString()),
    # "jurisdiction_province":ListOf(CensysString()),
})

# x509/pkix/pkix.go: Extension
unknown_extension = SubRecord({
    "id": OID(),
    "critical": Boolean(),
    "value": IndexedBinary(),
})

# x509/pkix/pkix.go: type EDIPartyName struct
edi_party_name = SubRecord({
    "name_assigner": CensysString(),
    "party_name": CensysString(),
})

# x509/extensions.go: GeneralNames/jsonGeneralNames
alternate_name = SubRecord({
    "dns_names": ListOf(FQDN()),
    "email_addresses": ListOf(EmailAddress()),
    "ip_addresses": ListOf(IPAddress()),
    "directory_names": ListOf(distinguished_name),
    "edi_party_names": ListOf(edi_party_name),
    "other_names": ListOf(SubRecord({
        "id": OID(),
        "value": IndexedBinary(),
    })),
    "registered_ids": ListOf(OID()),
    "uniform_resource_identifiers": ListOf(URI()),
})

# json/dhe.go: cryptoParameter / auxCryptoParameter
crypto_parameter = SubRecord({
    "value": IndexedBinary(),
    "length": Unsigned16BitInteger(),
})

# json/dhe.go: DHParams / auxDHParams:
dh_params = SubRecord({
    "prime": crypto_parameter.new(required=True),
    "generator": crypto_parameter.new(required=True),
    "server_public": crypto_parameter.new(required=False),
    "server_private": crypto_parameter.new(required=False),
    "client_public": crypto_parameter.new(required=False),
    "client_private": crypto_parameter.new(required=False),
    "session_key": crypto_parameter.new(required=False),
})

# json/rsa.go: RSAPublicKey/auxRSAPublicKey (alias for crypto/rsa/PublicKey)
rsa_public_key = SubRecord({
    "exponent": Unsigned32BitInteger(),
    "modulus": IndexedBinary(),
    "length": Unsigned16BitInteger(doc="Bit-length of modulus."),
})

# json/rsa.go: RSAClientParams
rsa_client_params = SubRecord({
    "length": Unsigned16BitInteger(),
    "encrypted_pre_master_secret": Binary(),
})

# json/ecdhe.go: TLSCurveID.MarshalJSON()
tls_curve_id = SubRecord({
    "name": String(),
    "id": Unsigned16BitInteger(),
})

# json/ecdhe.go: ECPoint.MarshalJSON()
ec_point = SubRecord({
    "x": crypto_parameter.new(),
    "y": crypto_parameter.new(),
})

# json/ecdhe.go: ECDHPrivateParams
ecdh_private_params = SubRecord({
    "value": IndexedBinary(required=False),
    "length": Unsigned16BitInteger(required=False),
})

# json/ecdhe.go: ECDHParams
ecdh_params = SubRecord({
    "curve_id": tls_curve_id.new(required=False),
    "server_public": ec_point.new(required=False),
    "server_private": ecdh_private_params.new(required=False),
    "client_public": ec_point.new(required=False),
    "client_private": ecdh_private_params.new(required=False),
})

# x509/json.go (mapped from crypto.dsa)
dsa_public_key = SubRecord({
    "p": IndexedBinary(),
    "q": IndexedBinary(),
    "g": IndexedBinary(),
    "y": IndexedBinary(),
})

# x509/json.go (mapped from crypto.ecdsa)
ecdsa_public_key = SubRecord({
    "pub": IndexedBinary(),
    "b": IndexedBinary(),
    "gx": IndexedBinary(),
    "gy": IndexedBinary(),
    "n": IndexedBinary(),
    "p": IndexedBinary(),
    "x": IndexedBinary(),
    "y": IndexedBinary(),
    "curve": Enum(["P-224", "P-256", "P-384", "P-521"]),
    "length": Unsigned16BitInteger(),
    # schema conflict in censys prod cert index
    #"asn1_oid":OID(),
})

# x509/ct/types.go: SignedCertificateTimestamp.
# Note: ztag_sct has "log_name": String(), which is not present in the go.
sct_record = SubRecord({
    "version": Unsigned32BitInteger(),
    "log_id": IndexedBinary(),
    "timestamp": Timestamp(),
    "extensions": Binary(),
    "signature": Binary()
})

# /go/src/net/ip.go: type IPNet struct
ip_net = SubRecord({
    "IP": Binary(),
    "Mask": Binary(),
})

# x509/json.go: auxGeneralSubtreeIP (modifies GeneralSubtreeIP from x509.go)
general_subtree_ip = SubRecord({
    "cidr": String(),
    "begin": IPAddress(),
    "end": IPAddress(),
    "mask": IPAddress(),
}, exclude=["bigquery",]) # XXX

# x509/extensions.go: type NoticeReference struct
notice_reference = SubRecord({
    "organization": CensysString(),
    "notice_numbers": ListOf(Signed32BitInteger()),
})

# x509/extensions.go: type UserNoticeData struct
user_notice_data = SubRecord({
    "explicit_text": EnglishString(),
    "notice_reference": ListOf(notice_reference),
})

# x509/extensions.go: type CertificatePoliciesJSON struct
# TODO: ztag has a "name": String() field?
certificate_policies_data = SubRecord({
    "id": OID(),
    "cps": ListOf(URL()),
    "user_notice": ListOf(user_notice_data),
})

# Generated by zcrypto/x509/extended_key_usage.sh, with a manual tweak on unknown
extended_key_usage = SubRecord({
    # NOTE: ztag has "value" with the comment "TODO: remove after reparse",
    # but there is no "value" in the JSON.
    "value": ListOf(Signed32BitInteger()),
    "any": Boolean(),
    "apple_code_signing": Boolean(),
    "apple_code_signing_development": Boolean(),
    "apple_code_signing_third_party": Boolean(),
    "apple_crypto_development_env": Boolean(),
    "apple_crypto_env": Boolean(),
    "apple_crypto_maintenance_env": Boolean(),
    "apple_crypto_production_env": Boolean(),
    "apple_crypto_qos": Boolean(),
    "apple_crypto_test_env": Boolean(),
    "apple_crypto_tier0_qos": Boolean(),
    "apple_crypto_tier1_qos": Boolean(),
    "apple_crypto_tier2_qos": Boolean(),
    "apple_crypto_tier3_qos": Boolean(),
    "apple_ichat_encryption": Boolean(),
    "apple_ichat_signing": Boolean(),
    "apple_resource_signing": Boolean(),
    "apple_software_update_signing": Boolean(),
    "apple_system_identity": Boolean(),
    "client_auth": Boolean(),
    "code_signing": Boolean(),
    "dvcs": Boolean(),
    "eap_over_lan": Boolean(),
    "eap_over_ppp": Boolean(),
    "email_protection": Boolean(),
    "ipsec_end_system": Boolean(),
    "ipsec_tunnel": Boolean(),
    "ipsec_user": Boolean(),
    "microsoft_ca_exchange": Boolean(),
    "microsoft_cert_trust_list_signing": Boolean(),
    "microsoft_csp_signature": Boolean(),
    "microsoft_document_signing": Boolean(),
    "microsoft_drm": Boolean(),
    "microsoft_drm_individualization": Boolean(),
    "microsoft_efs_recovery": Boolean(),
    "microsoft_embedded_nt_crypto": Boolean(),
    "microsoft_encrypted_file_system": Boolean(),
    "microsoft_enrollment_agent": Boolean(),
    "microsoft_kernel_mode_code_signing": Boolean(),
    "microsoft_key_recovery_21": Boolean(),
    "microsoft_key_recovery_3": Boolean(),
    "microsoft_license_server": Boolean(),
    "microsoft_licenses": Boolean(),
    "microsoft_lifetime_signing": Boolean(),
    "microsoft_mobile_device_software": Boolean(),
    "microsoft_nt5_crypto": Boolean(),
    "microsoft_oem_whql_crypto": Boolean(),
    "microsoft_qualified_subordinate": Boolean(),
    "microsoft_root_list_signer": Boolean(),
    "microsoft_server_gated_crypto": Boolean(),
    "microsoft_sgc_serialized": Boolean(),
    "microsoft_smart_display": Boolean(),
    "microsoft_smartcard_logon": Boolean(),
    "microsoft_system_health": Boolean(),
    "microsoft_system_health_loophole": Boolean(),
    "microsoft_timestamp_signing": Boolean(),
    "microsoft_whql_crypto": Boolean(),
    "netscape_server_gated_crypto": Boolean(),
    "ocsp_signing": Boolean(),
    "sbgp_cert_aa_service_auth": Boolean(),
    "server_auth": Boolean(),
    "time_stamping": Boolean(),
    # NOTE: ztag has this commented out, but it is included in the JSON.
    "unknown": ListOf(OID()),
})

# x509/json.go jsonCertificate (mapped from x509.Certificate)
parsed_certificate = SubRecord({
    "subject": distinguished_name,
    "subject_dn": CensysString(),
    "issuer": distinguished_name,
    "issuer_dn": CensysString(),
    "version": Unsigned8BitInteger(),
    "serial_number": String(doc="Serial number as an signed decimal integer. "\
                                "Stored as string to support >uint lengths. "\
                                "Negative values are allowed."),
    "validity": SubRecord({
        "start": Timestamp(doc="Timestamp of when certificate is first valid. Timezone is UTC."),
        "end": Timestamp(doc="Timestamp of when certificate expires. Timezone is UTC."),
        "length": Signed64BitInteger(),
    }),
    "signature_algorithm": SubRecord({
        "name": String(),
        "oid": String(),
    }),
    "subject_key_info": SubRecord({
        "fingerprint_sha256": HexString(),
        # x509/json.go: auxPublicKeyAlgorithm
        "key_algorithm": SubRecord({
            "name": String(doc="Name of public key type, e.g., RSA or ECDSA. "\
                               "More information is available the named SubRecord "\
                               "(e.g., rsa_public_key)."),
            "oid": OID(doc="OID of the public key on the certificate. "\
                           "This is helpful when an unknown type is present. "\
                           "This field is reserved and not current populated.")
        }),
        "rsa_public_key": rsa_public_key,
        "dsa_public_key": dsa_public_key,
        "ecdsa_public_key": ecdsa_public_key,
    }),
    "extensions": SubRecord({
        "key_usage": SubRecord({
            "value": Unsigned16BitInteger("Integer value of the bitmask in the extension"),
            "digital_signature": Boolean(),
            "certificate_sign": Boolean(),
            "crl_sign": Boolean(),
            "content_commitment": Boolean(),
            "key_encipherment": Boolean(),
            "data_encipherment": Boolean(),
            "key_agreement": Boolean(),
            "decipher_only": Boolean(),
            "encipher_only": Boolean(),
        }),
        "basic_constraints": SubRecord({
            "is_ca": Boolean(),
            "max_path_len": Signed32BitInteger(),
        }),
        "subject_alt_name": alternate_name,
        "issuer_alt_name": alternate_name,
        "crl_distribution_points": ListOf(URL()),
        "authority_key_id": HexString(),
        "subject_key_id": HexString(),
        "extended_key_usage": extended_key_usage,
        "certificate_policies": ListOf(certificate_policies_data),
        "authority_info_access": SubRecord({
            "ocsp_urls": ListOf(URL()),
            "issuer_urls": ListOf(URL())
        }),
        "name_constraints": SubRecord({
            "critical": Boolean(),
            "permitted_names": ListOf(FQDN()),
            # We do not schema email addresses as an EmailAddress per
            # rfc5280#section-4.2.1.10 documentation:
            # A name constraint for Internet mail addresses MAY specify a
            # particular mailbox, all addresses at a particular host, or all
            # mailboxes in a domain.  To indicate a particular mailbox, the
            # constraint is the complete mail address.  For example,
            # "root@example.com" indicates the root mailbox on the host
            # "example.com".  To indicate all Internet mail addresses on a
            # particular host, the constraint is specified as the host name.  For
            # example, the constraint "example.com" is satisfied by any mail
            # address at the host "example.com".  To specify any address within a
            # domain, the constraint is specified with a leading period (as with
            # URIs).  For example, ".example.com" indicates all the Internet mail
            # addresses in the domain "example.com", but not Internet mail
            # addresses on the host "example.com".
            "permitted_email_addresses": ListOf(CensysString()),
            "permitted_ip_addresses": ListOf(general_subtree_ip),
            "permitted_directory_names": ListOf(distinguished_name),
            "permitted_registered_ids": ListOf(OID()),
            "permitted_edi_party_names": ListOf(edi_party_name),
            "excluded_names": ListOf(FQDN()),
            "excluded_email_addresses": ListOf(CensysString()),
            "excluded_ip_addresses": ListOf(general_subtree_ip),
            "excluded_directory_names": ListOf(distinguished_name),
            "excluded_registered_ids": ListOf(String()),
            "excluded_edi_party_names": ListOf(edi_party_name),
        }),
        "signed_certificate_timestamps": ListOf(sct_record),
        "ct_poison": Boolean()
    }),
    "unknown_extensions": ListOf(unknown_extension),
    "signature": SubRecord({
        "signature_algorithm": SubRecord({
            "name": String(),
            "oid": OID(),
        }),
        "value": IndexedBinary(),
        "valid": Boolean(),
        "self_signed": Boolean(),
    }),
    "fingerprint_md5": HexString(),
    "fingerprint_sha1": HexString(),
    "fingerprint_sha256": HexString(),
    "spki_subject_fingerprint": HexString(),
    "tbs_fingerprint": HexString(),
    "tbs_noct_fingerprint": HexString(),
    "names": ListOf(FQDN()),
    # NOTE: ztag has "__expanded_names": ListOf(String())
    # TODO: What Enum() values?
    # [ "unknown", "DV", "OV", "EV" ]
    "validation_level": Enum([ "unknown", "DV", "OV", "EV" ]),
    "redacted": Boolean(),
})

# ??? not in zcrypto?
certificate_trust = SubRecord({
    "type": Enum(doc="root, intermediate, or leaf certificate"),
    "trusted_path": Boolean(doc="Does certificate chain up to browser root store"),
    "valid": Boolean(doc="is this certificate currently valid in this browser"),
    "was_valid": Boolean(doc="was this certificate ever valid in this browser")
})

lint = SubRecord({})

# tls/tls_handshake.go: SimpleCertificate
simple_certificate = SubRecord({
    "raw": Binary(),
    "parsed": parsed_certificate,
    "validation": SubRecord({
        "nss": certificate_trust,
        "apple": certificate_trust,
        "microsoft": certificate_trust,
        "android": certificate_trust,
        "java": certificate_trust,
    }),
    "lint": lint
})

# ???
server_certificate_valid = SubRecord({
    "complete_chain": Boolean(doc="does server provide a chain up to a root"),
    "valid": Boolean(doc="is this certificate currently valid in this browser"),
    "error": String()
})

###### END ztag/zgrab ######

# TODO: Should any of these be IndexedBinary() / CensysString()?

GoInt = Signed32BitInteger

# tls/tls_handshake.go: CipherSuite
cipher_suite = SubRecord({
    "hex": String(),
    # TODO: Enum()? There are a ton of these.
    "name": String(),
    "value": Unsigned16BitInteger(),
})

# tls/tls_handshake.go: CompressionMethod (uint8)
compression_method = SubRecord({
    "hex": String(),
    "name": Enum(["NULL","DEFLATE", "LZS", "unknown"]),
    "value": Unsigned8BitInteger(),
})

# tls/tls_ka.go: auxSignatureAndHash (SignatureAndHash)
signature_and_hash_type = SubRecord({
    "signature_algorithm": String(),
    "hash_algorithm": String(),
})

# tls/tls_handshake.go: type TLSVersion uint16 (marshal -> name/value)
tls_version = SubRecord({
    # tls_names.go: TLSVersion.String()
    "name": Enum(values=["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "unknown"]),
    "value": GoInt(),
})

# tls/tls_handshake.go: type SessionTicket
session_ticket = SubRecord({
    "value": Binary(),
    "length": GoInt(),
    "lifetime_hint": Unsigned32BitInteger(),
})

# tls/common.go: CurveID
curve_id = SubRecord({
    "hex": String(),
    # TODO: Enum()? See tls_names.go
    "name": String(),
    "value": Unsigned16BitInteger(),
})

# tls/common.go: PointFormat
point_format = SubRecord({
    "hex": String(),
    "name": Enum(values=["unknown", "uncompressed", "ansiX962_compressed_prime", "ansiX962_compressed_char2"]),
    "value": Unsigned8BitInteger(),
})

# tls/tls_handshake.go: ClientHello
client_hello = SubRecord({
    "version": tls_version,
    "random": Binary(),
    "session_id": Binary(),
    "cipher_suites": ListOf(cipher_suite),
    "compression_methods": ListOf(compression_method),
    "ocsp_stapling": Boolean(),
    "ticket": Boolean(),
    "secure_renegotiation": Boolean(),
    "heartbeat": Boolean(),
    "extended_random": Binary(),
    "extended_master_secret": Boolean(),
    "next_protocol_negotiation": Boolean(),
    "server_name": String(),
    "scts": Boolean(),
    "supported_curves": ListOf(curve_id),
    "supported_point_formats": ListOf(point_format),
    "session_ticket": session_ticket,
    "signature_and_hashes": ListOf(signature_and_hash_type),
    "sct_enabled": Boolean(),
    "alpn_protocols": ListOf(String()),
    "unknown_extensions": ListOf(Binary()),
})

# tls/tls_handshake.go: ServerHello
server_hello = SubRecord({
    "version": tls_version,
    "random": Binary(),
    "session_id": Binary(),
    "cipher_suite": cipher_suite,
    "compression_method": Unsigned8BitInteger(),
    "ocsp_stapling": Boolean(),
    "ticket": Boolean(),
    "secure_renegotiation": Boolean(),
    "heartbeat": Boolean(),
    "extended_random": Binary(),
    "extended_master_secret": Boolean(),
    "scts": ListOf(SubRecord({
        "parsed": sct_record,
        "raw": Binary(),
    })),
})

# tls/tls_handshake.go: ServerKeyExchange
server_key_exchange = SubRecord({
    "ecdh_params": ecdh_params,
    "rsa_params": rsa_client_params,
    "dh_params": dh_params,
    "digest": Binary(),
    "signature": SubRecord({
        "raw": Binary(),
        "type": String(),
        "valid": Boolean(),
        "signature_and_hash_type": signature_and_hash_type,
        "tls_version": tls_version,
    }),
    "signature_error": String(),
})

# tls/tls_handshake.go: ClientKeyExchange
client_key_exchange = SubRecord({
    "dh_params": dh_params,
    "ecdh_params": ecdh_params,
    "rsa_params": rsa_client_params,
})

# tls/tls_handshake.go: MasterSecret
master_secret = SubRecord({
    "value": Binary(),
    "length": GoInt(),
})

# tls/tls_handshake.go: PreMasterSecret
pre_master_secret = SubRecord({
    "value": Binary(),
    "length": GoInt(),
})

# tls/tls_handshake.go: KeyMaterial
key_material = SubRecord({
    "pre_master_secret": pre_master_secret,
    "master_secret": master_secret,
})

# tls/tls_handshake.go: ServerHandshake
tls_handshake = SubRecord({
    "client_hello": client_hello,
    "server_hello": server_hello,
    "server_certificates": SubRecord({
        "certificate": simple_certificate,
        "chain": ListOf(simple_certificate),
        # x509/validation.go: type Validation struct
        "validation": SubRecord({
            "matches_domain": Boolean(),
            # "stores" does not seem to be present here?
            "browser_trusted": Boolean(),
            "browser_error": String()
        }),
    }),
    "server_key_exchange": server_key_exchange,
    "server_finished": SubRecord({
        "verify_data": Binary()
    }),
    "session_ticket": session_ticket,
    "key_material": key_material,
    "client_finished": SubRecord({
        "verify_data": Binary()
    }),
    "client_key_exchange": client_key_exchange,
})

# zcrypto/tls/tls_heartbeat.go: Heartbleed
heartbleed_log = SubRecord({
    "heartbleed_enabled": Boolean(),
    "heartbleed_vulnerable": Boolean()
})

# zcrypto/x509/chain.go: type CertificateChain []*Certificate
certificate_chain = ListOf(parsed_certificate)

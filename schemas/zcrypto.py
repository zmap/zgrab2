from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

# Mostly copied from zmap/zgrab/zgrab_schema.py
# Since the struct -> json mappings are defined in zcrypto, it seems like it
# would make sense to have this schema defined there

# For items in x509/pkix/pkix.go, there is a corresponding struct in
# x509/pkix/json.go, prefixed with "aux" (e.g. Name -> auxName)

# x509/pkix/pkix.go: Name
distinguished_name = SubRecord({
    "serial_number": ListOf(String()),
    "common_name": ListOf(String()),
    "country": ListOf(String()),
    "locality": ListOf(String()),
    "province": ListOf(String()),
    "street_address": ListOf(String()),
    "organization": ListOf(String()),
    "organizational_unit": ListOf(String()),
    "postal_code": ListOf(String()),
    "domain_component": ListOf(String()),
})

# x509/pkix/pkix.go: Extension
unknown_extension = SubRecord({
    "id": String(),
    "critical": Boolean(),
    "value": Binary(),
})

# x509/extensions.go: GeneralNames/jsonGeneralNames
alternate_name = SubRecord({
    "dns_names": ListOf(String()),
    "email_addresses": ListOf(String()),
    "ip_addresses": ListOf(String()),
    "directory_names": ListOf(distinguished_name),
    "edi_party_names": ListOf(SubRecord({
        "name_assigner": AnalyzedString(es_include_raw=True),
        "party_name": AnalyzedString(es_include_raw=True),
    })),
    "other_names": ListOf(SubRecord({
        "id": String(),
        "value": Binary(),
    })),
    "registered_ids": ListOf(String()),
    "uniform_resource_identifiers": ListOf(AnalyzedString(es_include_raw=True)),
})

# x509/json.go (mapped from crypto.rsa)
rsa_public_key = SubRecord({
    "exponent": Long(),
    "modulus": Binary(),
    "length": Unsigned32BitInteger(doc="Bit-length of modulus."),
})

# x509/json.go (mapped from crypto.dsa)
dsa_public_key = SubRecord({
    "p": Binary(),
    "q": Binary(),
    "g": Binary(),
    "y": Binary(),
})

# x509/json.go (mapped from crypto.ecdsa)
ecdsa_public_key = SubRecord({
    "pub": Binary(),
    "b": Binary(),
    "gx": Binary(),
    "gy": Binary(),
    "n": Binary(),
    "p": Binary(),
    "x": Binary(),
    "y": Binary(),
    "curve": String(),
    "length": Unsigned16BitInteger(),
    "asn1_oid": String(),
})

# x509/json.go jsonCertificate (mapped from x509.Certificate)
parsed_certificate = SubRecord({
    "subject": distinguished_name,
    # TODO FIXME: Added by jb 2017/12/11
    "subject_dn": String(),
    "issuer": distinguished_name,
    # TODO FIXME: Added by jb 2017/12/11
    "issuer_dn": String(),
    "version": Unsigned32BitInteger(),
    "serial_number": String(doc="Serial number as an unsigned decimal integer. Stored as string to support >uint lengths. Negative values are allowed."),
    "validity": SubRecord({
        "start": DateTime(doc="Timestamp of when certificate is first valid. Timezone is UTC."),
        "end": DateTime(doc="Timestamp of when certificate expires. Timezone is UTC."),
        "length": Unsigned32BitInteger(),
    }),
    "signature_algorithm": SubRecord({
        "name": String(),
        "oid": String(),
    }),
    "subject_key_info": SubRecord({
        "fingerprint_sha256": Binary(),
        "key_algorithm": SubRecord({
            "name": String(doc="Name of public key type, e.g., RSA or ECDSA. More information is available the named SubRecord (e.g., rsa_public_key)."),
         }),
        "rsa_public_key": rsa_public_key,
        "dsa_public_key": dsa_public_key,
        "ecdsa_public_key": ecdsa_public_key,
    }),
    "extensions": SubRecord({
        "key_usage": SubRecord({
            "digital_signature": Boolean(),
            "certificate_sign": Boolean(),
            "crl_sign": Boolean(),
            "content_commitment": Boolean(),
            "key_encipherment": Boolean(),
            "value": Unsigned32BitInteger(),
            "data_encipherment": Boolean(),
            "key_agreement": Boolean(),
            "decipher_only": Boolean(),
            "encipher_only": Boolean(),
        }),
        "basic_constraints": SubRecord({
            "is_ca": Boolean(),
            "max_path_len": Unsigned32BitInteger(),
        }),
        "subject_alt_name": alternate_name,
        "issuer_alt_name": alternate_name,
        "crl_distribution_points": ListOf(String()),
        "authority_key_id": Binary(),  # is this actually binary?
        "subject_key_id": Binary(),
        "extended_key_usage": ListOf(Integer()),  # ??? EKUs are OBJECT IDENTIFIERS...?
        "certificate_policies": ListOf(String()),
        "authority_info_access": SubRecord({
            "ocsp_urls": ListOf(String()),
            "issuer_urls": ListOf(String())
        }),
        "name_constraints": SubRecord({
            "critical": Boolean(),
            "permitted_names": ListOf(String()),
            "permitted_email_addresses": ListOf(String()),
            "permitted_ip_addresses": ListOf(String()),
            "permitted_directory_names": ListOf(distinguished_name),
            "excluded_names": ListOf(String()),
            "excluded_email_addresses": ListOf(String()),
            "excluded_ip_addresses": ListOf(String()),
            "excluded_directory_names": ListOf(distinguished_name)
        }),
        "signed_certificate_timestamps": ListOf(SubRecord({
            "version": Unsigned32BitInteger(),
            "log_id": Binary(es_index=True),
            "timestamp": DateTime(),
            "extensions": Binary(),
            "signature": Binary()
        })),
        "ct_poison": Boolean()
    }),
    "unknown_extensions": ListOf(unknown_extension),
    "signature": SubRecord({
        "signature_algorithm": SubRecord({
            "name": String(),
            "oid": String(),
        }),
        "value": Binary(),
        # TODO FIXME: valid was commented out...? uncommented by jb 2017/12/11
        "valid": Boolean(),
        "self_signed": Boolean(),
    }),
    "fingerprint_md5": Binary(),
    "fingerprint_sha1": Binary(),
    "fingerprint_sha256": Binary(),
    "spki_subject_fingerprint": Binary(),
    "tbs_fingerprint": Binary(),
    # TODO FIXME: added by jb 2017/12/11
    "tbs_noct_fingerprint": Binary(),
    "validation_level": String(),
    "redacted": Boolean(),
    "names": ListOf(String()),
})

# ???
certificate_trust = SubRecord({
    "type": String(doc="root, intermediate, or leaf certificate"),
    "trusted_path": Boolean(doc="Does certificate chain up to browser root store"),
    "valid": Boolean(doc="is this certificate currently valid in this browser"),
    "was_valid": Boolean(doc="was this certificate ever valid in this browser")
})

lint = SubRecord({})

# ???
certificate = SubRecord({
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

hex_name_value = SubRecord({
    "hex": String(),
    "name": String(),
    # FIXME: Integer size?
    "value": Integer(),
})

cipher_suite = hex_name_value

signature_and_hash_type = SubRecord({
    "signature_algorithm": String(),
    "hash_algorithm": String(),
})

hex_name_value = SubRecord({
    "hex": String(),
    "name": String(),
    # FIXME: Integer size?
    "value": Integer(),
})

cipher_suite = hex_name_value

signature_and_hash_type = SubRecord({
    "signature_algorithm": String(),
    "hash_algorithm": String(),
})

# zcrypto/tls/tls_handshake.go: ServerHandshake
tls_handshake = SubRecord({
    "client_hello": SubRecord({
        "cipher_suites": ListOf(cipher_suite),
        "compression_methods": ListOf(hex_name_value),
        "extended_master_secret": Boolean(),
        "extended_random": Binary(),
        "heartbeat": Boolean(),
        "next_protocol_negotiation": Boolean(),
        "ocsp_stapling": Boolean(),
        "random": Binary(),
        "sct_enabled": Boolean(),
        "scts": Boolean(),
        "secure_renegotiation": Boolean(),
        "signature_and_hashes": ListOf(signature_and_hash_type),
        "supported_curves": ListOf(hex_name_value),
        "supported_point_formats": ListOf(hex_name_value),
        "ticket": Boolean(),
        "version": SubRecord({
            "name": String(),
            # FIXME: Integer size?
            "value": Integer()
        }),
    }),
    "server_hello": SubRecord({
        "version": SubRecord({
            "name": String(),
            # FIXME: Integer size?
            "value": Integer()
        }),
        "random": Binary(),
        "session_id": Binary(),
        "cipher_suite": cipher_suite,
        # FIXME: Integer size?
        "compression_method": Integer(),
        "ocsp_stapling": Boolean(),
        "ticket": Boolean(),
        "secure_renegotiation": Boolean(),
        "heartbeat": Boolean(),
        "extended_random": Binary(),
        "extended_master_secret": Boolean(),
        "scts": ListOf(SubRecord({
                "parsed": SubRecord({
                    "version": Unsigned16BitInteger(),
                    "log_id": IndexedBinary(),
                    "timestamp": Signed64BitInteger(),
                    "signature": Binary(),
                 }),
                "raw": Binary()
            })),
    }),
    "server_certificates": SubRecord({
        "certificate": certificate,
        "chain": ListOf(certificate),
        "validation": SubRecord({
            "matches_domain": Boolean(),
            "stores": SubRecord({
                "nss": server_certificate_valid,
                "microsoft": server_certificate_valid,
                "apple": server_certificate_valid,
                "java": server_certificate_valid,
                "android": server_certificate_valid,
            }),
            # TODO FIXME: ?? are the above applicable in zgrab2? I see the following    # TODO FIXME: Added by jb 2017/12/11
            # TODO FIXME: Added by jb 2017/12/11
            "browser_trusted": Boolean(),
            "browser_error": String()
        }),
    }),
    "server_key_exchange": SubRecord({
        "ecdh_params": SubRecord({
            "curve_id": SubRecord({
                "name": String(),
                # FIXME: Integer size (also -- not an OBJECT IDENTIFIER?)
                "id": Integer(),
            }),
            "server_public": SubRecord({
                "x": SubRecord({
                    "value": Binary(),
                    # FIXME: Integer size
                    "length": Integer(),
                }),
                "y": SubRecord({
                    "value": Binary(),
                    # FIXME: Integer size
                    "length": Integer(),
                }),
            }),
        }),
        "rsa_params": SubRecord({
            "exponent": Long(),
            "modulus": Binary(),
            # FIXME: Integer size
            "length": Integer(),
        }),
        "dh_params": SubRecord({
            "prime": SubRecord({
                "value": Binary(),
                # FIXME: Integer size
                "length": Integer(),
            }),
            "generator": SubRecord({
                "value": Binary(),
                # FIXME: Integer size
                "length": Integer(),
            }),
            "server_public": SubRecord({
                "value": Binary(),
                # FIXME: Integer size
                "length": Integer(),
            }),
        }),
        "signature": SubRecord({
            "raw": Binary(),
            "type": String(),
            "valid": Boolean(),
            "signature_and_hash_type": signature_and_hash_type,
            "tls_version": SubRecord({
                "name": String(),
                # FIXME: Integer size
                "value": Integer()
            }),
        }),
        "signature_error": String(),
    }),
    "server_finished": SubRecord({
        "verify_data": Binary()
    }),
    "session_ticket": SubRecord({
        "value": Binary(),
        # FIXME: Integer size
        "length": Integer(),
        "lifetime_hint": Long()
    }),
    "key_material": SubRecord({
        "pre_master_secret": SubRecord({
            "value": Binary(),
            # FIXME: Integer size
            "length": Integer()
        }),
        "master_secret": SubRecord({
            "value": Binary(),
            # FIXME: Integer size
            "length": Integer()
        }),
    }),
    "client_finished": SubRecord({
        "verify_data": Binary()
    }),
    "client_key_exchange": SubRecord({
        "dh_params": SubRecord({
            "prime": SubRecord({
                "value": Binary(),
                # FIXME: Integer size
                "length": Integer()
            }),
            "generator": SubRecord({
                "value": Binary(),
                # FIXME: Integer size
                "length": Integer()
            }),
            "client_public": SubRecord({
                # FIXME: Integer size
                "value": Binary(),
                "length": Integer()
            }),
            "client_private": SubRecord({
                # FIXME: Integer size
                "value": Binary(),
                "length": Integer()
            }),
        }),
        "ecdh_params": SubRecord({
            "curve_id": SubRecord({
                "name": String(),
                # FIXME: Integer size (and...not an OBJECT IDENTIFIER?)
                "id": Integer()
            }),
            "client_public": SubRecord({
                "x": SubRecord({
                    "value": Binary(),
                    # FIXME: Integer size
                    "length": Integer()
                }),
                "y": SubRecord({
                    "value": Binary(),
                    # FIXME: Integer size
                    "length": Integer()
                }),
            }),
            "client_private": SubRecord({
                "value": Binary(),
                # FIXME: Integer size
                "length": Integer()
            }),
        }),
        "rsa_params": SubRecord({
            # FIXME: Integer size
            "length": Integer(),
            "encrypted_pre_master_secret": Binary()
        }),
    }),
})

# zcrypto/tls/tls_heartbeat.go: Heartbleed
heartbleed_log = SubRecord({
    "heartbleed_enabled": Boolean(),
    "heartbleed_vulnerable": Boolean()
})

# zcrypto/x509/chain.go: type CertificateChain []*Certificate
certificate_chain = ListOf(parsed_certificate)

# zcrypto/tls/common.go: ConnectionState (note: no `json` tags)
tls_connection_state = SubRecord({
    "Version": Unsigned16BitInteger(),
    "HandshakeComplete": Boolean(),
    "DidResume": Boolean(),
    "CipherSuite": Unsigned16BitInteger(),
    "NegotiatedProtocol": String(),
    "NegotiatedProtocolIsMutual": Boolean(),
    "ServerName": String(),
    "PeerCertificate": parsed_certificate,
    "VerifiedChains": ListOf(certificate_chain),
})

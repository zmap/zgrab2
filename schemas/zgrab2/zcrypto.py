from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

# Schema for JSON output of those zcrypto exports used by zgrab2 / ztag.

# Mostly copied from zmap/zgrab/zgrab_schema.py, then merged in more
# recent changes from ztag, then converted sub_records into
# SubRecordTypes.


# TODO FIXME: zcrypto is not the right place for this. Was previously
# defined in ztag.
class CensysString(WhitespaceAnalyzedString):
    "default type for any strings in Censys"
    INCLUDE_RAW = True


# Helper function for types where unknown values have a special value.
# known are the known values, range generates the keys, and unknown is
# either a static value or a function mapping unknown keys to values.
def getUnknowns(known, range, unknown="unknown"):
    if not callable(unknown):
        staticValue = unknown
        unknown = lambda x: staticValue
    ret = {i: unknown(i) for i in range}
    ret.update(known)
    return ret


# x509/pkix/pkix.go: Name
DistinguishedName = SubRecordType({
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
UnknownExtension = SubRecordType({
    "id": OID(doc="The OBJECT IDENTIFIER identifying the extension.", required=True),
    "critical": Boolean(doc="Certificates should be rejected if they have critical extensions the validator does not recognize."),
    "value": IndexedBinary(doc="The raw value of the extnValue OCTET STREAM.", required=True),
}, doc="An unparsed X.509 extension value.")

# x509/pkix/pkix.go: type EDIPartyName struct
EDIPartyName = SubRecordType({
    "name_assigner": CensysString(doc="The nameAssigner (a DirectoryString)", required=False),
    "party_name": CensysString(doc="The partyName (a DirectoryString)", required=True),
}, doc="An X.400 generalName representing an Electronic Data Interchange (EDI) entity.")

# x509/pkix/json.go: auxOtherName / OtherName
OtherName = SubRecordType({
    "id": OID(doc="The OBJECT IDENTIFIER identifying the syntax of the otherName value."),
    "value": IndexedBinary(doc="The raw otherName value."),
})

# x509/extensions.go: GeneralNames/jsonGeneralNames
GeneralNames = SubRecordType({
    "dns_names": ListOf(FQDN()),
    "email_addresses": ListOf(EmailAddress()),
    "ip_addresses": ListOf(IPAddress()),
    "directory_names": ListOf(DistinguishedName()),
    "edi_party_names": ListOf(EDIPartyName()),
    "other_names": ListOf(OtherName()),
    "registered_ids": ListOf(OID()),
    "uniform_resource_identifiers": ListOf(URI()),
})

# json/dhe.go: cryptoParameter / auxCryptoParameter
CryptoParameter = SubRecordType({
    "value": IndexedBinary(required=True),
    "length": Unsigned16BitInteger(required=True),
})

# json/dhe.go: DHParams / auxDHParams:
DHParams = SubRecordType({
    "prime": CryptoParameter(required=True),
    "generator": CryptoParameter(required=True),
    "server_public": CryptoParameter(required=False),
    "server_private": CryptoParameter(required=False),
    "client_public": CryptoParameter(required=False),
    "client_private": CryptoParameter(required=False),
    "session_key": CryptoParameter(required=False),
})

# json/rsa.go: RSAPublicKey/auxRSAPublicKey (alias for crypto/rsa/PublicKey)
RSAPublicKey = SubRecordType({
    "exponent": Unsigned32BitInteger(required=True, doc="The RSA key's public exponent (e)."),
    "modulus": IndexedBinary(required=True, doc="The RSA key's modulus (n) in big-endian encoding."),
    "length": Unsigned16BitInteger(required=True, doc="Bit-length of modulus."),
}, doc="Container for the public portion (modulus and exponent) of an RSA asymmetric key.")

# json/rsa.go: RSAClientParams
RSAClientParams = SubRecordType({
    "length": Unsigned16BitInteger(required=False, doc="Bit-length of modulus."),
    "encrypted_pre_master_secret": Binary(required=False),
}, doc="TLS key exchange parameters for RSA keys.")

# json/names.go: ecIDToName
tls_curve_id_names = [
    "unknown", "sect163k1", "sect163r1", "sect163r2",
    "sect193r1", "sect193r2", "sect233k1", "sect233r1", "sect239k1",
    "sect283k1", "sect283r1", "sect409k1", "sect409r1", "sect571k1",
    "sect571r1", "secp160k1", "secp160r1", "secp160r2", "secp192k1",
    "secp192r1", "secp224k1", "secp224r1", "secp256k1", "secp256r1",
    "secp384r1", "secp521r1", "brainpoolp256r1", "brainpoolp384r1",
    "brainpoolp512r1"]

# json/ecdhe.go: TLSCurveID.MarshalJSON()
TLSCurveID = SubRecordType({
    "name": Enum(required=True, values=tls_curve_id_names, doc="The name of the curve algorithm (e.g. sect163kr1, secp192r1). Unrecognized curves are 'unknown'."),
    "id": Unsigned16BitInteger(required=True, doc="The numeric value of the curve identifier. See http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8"),
}, doc="An elliptic curve algorithm identifier.")

# json/ecdhe.go: ECPoint.MarshalJSON()
ECPoint = SubRecordType({
    "x": CryptoParameter(required=True),
    "y": CryptoParameter(required=True),
}, doc="An elliptic curve point.")

# json/ecdhe.go: ECDHPrivateParams
ECDHPrivateParams = SubRecordType({
    "value": IndexedBinary(required=False),
    "length": Unsigned16BitInteger(required=False),
}, doc="TLS key exchange parameters for ECDH keys.")

# json/ecdhe.go: ECDHParams
ECDHParams = SubRecordType({
    "curve_id": TLSCurveID(required=False),
    "server_public": ECPoint(required=False),
    "server_private": ECDHPrivateParams(required=False),
    "client_public": ECPoint(required=False),
    "client_private": ECDHPrivateParams(required=False),
}, doc="Parameters for ECDH key exchange.")

# x509/json.go (mapped from crypto.dsa)
DSAPublicKey = SubRecordType({
    "p": IndexedBinary(),
    "q": IndexedBinary(),
    "g": IndexedBinary(),
    "y": IndexedBinary(),
}, doc="The public portion of a DSA asymmetric key.")

# x509/json.go (mapped from crypto.ecdsa)
ECDSAPublicKey = SubRecordType({
    "pub": IndexedBinary(),
    "b": IndexedBinary(),
    "gx": IndexedBinary(),
    "gy": IndexedBinary(),
    "n": IndexedBinary(),
    "p": IndexedBinary(),
    "x": IndexedBinary(),
    "y": IndexedBinary(),
    "curve": Enum(values=["P-224", "P-256", "P-384", "P-521"]),
    "length": Unsigned16BitInteger(),
    # schema conflict in censys prod cert index
    # "asn1_oid":OID(),
}, doc="The public portion of an ECDSA asymmetric key.")

# x509/ct/types.go: SignedCertificateTimestamp.
# Note: ztag_sct has "log_name": String(), which is not present in the go.
SCTRecord = SubRecordType({
    "version": Unsigned32BitInteger(doc="Version of the protocol to which the SCT conforms.", required=True),
    "log_id": IndexedBinary(doc="The SHA-256 hash of the log's public key, calculated over the DER encoding of the key's SubjectPublicKeyInfo.", required=True),
    "timestamp": Timestamp(doc="Timestamp at which the SCT was issued.", required=False),
    "extensions": Binary(doc="For future extensions to the protocol.", required=False),
    "signature": Binary(doc="The log's signature for this SCT.", required=True),
})

# x509/json.go: auxGeneralSubtreeIP (modifies GeneralSubtreeIP from x509.go)
GeneralSubtreeIP = SubRecordType({
    "cidr": String(doc="The CIDR specifying the subtree.", required=False),
    "begin": IPAddress(doc="The first IP in the range.", required=False),
    "end": IPAddress(doc="The last IP in the range.", required=False),
    "mask": IPAddress(doc="The mask IP.", required=False),
}, exclude=["bigquery"], doc="A GeneralSubtree for GeneralName type of IP address.")  # XXX

# x509/extensions.go: type NoticeReference struct
NoticeReference = SubRecordType({
    # Note: these are both omitempty in the go code, but required in the ASN.1 spec.
    "organization": CensysString(doc="The organization that prepared the notice.", required=False),
    "notice_numbers": ListOf(Signed32BitInteger(), required=False, doc="The numeric identifier(s) of the notice."),
}, doc="A reference to a textual notice statement provided by an organization.")

# x509/extensions.go: type UserNoticeData struct
UserNoticeData = SubRecordType({
    "explicit_text": EnglishString(doc="Textual statement with a maximum size of 200 characters. Should be a UTF8String or IA5String.", required=False),
    # NOTE: We encode this as a slice, but it always has just one element (which makes sense, because the noticeRef is not a SEQUENCE in the ASN.1 spec).
    "notice_reference": ListOf(NoticeReference(), required=False, doc="Names an organization and identifies, by number, a particular textual statement prepared by that organization."),
}, doc="Notice to display to relying parties when certificate is used.")

# x509/extensions.go: type CertificatePoliciesJSON struct
# TODO: ztag has a "name": String() field?
CertificatePoliciesData = SubRecordType({
    "id": OID(doc="The OBJECT IDENTIFIER identifying the policy."),
    "cps": ListOf(URL(), doc="List of URIs to the policies"),
    "user_notice": ListOf(UserNoticeData(), doc="List of textual notices to display relying parties."),
})

# Generated by zcrypto/x509/extended_key_usage_schema.sh, with a manual tweak on unknown
ExtendedKeyUsage = SubRecordType({
    # NOTE: ztag has "value" with the comment "TODO: remove after reparse",
    # but there is no "value" in the JSON.
    "value": ListOf(Signed32BitInteger()),
    "any": Boolean(doc="Extension has extended key usage ANY (OBJECT IDENTIFIER = 2.5.29.37.0)"),
    "apple_code_signing": Boolean(doc="Extension has extended key usage APPLE_CODE_SIGNING (OBJECT IDENTIFIER = 1.2.840.113635.100.4.1)"),
    "apple_code_signing_development": Boolean(doc="Extension has extended key usage APPLE_CODE_SIGNING_DEVELOPMENT (OBJECT IDENTIFIER = 1.2.840.113635.100.4.1.1)"),
    "apple_code_signing_third_party": Boolean(doc="Extension has extended key usage APPLE_CODE_SIGNING_THIRD_PARTY (OBJECT IDENTIFIER = 1.2.840.113635.100.4.1.3)"),
    "apple_crypto_development_env": Boolean(doc="Extension has extended key usage APPLE_CRYPTO_DEVELOPMENT_ENV (OBJECT IDENTIFIER = 1.2.840.113635.100.4.5.4)"),
    "apple_crypto_env": Boolean(doc="Extension has extended key usage APPLE_CRYPTO_ENV (OBJECT IDENTIFIER = 1.2.840.113635.100.4.5)"),
    "apple_crypto_maintenance_env": Boolean(doc="Extension has extended key usage APPLE_CRYPTO_MAINTENANCE_ENV (OBJECT IDENTIFIER = 1.2.840.113635.100.4.5.2)"),
    "apple_crypto_production_env": Boolean(doc="Extension has extended key usage APPLE_CRYPTO_PRODUCTION_ENV (OBJECT IDENTIFIER = 1.2.840.113635.100.4.5.1)"),
    "apple_crypto_qos": Boolean(doc="Extension has extended key usage APPLE_CRYPTO_QOS (OBJECT IDENTIFIER = 1.2.840.113635.100.4.6)"),
    "apple_crypto_test_env": Boolean(doc="Extension has extended key usage APPLE_CRYPTO_TEST_ENV (OBJECT IDENTIFIER = 1.2.840.113635.100.4.5.3)"),
    "apple_crypto_tier0_qos": Boolean(doc="Extension has extended key usage APPLE_CRYPTO_TIER0_QOS (OBJECT IDENTIFIER = 1.2.840.113635.100.4.6.1)"),
    "apple_crypto_tier1_qos": Boolean(doc="Extension has extended key usage APPLE_CRYPTO_TIER1_QOS (OBJECT IDENTIFIER = 1.2.840.113635.100.4.6.2)"),
    "apple_crypto_tier2_qos": Boolean(doc="Extension has extended key usage APPLE_CRYPTO_TIER2_QOS (OBJECT IDENTIFIER = 1.2.840.113635.100.4.6.3)"),
    "apple_crypto_tier3_qos": Boolean(doc="Extension has extended key usage APPLE_CRYPTO_TIER3_QOS (OBJECT IDENTIFIER = 1.2.840.113635.100.4.6.4)"),
    "apple_ichat_encryption": Boolean(doc="Extension has extended key usage APPLE_ICHAT_ENCRYPTION (OBJECT IDENTIFIER = 1.2.840.113635.100.4.3)"),
    "apple_ichat_signing": Boolean(doc="Extension has extended key usage APPLE_ICHAT_SIGNING (OBJECT IDENTIFIER = 1.2.840.113635.100.4.2)"),
    "apple_resource_signing": Boolean(doc="Extension has extended key usage APPLE_RESOURCE_SIGNING (OBJECT IDENTIFIER = 1.2.840.113635.100.4.1.4)"),
    "apple_software_update_signing": Boolean(doc="Extension has extended key usage APPLE_SOFTWARE_UPDATE_SIGNING (OBJECT IDENTIFIER = 1.2.840.113635.100.4.1.2)"),
    "apple_system_identity": Boolean(doc="Extension has extended key usage APPLE_SYSTEM_IDENTITY (OBJECT IDENTIFIER = 1.2.840.113635.100.4.4)"),
    "client_auth": Boolean(doc="Extension has extended key usage CLIENT_AUTH (OBJECT IDENTIFIER = 1.3.6.1.5.5.7.3.2)"),
    "code_signing": Boolean(doc="Extension has extended key usage CODE_SIGNING (OBJECT IDENTIFIER = 1.3.6.1.5.5.7.3.3)"),
    "dvcs": Boolean(doc="Extension has extended key usage DVCS (OBJECT IDENTIFIER = 1.3.6.1.5.5.7.3.10)"),
    "eap_over_lan": Boolean(doc="Extension has extended key usage EAP_OVER_LAN (OBJECT IDENTIFIER = 1.3.6.1.5.5.7.3.14)"),
    "eap_over_ppp": Boolean(doc="Extension has extended key usage EAP_OVER_PPP (OBJECT IDENTIFIER = 1.3.6.1.5.5.7.3.13)"),
    "email_protection": Boolean(doc="Extension has extended key usage EMAIL_PROTECTION (OBJECT IDENTIFIER = 1.3.6.1.5.5.7.3.4)"),
    "ipsec_end_system": Boolean(doc="Extension has extended key usage IPSEC_END_SYSTEM (OBJECT IDENTIFIER = 1.3.6.1.5.5.7.3.5)"),
    "ipsec_tunnel": Boolean(doc="Extension has extended key usage IPSEC_TUNNEL (OBJECT IDENTIFIER = 1.3.6.1.5.5.7.3.6)"),
    "ipsec_user": Boolean(doc="Extension has extended key usage IPSEC_USER (OBJECT IDENTIFIER = 1.3.6.1.5.5.7.3.7)"),
    "microsoft_ca_exchange": Boolean(doc="Extension has extended key usage MICROSOFT_CA_EXCHANGE (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.21.5)"),
    "microsoft_cert_trust_list_signing": Boolean(doc="Extension has extended key usage MICROSOFT_CERT_TRUST_LIST_SIGNING (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.1)"),
    "microsoft_csp_signature": Boolean(doc="Extension has extended key usage MICROSOFT_CSP_SIGNATURE (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.16)"),
    "microsoft_document_signing": Boolean(doc="Extension has extended key usage MICROSOFT_DOCUMENT_SIGNING (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.12)"),
    "microsoft_drm": Boolean(doc="Extension has extended key usage MICROSOFT_DRM (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.5.1)"),
    "microsoft_drm_individualization": Boolean(doc="Extension has extended key usage MICROSOFT_DRM_INDIVIDUALIZATION (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.5.2)"),
    "microsoft_efs_recovery": Boolean(doc="Extension has extended key usage MICROSOFT_EFS_RECOVERY (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.4.1)"),
    "microsoft_embedded_nt_crypto": Boolean(doc="Extension has extended key usage MICROSOFT_EMBEDDED_NT_CRYPTO (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.8)"),
    "microsoft_encrypted_file_system": Boolean(doc="Extension has extended key usage MICROSOFT_ENCRYPTED_FILE_SYSTEM (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.4)"),
    "microsoft_enrollment_agent": Boolean(doc="Extension has extended key usage MICROSOFT_ENROLLMENT_AGENT (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.20.2.1)"),
    "microsoft_kernel_mode_code_signing": Boolean(doc="Extension has extended key usage MICROSOFT_KERNEL_MODE_CODE_SIGNING (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.61.1.1)"),
    "microsoft_key_recovery_21": Boolean(doc="Extension has extended key usage MICROSOFT_KEY_RECOVERY_21 (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.21.6)"),
    "microsoft_key_recovery_3": Boolean(doc="Extension has extended key usage MICROSOFT_KEY_RECOVERY_3 (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.11)"),
    "microsoft_license_server": Boolean(doc="Extension has extended key usage MICROSOFT_LICENSE_SERVER (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.5.4)"),
    "microsoft_licenses": Boolean(doc="Extension has extended key usage MICROSOFT_LICENSES (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.5.3)"),
    "microsoft_lifetime_signing": Boolean(doc="Extension has extended key usage MICROSOFT_LIFETIME_SIGNING (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.13)"),
    "microsoft_mobile_device_software": Boolean(doc="Extension has extended key usage MICROSOFT_MOBILE_DEVICE_SOFTWARE (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.14)"),
    "microsoft_nt5_crypto": Boolean(doc="Extension has extended key usage MICROSOFT_NT5_CRYPTO (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.6)"),
    "microsoft_oem_whql_crypto": Boolean(doc="Extension has extended key usage MICROSOFT_OEM_WHQL_CRYPTO (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.7)"),
    "microsoft_qualified_subordinate": Boolean(doc="Extension has extended key usage MICROSOFT_QUALIFIED_SUBORDINATE (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.10)"),
    "microsoft_root_list_signer": Boolean(doc="Extension has extended key usage MICROSOFT_ROOT_LIST_SIGNER (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.9)"),
    "microsoft_server_gated_crypto": Boolean(doc="Extension has extended key usage MICROSOFT_SERVER_GATED_CRYPTO (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.3)"),
    "microsoft_sgc_serialized": Boolean(doc="Extension has extended key usage MICROSOFT_SGC_SERIALIZED (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.3.1)"),
    "microsoft_smart_display": Boolean(doc="Extension has extended key usage MICROSOFT_SMART_DISPLAY (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.15)"),
    "microsoft_smartcard_logon": Boolean(doc="Extension has extended key usage MICROSOFT_SMARTCARD_LOGON (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.20.2.2)"),
    "microsoft_system_health": Boolean(doc="Extension has extended key usage MICROSOFT_SYSTEM_HEALTH (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.47.1.1)"),
    "microsoft_system_health_loophole": Boolean(doc="Extension has extended key usage MICROSOFT_SYSTEM_HEALTH_LOOPHOLE (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.47.1.3)"),
    "microsoft_timestamp_signing": Boolean(doc="Extension has extended key usage MICROSOFT_TIMESTAMP_SIGNING (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.2)"),
    "microsoft_whql_crypto": Boolean(doc="Extension has extended key usage MICROSOFT_WHQL_CRYPTO (OBJECT IDENTIFIER = 1.3.6.1.4.1.311.10.3.5)"),
    "netscape_server_gated_crypto": Boolean(doc="Extension has extended key usage NETSCAPE_SERVER_GATED_CRYPTO (OBJECT IDENTIFIER = 2.16.840.1.113730.4.1)"),
    "ocsp_signing": Boolean(doc="Extension has extended key usage OCSP_SIGNING (OBJECT IDENTIFIER = 1.3.6.1.5.5.7.3.9)"),
    "sbgp_cert_aa_service_auth": Boolean(doc="Extension has extended key usage SBGP_CERT_AA_SERVICE_AUTH (OBJECT IDENTIFIER = 1.3.6.1.5.5.7.3.11)"),
    "server_auth": Boolean(doc="Extension has extended key usage SERVER_AUTH (OBJECT IDENTIFIER = 1.3.6.1.5.5.7.3.1)"),
    "time_stamping": Boolean(doc="Extension has extended key usage TIME_STAMPING (OBJECT IDENTIFIER = 1.3.6.1.5.5.7.3.8)"),

    # NOTE: ztag has this commented out, but it is included in the JSON.
    "unknown": ListOf(OID(), doc="A list of the raw OBJECT IDENTIFIERs of any EKUs not recognized by the application."),
}, category="Extended Key Usage")

# x509/json.go jsonCertificate (mapped from x509.Certificate)
ParsedCertificate = SubRecordType({
    "subject": DistinguishedName(category="Subject", doc="The parsed subject name.", required=True),
    "subject_dn": CensysString(category="Basic Information", doc="A canonical string representation of the subject name.", examples=["C=US, ST=MI, L=Ann Arbor, OU=Scans, CN=localhost, emailAddress=root@localhost"]),
    "issuer": DistinguishedName(category="Issuer", doc="The parsed issuer name.", required=True),
    "issuer_dn": CensysString(category="Basic Information", doc="A canonical string representation of the issuer name.", examples=["C=US, ST=MI, L=Ann Arbor, OU=Certificate authority, CN=CA1, emailAddress=ca1@localhost"]),
    "version": Unsigned8BitInteger(category="Misc", doc="The x.509 certificate version number."),
    # NOTE: This is indeed encoded as a base 10 string via math.big.int.Text(10)
    "serial_number": String(doc="Serial number as an signed decimal integer. "\
                                "Stored as string to support >uint lengths. "\
                                "Negative values are allowed.",
                                category="Basic Information"),
    "validity": SubRecord({
        "start": Timestamp(doc="Timestamp of when certificate is first valid. Timezone is UTC."),
        "end": Timestamp(doc="Timestamp of when certificate expires. Timezone is UTC."),
        "length": Signed64BitInteger(),
    }, category="Validity Period"),
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
                               "(e.g., RSAPublicKey())."),
            "oid": OID(doc="OID of the public key on the certificate. "\
                           "This is helpful when an unknown type is present. "\
                           "This field is reserved and not currently populated.")
        }),
        "rsa_public_key": RSAPublicKey(),
        "dsa_public_key": DSAPublicKey(),
        "ecdsa_public_key": ECDSAPublicKey(),
    }, category="Public Key"),
    "extensions": SubRecord({
        "key_usage": SubRecord({
            "value": Unsigned16BitInteger(doc="Integer value of the bitmask in the extension"),
            "digital_signature": Boolean(),
            "certificate_sign": Boolean(),
            "crl_sign": Boolean(),
            "content_commitment": Boolean(),
            "key_encipherment": Boolean(),
            "data_encipherment": Boolean(),
            "key_agreement": Boolean(),
            "decipher_only": Boolean(),
            "encipher_only": Boolean(),
        }, category="Key Usage"),
        "basic_constraints": SubRecord({
            "is_ca": Boolean(),
            "max_path_len": Signed32BitInteger(),
        }, category="Basic Constaints"),
        "subject_alt_name": GeneralNames(category="Subject Alternate Names (SANs)", doc="The parsed Subject Alternative Name extension.", required=False),
        "issuer_alt_name": GeneralNames(doc="The parsed Issuer Alternative Name extension.", required=False),
        "crl_distribution_points": ListOf(URL(), category="CRL Distribution Points"),
        "authority_key_id": HexString(category="Authority Key ID (AKID)", doc="An identifier of the issuer's public key, encoded as a hexadecimal string."),
        "subject_key_id": HexString(category="Subject Key ID (SKID)", doc="An identifier of the subject's public key, encoded as a hexadecimal string."),
        "extended_key_usage": ExtendedKeyUsage(),
        "certificate_policies": ListOf(CertificatePoliciesData(), category="Certificate Policies"),
        "authority_info_access": SubRecord({
            "ocsp_urls": ListOf(URL()),
            "issuer_urls": ListOf(URL())
        }, category="Authority Info Access (AIA)"),
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
            "permitted_ip_addresses": ListOf(GeneralSubtreeIP()),
            "permitted_directory_names": ListOf(DistinguishedName()),
            "permitted_registered_ids": ListOf(OID()),
            "permitted_edi_party_names": ListOf(EDIPartyName()),
            "excluded_names": ListOf(FQDN()),
            "excluded_email_addresses": ListOf(CensysString()),
            "excluded_ip_addresses": ListOf(GeneralSubtreeIP()),
            "excluded_directory_names": ListOf(DistinguishedName()),
            "excluded_registered_ids": ListOf(String()),
            "excluded_edi_party_names": ListOf(EDIPartyName()),
        }, category="Name Constraints"),
        "signed_certificate_timestamps": ListOf(SCTRecord(), category="Embedded SCTS / CT Poison"),
        "ct_poison": Boolean(category="Embedded SCTS / CT Poison", doc="This is true if the certificate possesses the Certificate Transparency Precertificate Poison extension (1.3.6.1.4.1.11129.2.4.3).")
    }),
    "unknown_extensions": ListOf(UnknownExtension(), category="Unknown Extensions", doc="List of raw extensions that were not recognized by the application."),
    "signature": SubRecord({
        "signature_algorithm": SubRecord({
            "name": String(),
            "oid": OID(),
        }),
        "value": IndexedBinary(),
        "valid": Boolean(),
        "self_signed": Boolean(),
    }, category="Signature"),
    "fingerprint_md5": HexString(category="Fingerprint", doc="The MD5 digest over the DER encoding of the certificate, as a hexadecimal string."),
    "fingerprint_sha1": HexString(category="Fingerprint", doc="The SHA1 digest over the DER encoding of the certificate, as a hexadecimal string."),
    "fingerprint_sha256": HexString(category="Fingerprint", doc="The SHA2-256 digest over the DER encoding of the certificate, as a hexadecimal string."),
    "spki_subject_fingerprint": HexString(category="Fingerprint", doc="The SHA2-256 digest over the DER encoding of the certificate's SubjectPublicKeyInfo, as a hexadecimal string."),
    "tbs_fingerprint": HexString(category="Fingerprint", doc="The SHA2-256 digest over the DER encoding of the certificate's TBSCertificate, as a hexadecimal string."),
    "tbs_noct_fingerprint": HexString(category="Fingerprint", doc="The SHA2-256 digest over the DER encoding of the certificate's TBSCertificate, *with any CT extensions omitted*, as a hexadecimal string."),
    "names": ListOf(FQDN(), category="Basic Information", doc="A list of subject names in the certificate, including the Subject CommonName and SubjectAltName DNSNames, IPAddresses and URIs."),
    # NOTE: ztag has "__expanded_names": ListOf(String())
    # TODO: What Enum() values?
    # [ "unknown", "DV", "OV", "EV" ]
    "validation_level": Enum(values=["unknown", "DV", "OV", "EV"], category="Misc"),
    "redacted": Boolean(category="Misc", doc="This is set if any of the certificate's names start with a '?'."),
})

# x509/validation.go: Validation
CertValidationResult = SubRecordType({
    "browser_trusted": Boolean(doc="If true, the certificate was valid and chained to a browser root CA."),
    "browser_error": String(doc="If browser_trusted is false, this may give more information about the failure."),
    "matches_domain": Boolean(doc="If true, validation was provided with a hostname that matched the one of the certificate's names.")
})

# tls/tls_handshake.go: SimpleCertificate
SimpleCertificate = SubRecordType({
    "raw": Binary(doc="The DER encoding of the certificate."),
    "parsed": ParsedCertificate(doc="The parsed certificate."),
    "validation": CertValidationResult(doc="If present, the results of checking the certificate's validity."),
})

###### END ztag/zgrab ######

# TODO: Should any of these be IndexedBinary() / CensysString()?

GoInt = Signed32BitInteger

# tls/tls_handshake.go: CipherSuite (uint16)
CipherSuite = SubRecordType({
    "hex": String(doc="The hexadecimal encoding of the numeric cipher suite identifier, prefixed with 0x.", examples=["0x0", "0x10", "0x100", "0xCAFE"]),
    # TODO: Enum()? There are a ton of these; from cipherSuiteNames in tls_names.go.
    "name": String(doc="The const name of the cipher suite. See e.g. https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml.", examples=["unknown", "TLS_RSA_WITH_RC4_128_MD5", "TLS_KRB5_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"]),
    "value": Unsigned16BitInteger(doc="The numerical value of the cipher suite identifier."),
})

# tls/tls_handshake.go: CompressionMethod (uint8)
CompressionMethod = SubRecordType({
    "hex": String(doc="The hexadecimal encoding of the numeric compression method identifier, prefixed with 0x.", examples=["0x0", "0x1", "0x40", "0xFF"]),
    "name": Enum(doc="The const name of the compression method; see https://www.iana.org/assignments/comp-meth-ids/comp-meth-ids.xhtml#comp-meth-ids-2.", values=["NULL", "DEFLATE", "LZS", "unknown"]),
    "value": Unsigned8BitInteger(doc="The numerical value of the compression method identifier."),
})

signature_algorithm_names = getUnknowns({
    # 0: "anonymous",
    1: "rsa",
    2: "dsa",
    3: "ecdsa",
    # 255: "",
}, range(0, 256), lambda x: "unknown." + str(x))

hash_algorithm_names = getUnknowns({
    # 0: "none",
    1: "md5",
    2: "sha1",
    3: "sha224",
    4: "sha256",
    5: "sha384",
    6: "sha512",
    # 255: "",
}, range(0, 256), lambda x: "unknown." + str(x))

# tls/tls_ka.go: auxSignatureAndHash (SignatureAndHash)
SignatureAndHash = SubRecordType({
    # Defined in tls_names.go (signatureNames).
    "signature_algorithm": Enum(values=signature_algorithm_names.values(), doc="The name of the signature algorithm, as defined in RFC5246 section 7.4.1.4.1. Unrecognized values are of the form 'unknown.255'."),
    "hash_algorithm": Enum(values=hash_algorithm_names.values(), doc="The name of the hash algorithm, as defined in RFC5246 section 7.4.1.4.1. Unrecognized values are of the form 'unknown.255'."),
}, doc="mirrors the TLS 1.2, SignatureAndHashAlgorithm struct. See RFC 5246, section A.4.1.")

# tls/tls_handshake.go: type TLSVersion uint16 (marshal -> name/value)
TLSVersion = SubRecordType({
    # tls_names.go: TLSVersion.String()
    "name": Enum(values=["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "unknown"], doc="A human-readable version of the TLS version."),
    # Note -- this is an "int" (at least 32 bits) in the go struct, but the value itself is 16 bits.
    "value": Unsigned16BitInteger(doc="The TLS version identifier."),
})

# tls/tls_handshake.go: type SessionTicket
SessionTicket = SubRecordType({
    "value": Binary(doc="The session ticket (an opaque binary blob)."),
    # Note -- this is an "int" in the go struct, but the length of the ticket is defined to be in [0, 2^16-1] in RFC 5077 section 3.3.
    "length": Unsigned16BitInteger(doc="The length of the session ticket, in bytes."),
    "lifetime_hint": Unsigned32BitInteger(doc="A hint from the server as to how long the ticket should be stored (in seconds relative to when the ticket is received)."),
})

# curveNames from tls_names.go, via https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
curve_id_names = {
    1: "sect163k1",
    2: "sect163r1",
    3: "sect163r2",
    4: "sect193r1",
    5: "sect193r2",
    6: "sect233k1",
    7: "sect233r1",
    8: "sect239k1",
    9: "sect283k1",
    10: "sect283r1",
    11: "sect409k1",
    12: "sect409r1",
    13: "sect571k1",
    14: "sect571r1",
    15: "secp160k1",
    16: "secp160r1",
    17: "secp160r2",
    18: "secp192k1",
    19: "secp192r1",
    20: "secp224k1",
    21: "secp224r1",
    22: "secp256k1",
    23: "secp256r1",
    24: "secp384r1",
    25: "secp521r1",
    26: "brainpoolP256r1",
    27: "brainpoolP384r1",
    28: "brainpoolP512r1",
    29: "ecdh_x25519",
    30: "ecdh_x448",
    256: "ffdhe2048",
    257: "ffdhe3072",
    258: "ffdhe4096",
    259: "ffdhe6144",
    260: "ffdhe8192",
    65281: "arbitrary_explicit_prime_curves",
    65282: "arbitrary_explicit_char2_curves",
}

# tls/common.go: CurveID
# Not to be confused with TLSCurveID from json/ecdhe.go.
CurveID = SubRecordType({
    "hex": String(doc="The hexadecimal encoding of the numeric curve identifier, left-padded with zeroes, prefixed with 0x.", examples=["0x0001", "0x0026", "0xFF01"]),
    "name": Enum(values=curve_id_names.values(), doc="The enum name of the identified curve; see http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8."),
    "value": Unsigned16BitInteger(doc="The numerical value of the curve identifier."),
})

# tls/common.go: PointFormat
PointFormat = SubRecordType({
    "hex": String(doc="The hexadecimal encoding of the numeric point format identifier, left-padded with zeroes, prefixed with 0x.", examples=["0x00"]),
    "name": Enum(values=["unknown", "uncompressed", "ansiX962_compressed_prime", "ansiX962_compressed_char2"], doc="The enum name of the identified point format; see https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9."),
    "value": Unsigned8BitInteger(doc="The numerical value of the point format identifier."),
})

# tls/tls_handshake.go: ClientHello
ClientHello = SubRecordType({
    "version": TLSVersion(doc="The version of the TLS protocol by which the client wishes to communicate during this session."),
    "random": Binary(doc="A client-generated random structure."),
    "session_id": Binary(doc="The ID of a session the client wishes to use for this connection. This field is empty if no session_id is available, or if the client wishes to generate new security parameters."),
    "cipher_suites": ListOf(CipherSuite(), doc="A list of the cryptographic options supported by the client, ordered by client preference."),
    "compression_methods": ListOf(CompressionMethod(), doc="A list of the compression methods supported by the client, sorted by client preference."),
    "ocsp_stapling": Boolean(doc="This is true if the OCSP Stapling extension is set (see https://www.ietf.org/rfc/rfc6961.txt for details)."),
    "ticket": Boolean(doc="This is true if the client has the Session Ticket extension (see https://tools.ietf.org/html/rfc5077)."),
    "secure_renegotiation": Boolean(doc="This is true if the client has the Secure Renegotiation extension (see https://tools.ietf.org/html/rfc5746)."),
    "heartbeat": Boolean(doc="This is true if the client has the Heartbeat Supported extension (see https://tools.ietf.org/html/rfc6520)."),
    "extended_random": Binary(doc="The value of the Extended Random extension, if present (see https://tools.ietf.org/html/draft-rescorla-tls-extended-random-02)."),
    "extended_master_secret": Boolean(doc="This is true if the client has the Extended Master Secret extension (see https://tools.ietf.org/html/rfc7627)."),
    "next_protocol_negotiation": Boolean(doc="This is true if the client has the Next Protocol Negotiation extension (see https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html)."),
    "server_name": String(doc="This contains the server name from the Server Name Identification (SNI) extension, if present (see https://tools.ietf.org/html/rfc6066#section-3)."),
    "scts": Boolean(doc="This is true if the client has the Signed Certificate Timestamp extension, if present (see https://tools.ietf.org/html/rfc6962#section-3.3.1)"),
    "supported_curves": ListOf(CurveID(), doc="The list of supported curves in the Supported Elliptic Curves extension, if present (see https://tools.ietf.org/html/rfc4492#section-5.1.1)"),
    "supported_point_formats": ListOf(PointFormat(), doc="The list of supported elliptic curve point formats in the Supported Point Formats extension, if present (see https://tools.ietf.org/html/rfc4492#section-5.1.2)."),
    "session_ticket": SessionTicket(doc="The session ticket in the Session Ticket extension, if present (see https://tools.ietf.org/html/rfc5077)."),
    "signature_and_hashes": ListOf(SignatureAndHash(), doc="The value of the signature_algorithms extension, if present (see https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1)."),
    "sct_enabled": Boolean(doc="This is true if the client has the Signed Certificate Timestamp extension (see https://tools.ietf.org/html/rfc6962#section-3.3.1)."),
    "alpn_protocols": ListOf(String(), "This contains the list of protocols in the Application-Layer Protocol Negotiation extension, if present (see https://tools.ietf.org/html/rfc7301)."),
    "unknown_extensions": ListOf(Binary(), doc="A list of any unrecognized extensions in raw form."),
}, doc="The Client Hello message (see https://tools.ietf.org/html/rfc5246#section-7.4.1.2).")

# tls/tls_handshake.go: ServerHello
ServerHello = SubRecordType({
    "version": TLSVersion(doc="This field will contain the lower of that suggested by the client in the client hello and the highest supported by the server."),
    "random": Binary(doc="This structure is generated by the server and MUST be independently generated from the ClientHello.random."),
    "session_id": Binary(doc="This is the identity of the session corresponding to this connection."),
    "cipher_suite": CipherSuite(doc="The single cipher suite selected by the server from the list in ClientHello.cipher_suites."),
    # TODO FIXME: This is a uint8 in the go code, but it should probably be a CompressionMethod...?
    "compression_method": Unsigned8BitInteger(doc="The single compression algorithm selected by the server from the list in ClientHello.compression_methods."),
    "ocsp_stapling": Boolean(doc="This is true if the OCSP Stapling extension is set (see https://www.ietf.org/rfc/rfc6961.txt for details)."),
    "ticket": Boolean(doc="This is true if the server has the Session Ticket extension (see https://tools.ietf.org/html/rfc5077)."),
    "secure_renegotiation": Boolean(doc="This is true if the client has the Secure Renegotiation extension (see https://tools.ietf.org/html/rfc5746)."),
    "heartbeat": Boolean(doc="This is true if the client has the Heartbeat Supported extension (see https://tools.ietf.org/html/rfc6520)."),
    "extended_random": Binary(doc="The value of the Extended Random extension, if present (see https://tools.ietf.org/html/draft-rescorla-tls-extended-random-02)."),
    "extended_master_secret": Boolean(doc="This is true if the server has the Extended Master Secret extension (see https://tools.ietf.org/html/rfc7627)."),
    "scts": ListOf(SubRecord({
        "parsed": SCTRecord(),
        "raw": Binary(),
    }), doc="The values in the SignedCertificateTimestampList of the Signed Certificate Timestamp, if present."),
}, doc="The Server Hello message (see https://tools.ietf.org/html/rfc5246#section-7.4.1.3).")

# tls/tls_handshake.go: ServerKeyExchange
ServerKeyExchange = SubRecordType({
    "ecdh_params": ECDHParams(),
    "rsa_params": RSAClientParams(),
    "dh_params": DHParams(),
    "digest": Binary(doc="The digest that is signed."),
    "signature": SubRecord({
        "raw": Binary(),
        "type": String(),
        "valid": Boolean(),
        "signature_and_hash_type": SignatureAndHash(),
        "tls_version": TLSVersion(),
    }),
    "signature_error": String(doc="The signature error, if one occurred."),
}, doc="The key data sent by the server in the TLS key exchange message.")

# tls/tls_handshake.go: ClientKeyExchange
ClientKeyExchange = SubRecordType({
    "dh_params": DHParams(),
    "ecdh_params": ECDHParams(),
    "rsa_params": RSAClientParams(),
}, doc="The key data sent by the client in the TLS key exchange message.")

# tls/tls_handshake.go: MasterSecret
MasterSecret = SubRecordType({
    "value": Binary(),
    "length": GoInt(),
})

# tls/tls_handshake.go: PreMasterSecret
PreMasterSecret = SubRecordType({
    "value": Binary(),
    "length": GoInt(),
})

# tls/tls_handshake.go: KeyMaterial
KeyMaterial = SubRecordType({
    "pre_master_secret": PreMasterSecret(),
    "master_secret": MasterSecret(),
}, doc="The cryptographic values negotiated by the client and server.")

# tls/tls_handshake.go: ServerHandshake
TLSHandshake = SubRecordType({
    "client_hello": ClientHello(),
    "server_hello": ServerHello(),
    "server_certificates": SubRecord({
        "certificate": SimpleCertificate(),
        "chain": ListOf(SimpleCertificate()),
        # x509/validation.go: type Validation struct
        "validation": SubRecord({
            "matches_domain": Boolean(),
            # "stores" does not seem to be present here?
            "browser_trusted": Boolean(),
            "browser_error": String()
        }),
    }, doc="The certificates returned by the server, and their validation information."),
    "server_key_exchange": ServerKeyExchange(),
    "server_finished": SubRecord({
        "verify_data": Binary(doc="Data proving that the server has the correct parameters and secret data.")
    }, doc="The server's Finished message."),
    "session_ticket": SessionTicket(),
    "key_material": KeyMaterial(),
    "client_finished": SubRecord({
        "verify_data": Binary()
    }),
    "client_key_exchange": ClientKeyExchange(),
})

# zcrypto/tls/tls_heartbeat.go: Heartbleed
HeartbleedLog = SubRecordType({
    "heartbeat_enabled": Boolean(doc="Indicates whether the server has the heatbeat extension enabled."),
    "heartbleed_vulnerable": Boolean(doc="Indicates whether the server is vulnerable to the Heartbleed attack.")
})

# zcrypto/x509/chain.go: type CertificateChain []*Certificate
certificate_chain = ListOf(ParsedCertificate())

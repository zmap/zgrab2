# zschema sub-schema for zgrab2's ldap module
# Registers zgrab2-ldap globally, and ldap with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

ldap_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "supported_ldap_version": ListOf(
                    String(),
                    doc="The LDAP versions supported by the server.",
                ),
                "supported_extension": ListOf(
                    String(),
                    doc="OIDs of LDAP extensions supported by the server.",
                ),
                "supported_control": ListOf(
                    String(),
                    doc="OIDs of LDAP controls supported by the server.",
                ),
                "supported_capabilities": ListOf(
                    String(),
                    doc="OIDs of LDAP capabilities supported by the server.",
                ),
                "supported_sasl_mechanisms": ListOf(
                    String(),
                    doc="SASL mechanisms supported by the server.",
                ),
                "supported_ldap_policies": ListOf(
                    String(),
                    doc="LDAP policies supported by the server.",
                ),
                "naming_contexts": ListOf(
                    String(),
                    doc="The naming contexts (base DNs) held by the server.",
                ),
                "subschema_subentry": String(
                    doc="The DN of the subschema subentry.",
                ),
                "server_name": String(
                    doc="The DN of the server's directory entry.",
                ),
                "schema_naming_context": String(
                    doc="The DN of the schema naming context.",
                ),
                "root_domain_naming_context": String(
                    doc="The DN of the root domain naming context.",
                ),
                "ldap_service_name": String(
                    doc="The LDAP service name (Kerberos principal).",
                ),
                "is_synchronized": String(
                    doc="Whether the directory is synchronized.",
                ),
                "is_global_catalog_ready": String(
                    doc="Whether the server is a Global Catalog.",
                ),
                "highest_committed_usn": String(
                    doc="The highest committed update sequence number.",
                ),
                "forest_functionality": String(
                    doc="The forest functional level.",
                ),
                "ds_service_name": String(
                    doc="The DN of the directory service agent.",
                ),
                "domain_functionality": String(
                    doc="The domain functional level.",
                ),
                "domain_controller_functionality": String(
                    doc="The domain controller functional level.",
                ),
                "dns_host_name": String(
                    doc="The DNS hostname of the server.",
                ),
                "default_naming_context": String(
                    doc="The default naming context (base DN).",
                ),
                "current_time": String(
                    doc="The current time on the server.",
                ),
                "configuration_naming_context": String(
                    doc="The DN of the configuration naming context.",
                ),
                "other_attributes": SubRecord(
                    {},
                    doc="Any Root DSE attributes not mapped to a typed field.",
                    required=False,
                ),
                "starttls_response": Signed64BitInteger(
                    doc="The LDAP result code from the STARTTLS extended operation.",
                    required=False,
                ),
                "tls": zgrab2.tls_log,
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-ldap", ldap_scan_response)

zgrab2.register_scan_response_type("ldap", ldap_scan_response)

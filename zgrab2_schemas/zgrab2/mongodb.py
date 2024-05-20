# zschema sub-schema for zgrab2's mongodb module
# Registers zgrab2-mongodb globally, and mongodb with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

import zcrypto_schemas.zcrypto as zcrypto
from . import zgrab2

mongodb_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "build_info": SubRecord(
                    {
                        "version": String(doc="Version of mongodb server"),
                        "git_version": String(doc="Git Version of mongodb server"),
                        "max_wire_version": Signed32BitInteger(),
                        "sys_info": String(),
                        "allocator": String(),
                        "bits": Unsigned32BitInteger(),
                        "max_bson_object_size": Unsigned32BitInteger(),
                        "javascript_engine": String(),
                        "storage_engines": ListOf(String()),
                        "build_environment": SubRecord(
                            {
                                "dist_mod": String(),
                                "dist_arch": String(),
                                "cc": String(),
                                "cc_flags": String(),
                                "cxx": String(),
                                "cxx_flags": String(),
                                "link_flags": String(),
                                "target_arch": String(),
                                "target_os": String(),
                            }
                        ),
                    }
                ),
                "database_info": SubRecord(
                    {
                        "databases": ListOf(
                            SubRecord(
                                {
                                    "name": String(),
                                    "size_on_disk": Signed32BitInteger(),
                                    "empty": Boolean(),
                                }
                            )
                        ),
                        "total_size": Signed32BitInteger(),
                    }
                ),
                "is_master": SubRecord(
                    {
                        "is_master": Boolean(),
                        "max_wire_version": Signed32BitInteger(),
                        "min_wire_version": Signed32BitInteger(),
                        "max_bson_object_size": Signed32BitInteger(),
                        "max_write_batch_size": Signed32BitInteger(),
                        "logical_session_timeout_minutes": Signed32BitInteger(),
                        "max_message_size_bytes": Signed32BitInteger(),
                        "read_only": Boolean(),
                    }
                ),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-mongodb", mongodb_scan_response)

zgrab2.register_scan_response_type("mongodb", mongodb_scan_response)

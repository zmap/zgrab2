# zschema sub-schema for zgrab2's drda module
# Registers zgrab2-drda globally, and drda with the main zgrab2 schema.
from zschema.leaves import *
from zschema.compounds import *
import zschema.registry

from . import zgrab2

drda_scan_response = SubRecord(
    {
        "result": SubRecord(
            {
                "server_class": String(
                    doc="The DRDA SRVCLSNM attribute, describing the server platform, e.g. 'QDB2/NT64'."
                ),
                "instance_name": String(
                    doc="The DRDA SRVNAM attribute, e.g. the DB2 instance name 'DB2'."
                ),
                "release_level": String(
                    doc="The raw DRDA SRVRLSLV product release level attribute, e.g. 'SQL11013'."
                ),
                "version": String(
                    doc="The human-readable version derived from release_level, e.g. '11.01.3'."
                ),
                "external_name": String(doc="The DRDA EXTNAM external name attribute."),
                "product_id": String(
                    doc="The DRDA PRDID product ID attribute, when present."
                ),
                "raw": String(
                    doc="The hex-encoded EXCSATRD response, included when --verbose is set."
                ),
            }
        )
    },
    extends=zgrab2.base_scan_response,
)

zschema.registry.register_schema("zgrab2-drda", drda_scan_response)

zgrab2.register_scan_response_type("drda", drda_scan_response)

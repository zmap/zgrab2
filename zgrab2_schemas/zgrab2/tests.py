import logging
import sys
import collections
import itertools
import json
import os
import pprint
import os.path
from imp import load_source
import unittest
from . import zgrab2

logging.basicConfig(stream=sys.stderr)

logger = logging.getLogger("zgrab2-schema-tests")

import zschema
import zschema.registry


def get_data_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")


def get_data_file(file):
    return os.path.join(get_data_dir(), file)


def get_data_files():
    dir = get_data_dir()
    files = os.listdir(dir)
    return [file for file in files if file.endswith(".json")]


def get_schemas():
    return [item for item in zgrab2.scan_response_types]


class SchemaTests(unittest.TestCase):

    def test_schema(self):
        for schema in get_schemas():
            logger.error("checking schema %s", schema)
            recname = "zgrab2-" + schema
            record = zschema.registry.get_schema(recname)
            record.to_bigquery(recname)
            record.to_es()
            record.to_flat("zgrab", schema)

    def test_docs(self):
        for schema in get_schemas():
            logger.error("checking docs %s", schema)
            recname = "zgrab2-" + schema
            record = zschema.registry.get_schema(recname)
            record.docs_es(recname)
            record.docs_bq(recname)

    def test_validate(self):
        record = zschema.registry.get_schema("zgrab2")
        for file in get_data_files():
            with open(get_data_file(file)) as fp:
                record.validate(json.load(fp))

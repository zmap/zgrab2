ZGrab 2.0 schemas for zschema
=============================

## Validating

[integration_tests](../integration_tests) automatically validates
output from the integration tests; to manually validate a zgrab2 result,
you can follow these steps:

0. Get [zschema](https://github.com/zmap/zschema) (e.g. `git clone https://github.com/zmap/zschema`)
1. Run the zschema validator:
   1. Run the zschema module's main function
   2. Pass it the `validate` command
   3. Give the path to the zgrab2 schema [`zgrab2/__init__.py:zgrab2`](zgrab2/__init__.py)
   4. Pass in the zgrab2 JSON file to validate
     * ```
       echo 127.0.0.1 | ./cmd/zgrab2/zgrab2 mysql > output.json
       PYTHONPATH=/path/to/zschema python2 -m zschema validate zgrab2 output.json --path . --module zgrab2_schemas.zgrab2
       ```

## Adding new module schemas

There are two steps to adding a new zgrab2 module schema:

1. Add the module
   a. Register the response type with the zgrab2 schema
2. Register the module in `__init__.py`

### Add the module

Create your python file; if your protocol identifier (the default name
in the result table) is *my_protocol*, name the file `my_protocol.py`
(this allows a static schema validation from `protocol_name` to `protocol_schema`;
unfortunately, this means that multiple scans on a single host, or scans
using custom identifiers, will not validate).

Your module should include a `SubRecord` that extends from `zgrab2.base_scan_response`,
specifically, overridding the `result` field. See [zgrab2/mysql.py](zgrab2/mysql.py)
for an example.

### Register the module

In [`zgrab2/__init__.py`](zgrab2/__init__.py), add an import for your
module (e.g. `import my_protocol`). This will ensure that the module code
is executed and that the response type is registered with the zgrab2 module.

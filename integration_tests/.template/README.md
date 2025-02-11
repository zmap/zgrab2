Template integration test scripts

Specify your module's service in the `docker-compose.yml` file.

 - All scripts start with the default `CONTAINER_NAME` variable matching
   the standard format (`zgrab_<module name>`).

 - `test.sh` runs the container using the `docker-runner.sh` script and
   dumps the output in `zgrab-output/<module name>/<module_name>.json`.
   Afterwards it dumps the container logs to stdout. This can be used
   as-is, it only provides a single test case with no arguments.

 - `schema.py` registers the `scan_response_type` and provides a 
   skeleton that can be filled out. **This must be modified for all new
   modules**.

These files have `#{MODULE_NAME}` statically replaced with the module's
name (the argument passed to `new.sh`).

 - `*.sh` get copied to `integration_tests/<module name>/*.sh`

 - `schema.py` gets copied to `schemas/<module name>.py`

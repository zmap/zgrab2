ZGrab 2.0
=========

ZGrab is a fast, modular application-layer network scanner designed for completing large Internet-wide surveys. ZGrab is built to work with ZMap (ZMap identifies L4 responsive hosts, ZGrab performs in-depth, follow-up L7 handshakes). Unlike many other network scanners, ZGrab outputs detailed transcripts of network handshakes (e.g., all messages exchanged in a TLS handshake) for offline analysis.  

ZGrab 2.0 contains a new, modular ZGrab framework, which fully supersedes https://github.com/zmap/zgrab.

## Installation

### With Docker

You can run ZGrab 2.0 with our official Docker image. For example, to scan a single website using the HTTP module, you can use:

```shell
echo 'example.com' | docker run --rm -i ghcr.io/zmap/zgrab2 http
```

For more complex scanning scenarios, such as using multiple modules or custom configurations, you can create a configuration file and pass it to the container:

```shell
docker run --rm -i -v /path/to/your/config.ini:/config.ini ghcr.io/zmap/zgrab2 multiple -c /config.ini
```

Replace `/path/to/your/config.ini` with the path to your configuration file on the host machine. See [Multiple Module Usage](#multiple-module-usage) for more details on configurations.

### Building from Source

For Go 1.17 and later you must build from source:

```shell
git clone https://github.com/zmap/zgrab2.git
cd zgrab2
make
./zgrab2
```


For Go 1.16 and below you can install via go get:

You will need to have a valid `$GOPATH` set up, for more information about `$GOPATH`, see https://golang.org/doc/code.html.

Once you have a working `$GOPATH`, run:

```shell
go get github.com/zmap/zgrab2
```

This will install zgrab under `$GOPATH/src/github.com/zmap/zgrab2`

```shell
cd $GOPATH/src/github.com/zmap/zgrab2
make
```

## Single Module Usage 

ZGrab2 supports modules. For example, to run the ssh module use

```shell
./zgrab2 ssh
```

To retrieve detailed command-line usage and options for a specific module, append `-h` to the command:

```bash
./zgrab2 [module] -h
```

This will display the module-specific options, as well as the application-wide options, including usage examples, available flags, and descriptions for each option. 

Module specific options must be included after the module. Application specific options can be specified at any time.

## Input Format

Targets are specified with input files or from `stdin`, in CSV format.  Each input line has three fields:

```text
IP, DOMAIN, TAG
```

Each line must specify `IP`, `DOMAIN`, or both.  If only `DOMAIN` is provided, scanners perform a DNS hostname lookup to determine the IP address.  If both `IP` and `DOMAIN` are provided, scanners connect to `IP` but use `DOMAIN` in protocol-specific contexts, such as the HTTP HOST header and TLS SNI extension.

If the `IP` field contains a CIDR block, the framework will expand it to one target for each IP address in the block.

The `TAG` field is optional and used with the `--trigger` scanner argument.

Unused fields can be blank, and trailing unused fields can be omitted entirely.  For backwards compatibility, the parser allows lines with only one field to contain `DOMAIN`.

These are examples of valid input lines:

```text
10.0.0.1
domain.com
10.0.0.1, domain.com
10.0.0.1, domain.com, tag
10.0.0.1, , tag
, domain.com, tag
192.168.0.0/24, , tag

```

## Multiple Module Usage

To run a scan with multiple modules, a `.ini` file must be used with the `multiple` module. Below is an example `.ini` file with the corresponding zgrab2 command. 

***multiple.ini***
```ini
[Application Options]
output-file="output.txt"
input-file="input.txt"
[http]
name="http80"
port=80
endpoint="/"
[http]
name="http8080"
port=8080
endpoint="/"
[ssh]
port=22
```
```shell
./zgrab2 multiple -c multiple.ini
```
`Application Options` must be the initial section name. Other section names should correspond exactly to the relevant zgrab2 module name. The default name for each module is the command name. If the same module is to be used multiple times then `name` must be specified and unique. 

Multiple module support is particularly powerful when combined with input tags and the `--trigger` scanner argument. For example, this input contains targets with two different tags:

```text
141.212.113.199, , tagA
216.239.38.21, censys.io, tagB
```

Invoking zgrab2 with the following `multiple` configuration will perform an SSH grab on the first target above and an HTTP grab on the second target:

```ini
[ssh]
trigger="tagA"
name="ssh22"
port=22

[http]
trigger="tagB"
name="http80"
port=80
```

## Adding New Protocols 

Add module to modules/ that satisfies the following interfaces: `Scanner`, `ScanModule`, `ScanFlags`.

The flags struct must embed zgrab2.BaseFlags. In the modules `init()` function the following must be included. 

```go
func init() {
    var newModule NewModule
    _, err := zgrab2.AddCommand("module", "short description", "long description of module", portNumber, &newModule)
    if err != nil {
        log.Fatal(err)
    }
}
```

### Output schema

To add a schema for the new module, add a module under schemas, and update [`zgrab2_schemas/zgrab2/__init__.py`](zgrab2_schemas/zgrab2/__init__.py) to ensure that it is loaded.

See [zgrab2_schemas/README.md](zgrab2_schemas/README.md) for details.

### Integration tests
To add integration tests for the new module, run `integration_tests/new.sh [your_new_protocol_name]`.
This will add stub shell scripts in `integration_tests/your_new_protocol_name`; update these as needed.
See [integration_tests/mysql/*](integration_tests/mysql) for an example.
The only hard requirement is that the `test.sh` script drops its output in `$ZGRAB_OUTPUT/[your-module]/*.json`, so that it can be validated against the schema.

#### How to Run Integration Tests

To run integration tests, you must have [Docker](https://www.docker.com/) and **Python 2** on host installed. Then, you can follow the following steps to run integration tests:

```shell
go get github.com/jmespath/jp && go build github.com/jmespath/jp
# or, sudo wget https://github.com/jmespath/jp/releases/download/0.2.1/jp-linux-amd64 -O /usr/local/bin/jp && sudo chmod +x /usr/local/bin/jp
pip2 install --user zschema
pip2 install --user -r requirements.txt
make integration-test
```

Running the integration tests will generate quite a bit of debug output. To ensure that tests completed successfully, you can check for a successful exit code after the tests complete:

```shell
echo $?
0
```

Refer to our [Github Actions workflow](.github/workflows/integration-test.yml) for an example of how to prepare environment for integration tests.

## License
ZGrab2.0 is licensed under Apache 2.0 and ISC. For more information, see the LICENSE file.

ZGrab 2.0
=========

ZGrab is a fast, modular application-layer network scanner designed for completing large Internet-wide surveys. ZGrab is built to work with ZMap (ZMap identifies L4 responsive hosts, ZGrab performs in-depth, follow-up L7 handshakes). Unlike many other network scanners, ZGrab outputs detailed transcripts of network handshakes (e.g., all messages exchanged in a TLS handshake) for offline analysis.  

> [!TIP]
> If you're just getting started with ZGrab2 and are interested in using it in combination with [ZMap](https://github.com/zmap/zmap) in a measurement pipeline, check out our [Getting Started with ZMap and ZGrab2 guide](https://github.com/zmap/.github/blob/main/wiki/getting-started-with-zmap-and-zgrab2.md).

ZGrab 2.0 contains a new, modular ZGrab framework, which fully supersedes https://github.com/zmap/zgrab.

ZGrab offers modules for a variety of protocols. Currently, we offer:

<table>
<tr><td>AMQP</td><td>BACnet</td><td>Banner</td><td>DNP3</td><td>Fox</td><td>FTP</td><td>HTTP</td><td>IMAP</td><td>IPP</td></tr>
<tr><td>JARM</td><td>ManageSieve</td><td>Memcached</td><td>Modbus</td><td>MongoDB</td><td>MQTT</td><td>MSSQL</td><td>MySQL</td><td>NTP</td></tr>
<tr><td>Oracle</td><td>POP3</td><td>PostgreSQL</td><td>PPTP</td><td>Redis</td><td>Siemens</td><td>SMB</td><td>SMTP</td><td>SOCKS5</td></tr>
<tr><td>SSH</td><td>Telnet</td><td>TLS</td></tr>
</table>

More details are available in the Modules [section](https://github.com/zmap/zgrab2/#single-module-usage) below.

For default behavior, you can pipe a list of target IPs or hostnames (one per line) into ZGrab2 via stdin to check out a modules' output.
```shell
echo "pool.ntp.org" | zgrab2 ntp
```

```sh
{"ip":"23.143.196.199","domain":"pool.ntp.org","data":{"ntp":{"status":"success","protocol":"ntp","port":123,"result":{"version":3,"time":"2025-11-07T00:58:45.13740072Z"},"timestamp":"2025-11-06T16:58:45-08:00"}}}
00h:00m:00s; Scan Complete; 1 targets scanned; 33.01 targets/sec; 100.0% success rate
```

> [!NOTE]
> Ethical Scanning
> 
> ZGrab will only collect information that is available to any standard application client _without_ authenticating.
> We will not accept contributions that attempt to gain access to systems by exploiting vulnerabilities or attempting to brute-force credentials.
> Application handshakes are always aborted before authentication is attempted.

## Installation

### Building from Source
We recommend installing ZGrab2 from source to ensure you have the latest version.

#### Prerequisites
If you do not already have Go installed, follow the instructions on the [Go installation page](https://go.dev/doc/install) to install Go 1.23 or later.

#### Clone and Build ZGrab2
```shell
git clone https://github.com/zmap/zgrab2.git
cd zgrab2
make
./zgrab2 http --help # to see the http module's help message
```

This will create the `zgrab2` binary in the current directory.

You can also install ZGrab2 so it can be used system-wide:
```shell
make install; zgrab2 --help
```

If there are no errors, the `zgrab2` binary should now be available system-wide.

#### Troubleshooting Install
Usually, installation issues are because Go will put the binary in your `$GOPATH/bin` directory, which may not be in your system's `PATH` meaning your shell cannot find it.

If you run into issues with `command not found: zgrab2`, ensure that your `$GOPATH/bin` is in your `PATH` environment variable.
Add the following line to your shell configuration file (e.g., `~/.bashrc`, `~/.zshrc`):
```shell
export PATH=$PATH:$GOPATH/bin
```

Then, reload your shell configuration:
```shell
source ~/.bashrc  # or source ~/.zshrc
```

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

Targets are specified with input files or from `stdin`, in CSV format.  Each input line has up to four fields:

```text
IP, DOMAIN, TAG, PORT
```

Each line must specify `IP`, `DOMAIN`, or both.  If only `DOMAIN` is provided, scanners perform a DNS hostname lookup to determine the IP address.  If both `IP` and `DOMAIN` are provided, scanners connect to `IP` but use `DOMAIN` in protocol-specific contexts, such as the HTTP HOST header and TLS SNI extension.

If the `IP` field contains a CIDR block, the framework will expand it to one target for each IP address in the block.

The `TAG` field is optional and used with the `--trigger` scanner argument. The `PORT` field is also optional, and acts
as a per-line override for the `-p`/`--port` option.

Unused fields can be blank, and trailing unused fields can be omitted entirely.  For backwards compatibility, the parser allows lines with only one field to contain `DOMAIN`.

These are examples of valid input lines:

```text
10.0.0.1
domain.com
10.0.0.1, domain.com
10.0.0.1, domain.com, tag
10.0.0.1, domain.com, tag, 1234
10.0.0.1, , tag
10.0.0.1, , , 5678
, domain.com, tag
192.168.0.0/24, , tag
```

And an example of calling zgrab2 with input:

```shell
echo "en.wikipedia.org" | ./zgrab2 http --max-redirects=1 --endpoint="/wiki/New_York_City"
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

You can run with this configuration using the following:
```shell
cat input.csv | ./zgrab2 multiple -c config.ini        
```

## Adding New Protocols

Broadly, we welcome contributions of new protocol modules to ZGrab2 for IANA recognized services or ones of significant research/security interest. 
Feel free to open an issue to discuss your proposed module before starting work to avoid work that may not be accepted.

Requirements for contributing a new module:
- Clean compile, passes `make lint` and `make test`
- Integration tests that run against a real service and validate output against a schema.


### 1. Scaffold the module

Run the scaffold target to generate the boilerplate:

```shell
make scaffold-new-module PROTO=myproto
```

This creates two files:
- `modules/myproto/scanner.go` — the scanner implementation
- `modules/myproto.go` — the thin registration wrapper

### 2. Fill in the scanner

Open `modules/myproto/scanner.go` and work through the `// TODO` markers:

**`Scanner.Init`** — cast the flags, call `s.SetBaseFlags`, and configure `DialerGroupConfig`.
Most TCP modules look like this:

```go
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
    f, _ := flags.(*Flags)
    s.config = f
    s.SetBaseFlags(&f.BaseFlags)
    s.DialerGroupConfig = &zgrab2.DialerGroupConfig{
        TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
        BaseFlags:                       &f.BaseFlags,
    }
    return nil
}
```

`DialerGroupConfig` is the mechanism that a module describes it's typical connection behavior to the framework so the framework an provide corresponding Dialers for the module to establish connections to the module's `Scanner.Scan` method.

Good examples to follow:
- Basic UDP example: [`modules/ntp/scanner.go`](modules/ntp/scanner.go)
- Basic TCP example: [`modules/jarm/scanner.go`](modules/jarm/scanner.go)
- TCP with Optional TLS: [`modules/fox/scanner.go`](modules/fox/scanner.go)
- Always TLS: [`modules/tls.go`](modules/tls.go)
- TCP handshake, application logic, followed by optional TLS handshake and more application logic: [`modules/smtp/scanner.go`](modules/smtp/scanner.go)


### 3. Register the module

Add it to the map in `bin/default_modules.go`and add the corresponding import at the top of that file.

### 4. Output schema

Add a schema file at `zgrab2_schemas/zgrab2/myproto.py` and register it in [`zgrab2_schemas/zgrab2/__init__.py`](zgrab2_schemas/zgrab2/__init__.py).
See the existing schemas for examples of how to write these files.

### 5. Integration tests

Integration tests are required for all new modules. They ensure the module can always perform a successful handshake against a real service.

Add a test service to `integration_tests/docker-compose.yml` and create an `integration_tests/myproto/` directory.

The only hard requirement is that `test.sh`/`test.py` writes its output to `$ZGRAB_OUTPUT/myproto/*.json` so it can be validated against the schema and the test should sanity-check the response for accuracy.

#### Examples
In the ideal case, use pre-existing Docker images for minimal and real-world matching test cases.
If none are available, a custom Dockerfile can be used to set up a test service.
- [`integration_tests/mysql/`](integration_tests/mysql) - good example of using only a `test.sh` file and pre-existing Docker image to test against
- [`integration_tests/smtp/`](integration_tests/smtp) - uses 4 separate dockerized services to test different service configurations
- [`integration_tests/ssh/`](integration_tests/ssh) - example of using a custom Dockerfile to setup a test service
- [`integration_tests/memcached/test.py`](integration_tests/memcached/test.py) - example of using Python instead of a shell script for running the test. The testing framework can work with either `*.sh` or `*.py` test files.

#### How to Run Integration Tests

To run integration tests, you must have [Docker](https://www.docker.com/) and **Python 3** on host installed. Then, you can follow the following steps to run integration tests:

```shell
# Install Python dependencies
sudo apt update
sudo apt install -y python3 jp python3-pip
python3 -m venv venv
source venv/bin/activate
# Install Python dependencies
pip install zschema
pip install -r requirements.txt
make integration-test-clean; make integration-test
```

Running the integration tests will generate quite a bit of debug output. To ensure that tests completed successfully, you can check for a successful exit code after the tests complete:

```shell
echo $?
0
```

To just run a single/few module's integration tests, you can use the `TEST_MODULES` env. var.:

```shell
make integration-test-clean; TEST_MODULES="http" make integration-test
make integration-test-clean; TEST_MODULES="http ssh" make integration-test
```

Refer to our [Github Actions workflow](.github/workflows/integration-test.yml) for an example of how to prepare environment for integration tests.

## License
ZGrab2.0 is licensed under Apache 2.0 and ISC. For more information, see the LICENSE file.

Zgrab 2.0
=========

This framework contains the new ZGrab framework, and will eventually replace https://github.com/zmap/zgrab.

## Building

You will need to have a valid `$GOPATH` set up, for more information about `$GOPATH`, see https://golang.org/doc/code.html.

Once you have a working `$GOPATH`, run:

```
$ go get github.com/zmap/zgrab2
```

This will install zgrab under `$GOPATH/src/github.com/zmap/zgrab`

```
$ cd $GOPATH/src/github.com/zmap/zgrab
$ make
```

## Single Module Usage 

Zgrab2 supports modules. For example, to run the ssh module use

```
./zgrab2 ssh
```

Module specific options must be included after the module. Application specific options can be specified at any time.

## Multiple Module Usage

To run a scan with multiple modules, a `.ini` file must be used with the `mult` module. Below is an example `.ini` file with the corresponding zgrab2 command. 

```
***mult.ini***
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
```
./zgrab2 mult -c mult.ini
```
If the same module is to be used multiple times then `name` must be specified and unique. The default name for each module is the command name. `Application Options` must be the initial section. Other section names should correspond exactly to the relevant zgrab2 module. 

## Contributing

Add file to zproto/ yo

## License
Zgrab is licensed under Apache 2.0 and ISC. For more information, see the LICENSE file.

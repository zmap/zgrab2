package main

import (
	"bufio"
	"fmt"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
)

type Options struct {
	OutputFileName     string     `short:"o" long:"output-file" default:"-" description:"Output filename, use - for stdout"`
	InputFileName      string     `short:"i" long:"input-file" default:"-" description:"Input filename, use - for stdin"`
	Meta               string     `short:"m" long:"metadata-file" default:"-" description:"Metadata filename, use - for stdout"`
	Log                string     `short:"l" long:"log-file" default:"-" description:"Log filename, use - for stdout"`
	LookupDomain       bool       `short:"d" long:"lookup-domain" description:"Input contains only domain names"`
	Interface          string     `short:"n" long:"interface" description:"Network interface to send on"`
	Timeout            int        `short:"t" long:"timeout" description:"Set connection timeout in seconds"`
	GOMAXPROCS         int        `short:"g" long:"gomaxprocs" default:"3" description:"Set GOMAXPROCS"`
	Senders            int        `short:"s" long:"senders" defaults:"1000" description:"Number of send coroutines to use"`
	ConnectionsPerHost int        `short:"h" long:"connections-per-host" defaults:"1" description:"Number of times to connect to each host (results in more output)"`
	Prometheus         string     `short:"a" long:"prometheus" description:"Address to use for Prometheus server (e.g. localhost:8080). If empty, Prometheus is disabled."`
	TLS                TLSConfig  `command:"tls"`
	HTTP               HTTPConfig `command:"http"`
	SSH                SSHConfig  `command:"ssh"`
	Mult               MultConfig `command:"mult"`

	NumProtocols int
}

var inputFile *os.File

type TLSConfig struct {
	Port                 int  `short:"p" long:"port" default:"443" description:"Specify port to grab on"`
	Heartbleed           bool `long:"heartbleed" description:"Check if server is vulnerable to Heartbleed"`
	Version              int  `long:"version" description:"Max TLS version to use"`
	Verbose              bool `long:"verbose" description:"Add extra TLS information to JSON output (client hello, client KEX, key material, etc)"`
	SessionTicket        bool `long:"session-ticket" description:"Send support for TLS Session Tickets and output ticket if presented"`
	ExtendedMasterSecret bool `long:"extended-master-secret" description:"Offer RFC 7627 Extended Master Secret extension"`
	ExtendedRandom       bool `long:"extended-random" description:"Send TLS Extended Random Extension"`
	NoSNI                bool `long:"no-sni" description:"Do not send domain name in TLS Handshake regardless of whether known"`
	SCTExt               bool `long:"sct" description:"Request Signed Certificate Timestamps during TLS Handshake"`
	HTTP                 HTTPOptions
}

type MultConfig struct {
	ConfigFileName string `short:"c" long:"config-file" default:"-" description:"Config filename, use - for stdin"`
	SameProtocol   bool   `long:"same" description:"Scan the same protocol multiple times with different config values"`

	configFile *os.File
}

type HTTPConfig struct {
	Port int `short:"p" long:"port" default:"80" description:"Specify port to grab on"`
	HTTP HTTPOptions
}

type HTTPOptions struct {
	Method       string `long:"method" default:"GET" description:"Set HTTP request method type"`
	Endpoint     string `long:"endpoint" default:"/" description:"Send an HTTP request to an endpoint"`
	UserAgent    string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent"`
	ProxyDomain  string `long:"proxy-domain" description:"Send a CONNECT <domain> first"`
	MaxSize      int    `long:"max-size" default:"256" description:"Max kilobytes to read in response to an HTTP request"`
	MaxRedirects int    `long:"max-redirects" default:"0" description:"Max number of redirects to follow"`
}

type SSHConfig struct {
	Port              int    `short:"p" long:"port" default:"22" description:"Specify port to grab on"`
	Client            string `long:"client" description:"Mimic behavior of a specific SSH client"`
	KexAlgorithms     string `long:"kex-algorithms" description:"Set SSH Key Exchange Algorithms"`
	HostKeyAlgorithms string `long:"host-key-algorithms" description:"Set SSH Host Key Algorithms"`
	NegativeOne       bool   `long:"negative-one" description:"Set SSH DH kex value to -1 in the selected group"`
}

var numProtocols = 0

//validate all high level configuration options
func validateHighLevel() {
	var err error

	switch options[numProtocols].InputFileName {
	case "-":
		inputFile = os.Stdin
	default:
		if inputFile, err = os.Open(options[numProtocols].InputFileName); err != nil {
			log.Fatal(err)
		}
	}
}

// Execute validates the options sent to TLSConfig and then passes operation back to main
func (x *TLSConfig) Execute(args []string) error {
	validateHighLevel()

	fmt.Println("tls scan")
	return nil
}

// Execute validates the options sent to HTTPConfig and then passes operation back to main
func (x *HTTPConfig) Execute(args []string) error {
	validateHighLevel()

	fmt.Println("http scan")
	return nil
}

// Execute validates the options sent to SSHConfig and then passes operation back to main
func (x *SSHConfig) Execute(args []string) error {
	validateHighLevel()

	fmt.Println("ssh scan")
	return nil
}

func customParse() {
	file, _ := os.Open(options[numProtocols].Mult.ConfigFileName)

	split := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		for i := 0; i < len(data); i++ {
			if data[i] == '[' {
				return i + 1, data[:i], nil
			}
		}
		return 0, data, bufio.ErrFinalToken

	}

	scanner := bufio.NewScanner(file)
	scanner.Split(split)

	count := 0
	for scanner.Scan() {
		if scanner.Text() != "" {
			count++
			bar := strings.NewReader("[" + scanner.Text())
			parser := flags.NewParser(&options[numProtocols], flags.Default)
			foo := flags.NewIniParser(parser)
			if err := foo.Parse(bar); err != nil {
				fmt.Println(err)
			}
			switch scanner.Text()[:3] { //todo: remove this shit, fork goflags or recreate
			case "htt":
				options[numProtocols].SSH.Port = -1
				options[numProtocols].TLS.Port = -1
				options[numProtocols].HTTP.Execute([]string{})
			case "ssh":
				options[numProtocols].HTTP.Port = -1
				options[numProtocols].TLS.Port = -1
				options[numProtocols].SSH.Execute([]string{})
			case "tls":
				options[numProtocols].SSH.Port = -1
				options[numProtocols].HTTP.Port = -1
				options[numProtocols].TLS.Execute([]string{})
			default:
				panic("unrecognized protocol")
			}
		}
	}
}

// Execute validates the options sent to MultConfig parses and executes the protocols and then passes operation back to main
func (x *MultConfig) Execute(args []string) error {
	validateHighLevel()

	var err error
	switch x.ConfigFileName {
	case "-":
		if options[numProtocols].InputFileName == "-" {
			log.Fatal("Cannot read both config and input from stdin")
		}
		x.configFile = os.Stdin
	default:
		if x.configFile, err = os.Open(options[numProtocols].Mult.ConfigFileName); err != nil {
			log.Fatal(err)
		}
	}

	customParse()

	return nil
}

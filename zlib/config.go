package zlib

import (
	"bufio"
	"fmt"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
)

type Option struct {
	OutputFileName     string     `short:"o" long:"output-file" default:"-" description:"Output filename, use - for stdout" json:"out"`
	InputFileName      string     `short:"i" long:"input-file" default:"-" description:"Input filename, use - for stdin" json:"in"`
	Meta               string     `short:"m" long:"metadata-file" default:"-" description:"Metadata filename, use - for stdout" json:"meta"`
	Log                string     `short:"l" long:"log-file" default:"-" description:"Log filename, use - for stdout" json:"log"`
	LookupDomain       bool       `short:"d" long:"lookup-domain" description:"Input contains only domain names" json:"lookup"`
	Interface          string     `short:"f" long:"interface" description:"Network interface to send on" json:"inter"`
	Timeout            int        `short:"t" long:"timeout" description:"Set connection timeout in seconds" json:"time"`
	GOMAXPROCS         int        `short:"g" long:"gomaxprocs" default:"3" description:"Set GOMAXPROCS" json:"gomax"`
	Senders            int        `short:"s" long:"senders" defaults:"1000" description:"Number of send coroutines to use" json:"sender"`
	ConnectionsPerHost int        `short:"h" long:"connections-per-host" defaults:"1" description:"Number of times to connect to each host (results in more output)" json:"connect"`
	Prometheus         string     `short:"a" long:"prometheus" description:"Address to use for Prometheus server (e.g. localhost:8080). If empty, Prometheus is disabled." json:"prom"`
	TLS                TLSConfig  `command:"tls" json:"tls"`
	HTTP               HTTPConfig `command:"http" json:"http"`
	SSH                SSHConfig  `command:"ssh" json:"ssh"`
	Mult               MultConfig `command:"mult" json:"mult"`
}

var Options [10]Option

var inputFile *os.File

var NumProtocols int

type TLSConfig struct {
	Port                 int         `short:"p" long:"port" default:"443" description:"Specify port to grab on" json:"port"`
	Name                 string      `short:"n" long:"name" default:"" description:"Specify name for output json, only necessary if scanning multiple protocols"`
	Heartbleed           bool        `long:"heartbleed" description:"Check if server is vulnerable to Heartbleed" json:"heart"`
	Version              int         `long:"version" description:"Max TLS version to use" json:"version"`
	Verbose              bool        `long:"verbose" description:"Add extra TLS information to JSON output (client hello, client KEX, key material, etc)" json:"verbose"`
	SessionTicket        bool        `long:"session-ticket" description:"Send support for TLS Session Tickets and output ticket if presented" json:"session"`
	ExtendedMasterSecret bool        `long:"extended-master-secret" description:"Offer RFC 7627 Extended Master Secret extension" json:"extended"`
	ExtendedRandom       bool        `long:"extended-random" description:"Send TLS Extended Random Extension" json:"extran"`
	NoSNI                bool        `long:"no-sni" description:"Do not send domain name in TLS Handshake regardless of whether known" json:"sni"`
	SCTExt               bool        `long:"sct" description:"Request Signed Certificate Timestamps during TLS Handshake" json:"sct"`
	HTTP                 HTTPOptions `json:"http"`
}

type MultConfig struct {
	ConfigFileName string `short:"c" long:"config-file" default:"-" description:"Config filename, use - for stdin" json:"config"`
	configFile     *os.File
}

type HTTPConfig struct {
	Port int         `short:"p" long:"port" default:"80" description:"Specify port to grab on" json:"port"`
	Name string      `short:"n" long:"name" default:"" description:"Specify name for output json, only necessary if scanning multiple protocols"`
	HTTP HTTPOptions `json:"http"`
}

type HTTPOptions struct {
	Method       string `long:"method" default:"GET" description:"Set HTTP request method type" json:"method"`
	Endpoint     string `long:"endpoint" default:"/" description:"Send an HTTP request to an endpoint" json:"endpoint"`
	UserAgent    string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent" json:"useragent"`
	ProxyDomain  string `long:"proxy-domain" description:"Send a CONNECT <domain> first" json:"proxydomain"`
	MaxSize      int    `long:"max-size" default:"256" description:"Max kilobytes to read in response to an HTTP request" json:"maxsize"`
	MaxRedirects int    `long:"max-redirects" default:"0" description:"Max number of redirects to follow" json:"maxredirects"`
}

type SSHConfig struct {
	Port              int    `short:"p" long:"port" default:"22" description:"Specify port to grab on" json:"port"`
	Name              string `short:"n" long:"name" default:"" description:"Specify name for output json, only necessary if scanning multiple protocols"`
	Client            string `long:"client" description:"Mimic behavior of a specific SSH client" json:"client"`
	KexAlgorithms     string `long:"kex-algorithms" description:"Set SSH Key Exchange Algorithms" json:"kex"`
	HostKeyAlgorithms string `long:"host-key-algorithms" description:"Set SSH Host Key Algorithms" json:"hostkey"`
	NegativeOne       bool   `long:"negative-one" description:"Set SSH DH kex value to -1 in the selected group" json:"negativeone"`
}

//validate all high level configuration options
func validateHighLevel() {
	var err error

	//Validate files
	switch Options[0].InputFileName {
	case "-":
		inputFile = os.Stdin
	default:
		if inputFile, err = os.Open(Options[0].InputFileName); err != nil {
			log.Fatal(err)
		}
	}

	// Validate Go Runtime config
	if Options[0].GOMAXPROCS < 1 {
		log.Fatal("Invalid GOMAXPROCS (must be at least 1, given %d)", Options[0].GOMAXPROCS)
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
	file, _ := os.Open(Options[NumProtocols].Mult.ConfigFileName)

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

	for scanner.Scan() {
		if scanner.Text() != "" {
			bar := strings.NewReader("[" + scanner.Text())
			parser := flags.NewParser(&Options[NumProtocols], flags.Default)
			foo := flags.NewIniParser(parser)
			if err := foo.Parse(bar); err != nil {
				log.Fatal(err)
			}
			switch scanner.Text()[:3] { //todo: remove this shit, fork goflags or recreate
			case "htt":
				Options[NumProtocols].SSH.Port = -1
				Options[NumProtocols].TLS.Port = -1
				Options[NumProtocols].HTTP.Execute([]string{})
			case "ssh":
				Options[NumProtocols].HTTP.Port = -1
				Options[NumProtocols].TLS.Port = -1
				Options[NumProtocols].SSH.Execute([]string{})
			case "tls":
				Options[NumProtocols].SSH.Port = -1
				Options[NumProtocols].HTTP.Port = -1
				Options[NumProtocols].TLS.Execute([]string{})
			default:
				panic("unrecognized protocol")
			}
		}
		NumProtocols++
	}
}

// Execute validates the options sent to MultConfig parses and executes the protocols and then passes operation back to main
func (x *MultConfig) Execute(args []string) error {
	validateHighLevel()

	var err error
	switch x.ConfigFileName {
	case "-":
		if Options[0].InputFileName == "-" {
			log.Fatal("Cannot read both config and input from stdin")
		}
		x.configFile = os.Stdin
	default:
		if x.configFile, err = os.Open(Options[NumProtocols].Mult.ConfigFileName); err != nil {
			log.Fatal(err)
		}
	}

	customParse()

	return nil
}

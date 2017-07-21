package zlib

import (
	"bufio"
	"encoding/gob"
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
	Senders            int        `short:"s" long:"senders" default:"1000" description:"Number of send coroutines to use" json:"sender"`
	ConnectionsPerHost int        `short:"h" long:"connections-per-host" defaults:"1" description:"Number of times to connect to each host (results in more output)" json:"connect"`
	Prometheus         string     `short:"a" long:"prometheus" description:"Address to use for Prometheus server (e.g. localhost:8080). If empty, Prometheus is disabled." json:"-"`
	TLS                TLSConfig  `command:"tls" json:"tls"`
	HTTP               HTTPConfig `command:"http" json:"http"`
	SSH                SSHConfig  `command:"ssh" json:"ssh"`
	Mult               MultConfig `command:"mult" json:"mult"`
}

var Options [10]Option

var inputFile *os.File

var NumProtocols int

type MultConfig struct {
	ConfigFileName string `short:"c" long:"config-file" default:"-" description:"Config filename, use - for stdin" json:"config"`
	configFile     *os.File
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
	NumProtocols++ //trust me
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
				Options[NumProtocols].HTTP.Execute([]string{})
			case "ssh":
				Options[NumProtocols].SSH.Execute([]string{})
			case "tls":
				Options[NumProtocols].TLS.Execute([]string{})
			default:
				panic("unrecognized protocol")
			}
			NumProtocols++
		}
	}
}

// Execute validates the options sent to MultConfig runs customParse and then passes operation back to main
func (x *MultConfig) Execute(args []string) error {
	validateHighLevel()
	NumProtocols-- //trust me

	var err error
	switch x.ConfigFileName {
	case "-":
		if Options[0].InputFileName == "-" {
			log.Fatal("Cannot read both config and input from stdin")
		}
		x.configFile = os.Stdin
	default:
		if x.configFile, err = os.Open(Options[0].Mult.ConfigFileName); err != nil {
			log.Fatal(err)
		}
	}

	deepCopyAll()
	customParse()
	return nil
}

// this is even more hacky
func deepcopy(dst, src interface{}) error {
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	enc := gob.NewEncoder(w)
	err = enc.Encode(src)
	if err != nil {
		return err
	}
	dec := gob.NewDecoder(r)
	return dec.Decode(dst)
}

// this is a super hacky method of ensuring that all options get defaults set
func deepCopyAll() {
	for i := 1; i < 10; i++ {
		deepcopy(&Options[i], Options[0])
	}
}

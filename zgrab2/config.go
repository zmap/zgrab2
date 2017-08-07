package zgrab2

import (
	"os"

	log "github.com/sirupsen/logrus"
)

type Config struct {
	OutputFileName     string     `short:"o" long:"output-file" default:"-" description:"Output filename, use - for stdout"`
	InputFileName      string     `short:"f" long:"input-file" default:"-" description:"Input filename, use - for stdin"`
	MetaFileName       string     `short:"m" long:"metadata-file" default:"-" description:"Metadata filename, use - for stdout"`
	LogFileName        string     `short:"l" long:"log-file" default:"-" description:"Log filename, use - for stdout"`
	Interface          string     `short:"i" long:"interface" description:"Network interface to send on"`
	Timeout            int        `short:"t" long:"timeout" description:"Set connection timeout in seconds"`
	Senders            int        `short:"s" long:"senders" default:"1000" description:"Number of send goroutines to use"`
	GOMAXPROCS         int        `long:"gomaxprocs" default:"0" description:"Set GOMAXPROCS"`
	ConnectionsPerHost int        `long:"connections-per-host" defaults:"1" description:"Number of times to connect to each host (results in more output)"`
	Prometheus         string     `long:"prometheus" description:"Address to use for Prometheus server (e.g. localhost:8080). If empty, Prometheus is disabled."`
	Mult               MultConfig `command:"mult" description:"Multiple banner grabs"`

	inputFile  *os.File
	outputFile *os.File
	metaFile   *os.File
	logFile    *os.File
}

func init() {
	config.Mult.ContinueOnError = true //set default for mult value
}

var config Config

//validate all high level configuration options
func ValidateHighLevel() {
	//Validate files
	if config.LogFileName != "-" {
		var err error
		if config.logFile, err = os.Open(config.LogFileName); err != nil {
			log.Fatal(err)
		}
		log.SetOutput(config.logFile)
	}

	switch config.InputFileName {
	case "-":
		config.inputFile = os.Stdin
	default:
		var err error
		if config.inputFile, err = os.Open(config.InputFileName); err != nil {
			log.Fatal(err)
		}
	}

	switch config.OutputFileName {
	case "-":
		config.outputFile = os.Stdout
	default:
		var err error
		if config.outputFile, err = os.Open(config.OutputFileName); err != nil {
			log.Fatal(err)
		}
	}

	switch config.MetaFileName {
	case "-":
		config.metaFile = os.Stdout
	default:
		var err error
		if config.metaFile, err = os.Open(config.MetaFileName); err != nil {
			log.Fatal(err)
		}
	}

	// Validate Go Runtime config
	if config.GOMAXPROCS < 0 {
		log.Fatal("invalid GOMAXPROCS (must be at least 1, given %d)", config.GOMAXPROCS)
	}
}

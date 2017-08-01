package zgrab2

import (
	log "github.com/sirupsen/logrus"
	"os"
)

type Option struct {
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

	inputFile *os.File
}

func init() {
	options.Mult.ContinueOnError = true //set default for mult value
}

var options Option

//validate all high level configuration options
func ValidateHighLevel() {
	//Validate files
	switch options.InputFileName {
	case "-":
		options.inputFile = os.Stdin
	default:
		var err error
		if options.inputFile, err = os.Open(options.InputFileName); err != nil {
			log.Fatal(err)
		}
	}

	// Validate Go Runtime config
	if options.GOMAXPROCS < 0 {
		log.Fatal("invalid GOMAXPROCS (must be at least 1, given %d)", options.GOMAXPROCS)
	}
}

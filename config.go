package zgrab2

import (
	"net/http"
	"os"
	"runtime"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	OutputFileName     string          `short:"o" long:"output-file" default:"-" description:"Output filename, use - for stdout"`
	InputFileName      string          `short:"f" long:"input-file" default:"-" description:"Input filename, use - for stdin"`
	MetaFileName       string          `short:"m" long:"metadata-file" default:"-" description:"Metadata filename, use - for stdout"`
	LogFileName        string          `short:"l" long:"log-file" default:"-" description:"Log filename, use - for stdout"`
	Interface          string          `short:"i" long:"interface" description:"Network interface to send on"`
	Senders            int             `short:"s" long:"senders" default:"1000" description:"Number of send goroutines to use"`
	GOMAXPROCS         int             `long:"gomaxprocs" default:"0" description:"Set GOMAXPROCS"`
	ConnectionsPerHost int             `long:"connections-per-host" default:"1" description:"Number of times to connect to each host (results in more output)"`
	Prometheus         string          `long:"prometheus" description:"Address to use for Prometheus server (e.g. localhost:8080). If empty, Prometheus is disabled."`
	Multiple           MultipleCommand `command:"multiple" description:"Multiple module actions"`

	inputFile  *os.File
	outputFile *os.File
	metaFile   *os.File
	logFile    *os.File
}

func init() {
	config.Multiple.ContinueOnError = true //set default for multiple value
}

var config Config

//validate all framework configuration options
func validateFrameworkConfiguration() {
	//Validate files
	switch config.LogFileName {
	case "-":
		config.logFile = os.Stderr
	default:
		var err error
		if config.logFile, err = os.Create(config.LogFileName); err != nil {
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
		if config.outputFile, err = os.Create(config.OutputFileName); err != nil {
			log.Fatal(err)
		}
	}

	switch config.MetaFileName {
	case "-":
		config.metaFile = os.Stderr
	default:
		var err error
		if config.metaFile, err = os.Create(config.MetaFileName); err != nil {
			log.Fatal(err)
		}
	}

	// Validate Go Runtime config
	if config.GOMAXPROCS < 0 {
		log.Fatal("invalid GOMAXPROCS (must be positive, given %d)", config.GOMAXPROCS)
	}
	runtime.GOMAXPROCS(config.GOMAXPROCS)

	//validate/start prometheus
	if config.Prometheus != "" {
		go func() {
			http.Handle("metrics", promhttp.Handler())
			if err := http.ListenAndServe(config.Prometheus, nil); err != nil {
				log.Fatalf("could not run prometheus server: %s", err.Error())
			}
		}()
	}

	//validate senders
	if config.Senders <= 0 {
		log.Fatalf("need at least one sender, given %d", config.Senders)
	}

	// validate connections per host
	if config.ConnectionsPerHost <= 0 {
		log.Fatalf("need at least one connection, given %d", config.ConnectionsPerHost)
	}

	// Stop the lowliest idiot from using this to DoS people
	if config.ConnectionsPerHost > 50 || config.ConnectionsPerHost < 1 {
		log.Fatalf("connectionsPerHost must be in the range [0,50]")
	}
}

func GetMetaFile() *os.File {
	return config.metaFile
}

package zgrab2

import (
	"net"
	"net/http"
	"os"
	"runtime"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

// Config is the high level framework options that will be parsed
// from the command line
type Config struct {
	OutputFileName     string          `short:"o" long:"output-file" default:"-" description:"Output filename, use - for stdout"`
	InputFileName      string          `short:"f" long:"input-file" default:"-" description:"Input filename, use - for stdin"`
	MetaFileName       string          `short:"m" long:"metadata-file" default:"-" description:"Metadata filename, use - for stderr"`
	LogFileName        string          `short:"l" long:"log-file" default:"-" description:"Log filename, use - for stderr"`
	Senders            int             `short:"s" long:"senders" default:"1000" description:"Number of send goroutines to use"`
	Debug              bool            `long:"debug" description:"Include debug fields in the output."`
	Flush              bool            `long:"flush" description:"Flush after each line of output."`
	GOMAXPROCS         int             `long:"gomaxprocs" default:"0" description:"Set GOMAXPROCS"`
	ConnectionsPerHost int             `long:"connections-per-host" default:"1" description:"Number of times to connect to each host (results in more output)"`
	ReadLimitPerHost   int             `long:"read-limit-per-host" default:"96" description:"Maximum total kilobytes to read for a single host (default 96kb)"`
	Prometheus         string          `long:"prometheus" description:"Address to use for Prometheus server (e.g. localhost:8080). If empty, Prometheus is disabled."`
	Multiple           MultipleCommand `command:"multiple" description:"Multiple module actions"`
	inputFile          *os.File
	outputFile         *os.File
	metaFile           *os.File
	logFile            *os.File
	inputTargets       InputTargetsFunc
	outputResults      OutputResultsFunc
	localAddr          *net.TCPAddr
}

// SetInputFunc sets the target input function to the provided function.
func SetInputFunc(f InputTargetsFunc) {
	config.inputTargets = f
}

// SetOutputFunc sets the result output function to the provided function.
func SetOutputFunc(f OutputResultsFunc) {
	config.outputResults = f
}

func init() {
	config.Multiple.ContinueOnError = true // set default for multiple value
	config.Multiple.BreakOnSuccess = false // set default for multiple value
}

var config Config

func validateFrameworkConfiguration() {
	// validate files
	if config.LogFileName == "-" {
		config.logFile = os.Stderr
	} else {
		var err error
		if config.logFile, err = os.Create(config.LogFileName); err != nil {
			log.Fatal(err)
		}
		log.SetOutput(config.logFile)
	}
	SetInputFunc(InputTargetsCSV)

	if config.InputFileName == "-" {
		config.inputFile = os.Stdin
	} else {
		var err error
		if config.inputFile, err = os.Open(config.InputFileName); err != nil {
			log.Fatal(err)
		}
	}

	if config.OutputFileName == "-" {
		config.outputFile = os.Stdout
	} else {
		var err error
		if config.outputFile, err = os.Create(config.OutputFileName); err != nil {
			log.Fatal(err)
		}
	}
	outputFunc := OutputResultsWriterFunc(config.outputFile)
	SetOutputFunc(outputFunc)

	if config.MetaFileName == "-" {
		config.metaFile = os.Stderr
	} else {
		var err error
		if config.metaFile, err = os.Create(config.MetaFileName); err != nil {
			log.Fatal(err)
		}
	}

	// Validate Go Runtime config
	if config.GOMAXPROCS < 0 {
		log.Fatalf("invalid GOMAXPROCS (must be positive, given %d)", config.GOMAXPROCS)
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
	if config.ConnectionsPerHost > 50 {
		log.Fatalf("connectionsPerHost must be in the range [0,50]")
	}

	// Stop even third-party libraries from performing unbounded reads on untrusted hosts
	if config.ReadLimitPerHost > 0 {
		DefaultBytesReadLimit = config.ReadLimitPerHost * 1024
	}
}

// GetMetaFile returns the file to which metadata should be output
func GetMetaFile() *os.File {
	return config.metaFile
}

func includeDebugOutput() bool {
	return config.Debug
}

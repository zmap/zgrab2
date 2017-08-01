package zgrab2

import (
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"os"
)

type MultConfig struct {
	ConfigFileName  string `short:"c" long:"config-file" default:"-" description:"Config filename, use - for stdin"`
	ContinueOnError bool   `long:"continue-on-error" description:"If proceeding protocols error, do not run following protocols (default: true)"`
	configFile      *os.File
}

// Execute validates the options sent to MultConfig runs customParse and then passes operation back to main
func (x *MultConfig) Validate(args []string) error {
	ValidateHighLevel()
	var err error
	switch x.ConfigFileName {
	case "-":
		if options.InputFileName == "-" {
			log.Fatal("Cannot read both config and input from stdin")
		}
		x.configFile = os.Stdin
	default:
		if x.configFile, err = os.Open(x.ConfigFileName); err != nil {
			log.Fatal(err)
		}
	}

	customParse()
	return nil
}

func customParse() {
	foo := flags.NewIniParser(Parser)
	if err := foo.ParseFile(options.Mult.ConfigFileName); err != nil {
		log.Fatal(err)
	}
}

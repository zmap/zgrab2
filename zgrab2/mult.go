package zgrab2

import (
	"os"

	"github.com/ajholland/zflags"
	log "github.com/sirupsen/logrus"
)

type MultConfig struct {
	ConfigFileName  string `short:"c" long:"config-file" default:"-" description:"Config filename, use - for stdin"`
	ContinueOnError bool   `long:"continue-on-error" description:"If proceeding protocols error, do not run following protocols (default: true)"`
	configFile      *os.File
}

// Validates the options sent to MultConfig runs iniParse and then passes operation back to main
func (x *MultConfig) Validate(args []string) error {
	ValidateHighLevel()
	var err error
	switch x.ConfigFileName {
	case "-":
		if config.InputFileName == "-" {
			log.Fatal("Cannot read both config and input from stdin")
		}
		x.configFile = os.Stdin
	default:
		if x.configFile, err = os.Open(x.ConfigFileName); err != nil {
			log.Fatal(err)
		}
	}

	foo := flags.NewIniParser(parser)
	if err := foo.ParseFile(config.Mult.ConfigFileName); err != nil {
		log.Fatal(err)
	}
	return nil
}

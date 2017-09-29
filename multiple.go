package zgrab2

import "errors"

type MultipleCommand struct {
	ConfigFileName  string `short:"c" long:"config-file" default:"-" description:"Config filename, use - for stdin"`
	ContinueOnError bool   `long:"continue-on-error" description:"If proceeding protocols error, do not run following protocols (default: true)"`
}

// Validates the options sent to MultipleCommand, and parses the configFile
func (x *MultipleCommand) Validate(args []string) error {
	if x.ConfigFileName == config.InputFileName {
		return errors.New("cannot receive config file and input file from same source")
	}

	return nil
}

func (x *MultipleCommand) Help() string {
	return ""
}

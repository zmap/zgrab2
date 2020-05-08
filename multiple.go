package zgrab2

import "errors"

// MultipleCommand contains the command line options for running
type MultipleCommand struct {
	ConfigFileName  string `short:"c" long:"config-file" default:"-" description:"Config filename, use - for stdin"`
	ContinueOnError bool   `long:"continue-on-error" description:"If proceeding protocols error, do not run following protocols (default: true)"`
	BreakOnSuccess  bool   `long:"break-on-success" description:"If proceeding protocols succeed, do not run following protocols (default: false)"`
}

// Validate the options sent to MultipleCommand
func (x *MultipleCommand) Validate(args []string) error {
	if x.ConfigFileName == config.InputFileName {
		return errors.New("cannot receive config file and input file from same source")
	}

	return nil
}

// Help returns a usage string that will be output at the command line
func (x *MultipleCommand) Help() string {
	return ""
}

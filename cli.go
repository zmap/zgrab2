package zgrab2

import (
	"fmt"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	flags "github.com/zmap/zflags"
)

var (
	parser *flags.Parser // parser for main zgrab2 command
	// iniParser is a parser just for ini files. It's frustrating that we need both, but the ini parser needs an option
	// group 'Application Options' and it seems we can't have this along with option groups in the main parser and have
	// options set correctly. The hidden one shadows the other and no CLI flags are set.
	iniParser *flags.Parser
)

const defaultDNSPort = "53"

func init() {
	parser = flags.NewParser(nil, flags.Default)
	desc := []string{
		// Using a long single line so the terminal can handle wrapping, except for Input/Examples which should be on
		// separate lines
		"zgrab2 is fast, modular L7 application-layer scanner. It is commonly used with tools like ZMap which identify " +
			"\"potential services\", or services we know are active on a given IP + port, and these are fed into ZGrab2 " +
			"to confirm and provide details of the service. It has support for a number of protocols listed below as " +
			"'Available commands' including SSH and HTTP. By default, zgrab2 will accept input from stdin and output " +
			"results to stdout, with updates and logs to stderr. Please see 'zgrab2 <command> --help' for more details " +
			"on a specific command.",
		"Input is taken from stdin or --input-file, if specified. Input is CSV-formatted with 'IP, Domain, Tag, Port' " +
			"or simply 'IP' or 'Domain'. See README.md for more details.",
		"",
		"Example usages:",
		"echo '1.1.1.1' | zgrab2 tls        # Scan 1.1.1.1 with TLS",
		"echo example.com | zgrab2 http     # Scan example.com with HTTP",
	}
	parser.LongDescription = strings.Join(desc, "\n")
	_, err := parser.AddCommand("multiple", "Run multiple commands in a single run", "", &config.Multiple)
	if err != nil {
		log.Fatalf("could not add multiple command: %v", err)
	}
	_, err = parser.AddGroup("General Options", "General options for controlling the behavior of ZGrab2", &config.GeneralOptions)
	if err != nil {
		log.Fatalf("could not add general options group: %v", err)
	}
	_, err = parser.AddGroup("Input/Output Options", "Options for controlling the input/output behavior of ZGrab2", &config.InputOutputOptions)
	if err != nil {
		log.Fatalf("could not add I/O options group: %v", err)
	}
	_, err = parser.AddGroup("Network Options", "Options for controlling the network behavior of ZGrab2", &config.NetworkingOptions)
	if err != nil {
		log.Fatalf("could not add networking options group: %v", err)
	}
	iniParser = flags.NewParser(nil, flags.Default)
}

// NewIniParser creates and returns a ini parser initialized
// with the default parser
func NewIniParser() *flags.IniParser {
	group, err := iniParser.AddGroup("Application Options", "Hidden group including all global options for ini files", &config)
	if err != nil {
		log.Fatalf("could not add Application Options group: %v", err)
	}
	group.Hidden = true

	return flags.NewIniParser(iniParser)
}

// AddCommand adds a module to the parser and returns a pointer to
// a flags.command object or an error
func AddCommand(command string, shortDescription string, longDescription string, port int, m ScanModule) (*flags.Command, error) {
	cmd, err := parser.AddCommand(command, shortDescription, longDescription, m)
	if err != nil {
		return nil, fmt.Errorf("could not add command to default parser: %w", err)
	}
	cmd.FindOptionByLongName("port").Default = []string{strconv.Itoa(port)}
	cmd.FindOptionByLongName("name").Default = []string{command}

	// Add the same command to the ini parser
	cmd, err = iniParser.AddCommand(command, shortDescription, longDescription, m)
	if err != nil {
		return nil, fmt.Errorf("could not add command to ini parser: %w", err)
	}
	cmd.FindOptionByLongName("port").Default = []string{strconv.Itoa(port)}
	cmd.FindOptionByLongName("name").Default = []string{command}
	modules[command] = m
	return cmd, nil
}

// ParseCommandLine parses the commands given on the command line
// and validates the framework configuration (global options)
// immediately after parsing
func ParseCommandLine(flags []string) ([]string, string, ScanFlags, error) {
	posArgs, moduleType, f, err := parser.ParseCommandLine(flags)
	if err == nil {
		validateFrameworkConfiguration()
	}
	sf, _ := f.(ScanFlags)
	return posArgs, moduleType, sf, err
}

package redis

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// redis-specific command-line flags.
type Flags struct {
	zgrab2.BaseFlags

	DoInline bool `long:"inline" description:"Send commands using the inline syntax"`
	Verbose  bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// Module implements the zgrab2.Module interface
type Module struct {
	// TODO: Add any module-global state
}

// Scanner implements the zgrab2.Scanner interface
type Scanner struct {
	config *Flags
}

// Scan holds the state for the scan of an individual target
type Scan struct {
	scanner *Scanner
	target  *zgrab2.ScanTarget
	conn    *Connection
}

// Result is the struct that is returned by the scan.
type Result struct {
	// Commands is the list of commands actually sent to the server, serialized in inline format (e.g. COMMAND arg1 "arg 2" arg3)
	Commands []string `json:"commands"`
	// CommandOutput is the output returned by the server for each command sent; the index in CommandOutput matches the index in Commands.
	CommandOutput []RedisValue `json:"command_output"`
}

// RegisterModule registers the zgrab2 module
func RegisterModule() {
	var module Module
	// FIXME: Set default port
	_, err := zgrab2.AddCommand("redis", "redis", "Probe for redis", 6379, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

func (flags *Flags) Validate(args []string) error {
	return nil
}

func (flags *Flags) Help() string {
	return ""
}

func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	return nil
}

func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

func (scanner *Scanner) GetPort() uint {
	return scanner.config.Port
}

func (scan *Scan) SendCommand(list []string) (RedisValue, error) {
	exec := scan.conn.SendCommand
	if scan.scanner.config.DoInline {
		exec = scan.conn.SendInlineCommand
	}
	return exec(list...)
}

func (scanner *Scanner) StartScan(target *zgrab2.ScanTarget) (*Scan, error) {
	conn, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return nil, err
	}
	return &Scan{
		target:  target,
		scanner: scanner,
		conn: &Connection{
			scanner: scanner,
			conn:    conn,
		},
	}, nil
}

// Scanner.Scan() TODO: describe what is scanned
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	commandList := [][]string{
		[]string{"PING"},
		[]string{"PING", "test"},
		[]string{"INFO"},
		[]string{"CLIENT", "LIST"},
		[]string{"INCR", "scancount"},
		[]string{"COMMAND"},
		[]string{"DBSIZE"},
		[]string{"DEBUG", "DIGEST"},
		[]string{"ECHO", "test"},
		[]string{"DOESNOTEXIST"},
	}
	var result *Result
	scan, err := scanner.StartScan(&target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	for i, cmds := range commandList {
		ret, err := scan.SendCommand(cmds)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		if result == nil {
			result = &Result{}
		}
		result.Commands = append(result.Commands, getInlineCommand(cmds...))
		result.CommandOutput = append(result.CommandOutput, ret)
		log.Warnf("%s -> %v / %s", result.Commands[i], ret, string(ret.Encode()))
	}
	return zgrab2.SCAN_SUCCESS, &result, nil
}

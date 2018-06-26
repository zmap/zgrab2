// Package redis provides a zgrab2 Module that probes for redis services.
// The default port for redis is TCP 6379, and it is a cleartext protocol
// defined at https://redis.io/topics/protocol.
// Servers can be configured to require (cleartext) password authentication,
// which is omitted from our probe by default (pass --password <your password>
// to supply one).
// Further, admins can rename commands, so even if authentication is not
// required we may not get the expected output.
// However, we should always get output in the expected format, which is fairly
// distinct. The probe sends a sequence of commands and checks that the response
// is well-formed redis data, which should be possible whatever the
// configuration.
package redis

import (
	"fmt"
	"io"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// Flags contains redis-specific command-line flags.
type Flags struct {
	zgrab2.BaseFlags

	// TODO: Take a JSON/YAML file with a list of custom commands to execute?
	// TODO: Take a JSON/YAML file with mappings for command names?
	AuthCommand string `long:"auth-command" default:"AUTH" description:"Override the command used to authenticate. Ignored if no password is set."`
	Password    string `long:"password" description:"Set a password to use to authenticate to the server. WARNING: This is sent in the clear."`
	DoInline    bool   `long:"inline" description:"Send commands using the inline syntax"`
	Verbose     bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// Module implements the zgrab2.Module interface
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface
type Scanner struct {
	config *Flags
}

// scan holds the state for the scan of an individual target
type scan struct {
	scanner *Scanner
	result  *Result
	target  *zgrab2.ScanTarget
	conn    *Connection
	close   func()
}

// Result is the struct that is returned by the scan.
// If authentication is required, most responses can have the value
// "(error: NOAUTH Authentication required.)"
type Result struct {
	// Commands is the list of commands actually sent to the server, serialized
	// in inline format (e.g. COMMAND arg1 "arg 2" arg3)
	Commands []string `json:"commands,omitempty" zgrab:"debug"`

	// RawCommandOutput is the output returned by the server for each command sent;
	// the index in RawCommandOutput matches the index in Commands.
	RawCommandOutput [][]byte `json:"raw_command_output,omitempty" zgrab:"debug"`

	// PingResponse is the response from the server, should be the simple string
	// "PONG".
	// NOTE: This is invoked *before* calling AUTH, so this may return an auth
	// required error even if --password is provided.
	PingResponse string `json:"ping_response,omitempty"`

	// InfoResponse is the response from the INFO command: "Lines can contain a
	// section name (starting with a # character) or a property. All the
	// properties are in the form of field:value terminated by \r\n."
	InfoResponse string `json:"info_response,omitempty"`

	// QuitResponse is the response from the QUIT command -- should be the
	// simple string "OK" even when authentication is required, unless the
	// QUIT command was renamed.
	QuitResponse string `json:"quit_response,omitempty"`

	// NonexistentResponse is the response to the non-existent command; even if
	// auth is required, this may give a different error than existing commands.
	NonexistentResponse string `json:"nonexistent_response,omitempty"`

	// AuthResponse is only included if --password is set.
	AuthResponse string `json:"auth_response,omitempty"`

	// Version is read from the InfoResponse (the field "server_version"), if
	// present.
	Version string `json:"version,omitempty"`
}

// RegisterModule registers the zgrab2 module
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("redis", "redis", "Probe for redis", 6379, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags provides an empty instance of the flags that will be filled in by the framework
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner provides a new scanner instance
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate checks that the flags are valid
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string
func (flags *Flags) Help() string {
	return ""
}

// Init initializes the scanner
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	return nil
}

// InitPerSender initializes the scanner for a given sender
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the name of the scanner
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// GetPort returns the port being scanned
func (scanner *Scanner) GetPort() uint {
	return scanner.config.Port
}

// Close cleans up the scanner.
func (scan *scan) Close() {
	defer scan.close()
}

// SendCommand sends the given command/args to the server, using the scanner's
// configuration, and drop the command/output into the result.
func (scan *scan) SendCommand(cmd string, args ...string) (RedisValue, error) {
	exec := scan.conn.SendCommand
	scan.result.Commands = append(scan.result.Commands, getInlineCommand(cmd, args...))
	if scan.scanner.config.DoInline {
		exec = scan.conn.SendInlineCommand
	}
	ret, err := exec(cmd, args...)
	if err != nil {
		return nil, err
	}
	scan.result.RawCommandOutput = append(scan.result.RawCommandOutput, ret.Encode())
	return ret, nil
}

// StartScan opens a connection to the target and sets up a scan instance for it
func (scanner *Scanner) StartScan(target *zgrab2.ScanTarget) (*scan, error) {
	conn, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return nil, err
	}
	return &scan{
		target:  target,
		scanner: scanner,
		result:  &Result{},
		conn: &Connection{
			scanner: scanner,
			conn:    conn,
		},
		close: func() { conn.Close() },
	}, nil
}

// Force the response into a string. Used when you expect a human-readable
// string.
func forceToString(val RedisValue) string {
	switch v := val.(type) {
	case SimpleString:
		return string(v)
	case BulkString:
		return string([]byte(v))
	case Integer:
		return fmt.Sprintf("%d", v)
	case ErrorMessage:
		return fmt.Sprintf("(Error: %s)", string(v))
	case NullType:
		return "<null>"
	case RedisArray:
		return "(Unexpected array)"
	default:
		panic("unreachable")
	}
}

// Protocol returns the protocol identifer for the scanner.
func (s *Scanner) Protocol() string {
	return "redis"
}

// Scan executes the following commands:
// 1. PING
// 2. (only if --password is provided) AUTH <password>
// 3. INFO
// 4. NONEXISTENT
// 5. QUIT
// The responses for each of these is logged, and if INFO succeeds, the version
// is scraped from it.
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	// ping, info, quit
	scan, err := scanner.StartScan(&target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer scan.Close()
	result := scan.result
	pingResponse, err := scan.SendCommand("PING")
	if err != nil {
		// if the first command fails (as opposed to succeeding but returning an
		// ErrorMessage response), then flag the probe as having failed.
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	// From this point forward, we always return a non-nil result, implying that
	// we have positively identified that a redis service is present.
	result.PingResponse = forceToString(pingResponse)
	if scanner.config.Password != "" {
		authResponse, err := scan.SendCommand(scanner.config.AuthCommand, scanner.config.Password)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		result.AuthResponse = forceToString(authResponse)
	}
	infoResponse, err := scan.SendCommand("INFO")
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	result.InfoResponse = forceToString(infoResponse)
	infoResponseBulk, ok := infoResponse.(BulkString)
	if ok {
		for _, line := range strings.Split(string(infoResponseBulk), "\r\n") {
			if strings.HasPrefix(line, "redis_version:") {
				result.Version = strings.SplitN(line, ":", 2)[1]
				break
			}
		}
	}
	bogusResponse, err := scan.SendCommand("NONEXISTENT")
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	result.NonexistentResponse = forceToString(bogusResponse)
	quitResponse, err := scan.SendCommand("QUIT")
	if err != nil && err != io.EOF {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	result.QuitResponse = forceToString(quitResponse)
	return zgrab2.SCAN_SUCCESS, &result, nil
}

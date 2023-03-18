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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"gopkg.in/yaml.v2"
)

// Flags contains redis-specific command-line flags.
type Flags struct {
	zgrab2.BaseFlags

	CustomCommands   string `long:"custom-commands" description:"Pathname for JSON/YAML file that contains extra commands to execute. WARNING: This is sent in the clear."`
	Mappings         string `long:"mappings" description:"Pathname for JSON/YAML file that contains mappings for command names."`
	MaxInputFileSize int64  `long:"max-input-file-size" default:"102400" description:"Maximum size for either input file."`
	Password         string `long:"password" description:"Set a password to use to authenticate to the server. WARNING: This is sent in the clear."`
	DoInline         bool   `long:"inline" description:"Send commands using the inline syntax"`
	Verbose          bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
	UseTLS           bool   `long:"use-tls" description:"Sends probe with a TLS connection. Loads TLS module command options."`
	zgrab2.TLSFlags
}

// Module implements the zgrab2.Module interface
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface
type Scanner struct {
	config          *Flags
	commandMappings map[string]string
	customCommands  []string
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

	// AuthResponse is only included if --password is set.
	AuthResponse string `json:"auth_response,omitempty"`

	// InfoResponse is the response from the INFO command: "Lines can contain a
	// section name (starting with a # character) or a property. All the
	// properties are in the form of field:value terminated by \r\n."
	InfoResponse string `json:"info_response,omitempty"`

	// Version is read from the InfoResponse (the field "server_version"), if
	// present.
	Version string `json:"version,omitempty"`

	// Major is the version's major number.
	Major *uint32 `json:"major,omitempty"`

	// Minor is the version's minor number.
	Minor *uint32 `json:"minor,omitempty"`

	// Patchlevel is the version's patchlevel number.
	Patchlevel *uint32 `json:"patchlevel,omitempty"`

	// OS is read from the InfoResponse (the field "os"), if present. It specifies
	// the OS the redis server is running.
	OS string `json:"os,omitempty"`

	// ArchBits is read from the InfoResponse (the field "arch_bits"), if present.
	// It specifies the architecture bits (32 or 64) the redis server used to build.
	ArchBits string `json:"arch_bits,omitempty"`

	// Mode is read from the InfoResponse (the field "redis_mode"), if present.
	// It specifies the mode the redis server is running, either cluster or standalone.
	Mode string `json:"mode,omitempty"`

	// GitSha1 is read from the InfoResponse (the field "redis_git_sha1"), if present.
	// It specifies the Git Sha 1 the redis server used.
	GitSha1 string `json:"git_sha1,omitempty"`

	// BuildID is read from the InfoResponse (the field "redis_build_id"), if present.
	// It specifies the Build ID of the redis server.
	BuildID string `json:"build_id,omitempty"`

	// GCCVersion is read from the InfoResponse (the field "gcc_version"), if present.
	// It specifies the version of the GCC compiler used to compile the Redis server.
	GCCVersion string `json:"gcc_version,omitempty"`

	// MemAllocator is read from the InfoResponse (the field "mem_allocator"), if present.
	// It specifies the memory allocator.
	MemAllocator string `json:"mem_allocator,omitempty"`

	// Uptime is read from the InfoResponse (the field "uptime_in_seconds"), if present.
	// It specifies the number of seconds since Redis server start.
	Uptime uint32 `json:"uptime_in_seconds,omitempty"`

	// UsedMemory is read from the InfoResponse (the field "used_memory"), if present.
	// It specifies the total number of bytes allocated by Redis using its allocator.
	UsedMemory uint32 `json:"used_memory,omitempty"`

	// ConnectionsReceived is read from the InfoResponse (the field "total_connections_received"),
	// if present. It specifies the total number of connections accepted by the server.
	ConnectionsReceived uint32 `json:"total_connections_received,omitempty"`

	// CommandsProcessed is read from the InfoResponse (the field "total_commands_processed"),
	// if present. It specifies the total number of commands processed by the server.
	CommandsProcessed uint32 `json:"total_commands_processed,omitempty"`

	// NonexistentResponse is the response to the non-existent command; even if
	// auth is required, this may give a different error than existing commands.
	NonexistentResponse string `json:"nonexistent_response,omitempty"`

	// CustomResponses is an array that holds the commands, arguments, and
	// responses from user-inputted commands.
	CustomResponses []CustomResponse `json:"custom_responses,omitempty"`

	// QuitResponse is the response from the QUIT command -- should be the
	// simple string "OK" even when authentication is required, unless the
	// QUIT command was renamed.
	QuitResponse string `json:"quit_response,omitempty"`

	// TLSLog is the standard TLS log for the connection if used
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// RegisterModule registers the zgrab2 module
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("redis", "redis", module.Description(), 6379, &module)
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

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Probe for Redis"
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
	err := scanner.initCommands()
	if err != nil {
		log.Fatal(err)
	}
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

// Close cleans up the scanner.
func (scan *scan) Close() {
	defer scan.close()
}

func getUnmarshaler(file string) (func([]byte, interface{}) error, error) {
	var unmarshaler func([]byte, interface{}) error
	switch ext := filepath.Ext(file); ext {
	case ".json":
		unmarshaler = json.Unmarshal
	case ".yaml", ".yml":
		unmarshaler = yaml.Unmarshal
	default:
		err := fmt.Errorf("file type %s not valid", ext)
		return nil, err
	}
	return unmarshaler, nil
}

func (scanner *Scanner) getFileContents(file string, output interface{}) error {
	unmarshaler, err := getUnmarshaler(file)
	if err != nil {
		return err
	}
	fileStat, err := os.Stat(file)
	if err != nil {
		return err
	}
	if fileStat.Size() > scanner.config.MaxInputFileSize {
		err = fmt.Errorf("input file too large")
		return err
	}
	fileContent, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	err = unmarshaler([]byte(fileContent), output)
	if err != nil {
		return err
	}

	return nil
}

// Initializes the command mappings
func (scanner *Scanner) initCommands() error {
	scanner.commandMappings = map[string]string{
		"PING":        "PING",
		"AUTH":        "AUTH",
		"INFO":        "INFO",
		"NONEXISTENT": "NONEXISTENT",
		"QUIT":        "QUIT",
	}

	if scanner.config.CustomCommands != "" {
		var customCommands []string
		err := scanner.getFileContents(scanner.config.CustomCommands, &customCommands)
		if err != nil {
			return err
		}
		scanner.customCommands = customCommands
	}

	// User supplied a file for updated command mappings
	if scanner.config.Mappings != "" {
		var mappings map[string]string
		err := scanner.getFileContents(scanner.config.Mappings, &mappings)
		if err != nil {
			return err
		}
		for origCommand, newCommand := range mappings {
			scanner.commandMappings[strings.ToUpper(origCommand)] = strings.ToUpper(newCommand)
		}
	}

	return nil
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
	var (
		conn    net.Conn
		tlsConn *zgrab2.TLSConnection
		err     error
	)

	isSSL := false
	conn, err = target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return nil, err
	}

	if scanner.config.UseTLS {
		tlsConn, err = scanner.config.TLSFlags.GetTLSConnection(conn)
		if err != nil {
			return nil, err
		}
		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}
		conn = tlsConn
		isSSL = true
	} else {
		conn, err = target.Open(&scanner.config.BaseFlags)
	}

	if err != nil {
		return nil, err
	}

	return &scan{
		target:  target,
		scanner: scanner,
		result:  &Result{},
		conn: &Connection{
			scanner: scanner,
			isSSL:   isSSL,
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
func (scanner *Scanner) Protocol() string {
	return "redis"
}

// Converts the string to a Uint32 if possible. If not, returns 0 (the zero value of a uin32)
func convToUint32(s string) uint32 {
	s64, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(s64)
}

// Scan executes the following commands:
// 1. PING
// 2. (only if --password is provided) AUTH <password>
// 3. INFO
// 4. NONEXISTENT
// 5. (only if --custom-commands is provided) CustomCommands <args>
// 6. QUIT
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
	pingResponse, err := scan.SendCommand(scanner.commandMappings["PING"])
	if err != nil {
		// If the first command fails (as opposed to succeeding but returning an
		// ErrorMessage response), then flag the probe as having failed.
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	// From this point forward, we always return a non-nil result, implying that
	// we have positively identified that a redis service is present.
	result.PingResponse = forceToString(pingResponse)
	if scanner.config.Password != "" {
		authResponse, err := scan.SendCommand(scanner.commandMappings["AUTH"], scanner.config.Password)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		result.AuthResponse = forceToString(authResponse)
	}
	infoResponse, err := scan.SendCommand(scanner.commandMappings["INFO"])
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	result.InfoResponse = forceToString(infoResponse)
	if infoResponseBulk, ok := infoResponse.(BulkString); ok {
		for _, line := range strings.Split(string(infoResponseBulk), "\r\n") {
			linePrefixSuffix := strings.SplitN(line, ":", 2)
			prefix := linePrefixSuffix[0]
			var suffix string
			if len(linePrefixSuffix) > 1 {
				suffix = linePrefixSuffix[1]
			}
			switch prefix {
			case "redis_version":
				result.Version = suffix
				versionSegments := strings.SplitN(suffix, ".", 3)
				if len(versionSegments) > 0 {
					major := convToUint32(versionSegments[0])
					result.Major = &major
				}
				if len(versionSegments) > 1 {
					minor := convToUint32(versionSegments[1])
					result.Minor = &minor
				}
				if len(versionSegments) > 2 {
					patchlevel := convToUint32(versionSegments[2])
					result.Patchlevel = &patchlevel
				}
			case "os":
				result.OS = suffix
			case "arch_bits":
				result.ArchBits = suffix
			case "redis_mode":
				result.Mode = suffix
			case "redis_git_sha1":
				result.GitSha1 = suffix
			case "redis_build_id":
				result.BuildID = suffix
			case "gcc_version":
				result.GCCVersion = suffix
			case "mem_allocator":
				result.MemAllocator = suffix
			case "uptime_in_seconds":
				result.Uptime = convToUint32(suffix)
			case "used_memory":
				result.UsedMemory = convToUint32(suffix)
			case "total_connections_received":
				result.ConnectionsReceived = convToUint32(suffix)
			case "total_commands_processed":
				result.CommandsProcessed = convToUint32(suffix)
			}
		}
	}
	bogusResponse, err := scan.SendCommand(scanner.commandMappings["NONEXISTENT"])
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	result.NonexistentResponse = forceToString(bogusResponse)
	for i := range scanner.customCommands {
		fullCmd := strings.Fields(scanner.customCommands[i])
		resp, err := scan.SendCommand(fullCmd[0], fullCmd[1:]...)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		customResponse := CustomResponse{
			Command:   fullCmd[0],
			Arguments: strings.Join(fullCmd[1:], " "),
			Response:  forceToString(resp),
		}
		result.CustomResponses = append(result.CustomResponses, customResponse)
	}
	quitResponse, err := scan.SendCommand(scanner.commandMappings["QUIT"])
	if err != nil && err != io.EOF {
		return zgrab2.TryGetScanStatus(err), result, err
	} else if quitResponse == nil {
		quitResponse = NullValue
	}
	result.QuitResponse = forceToString(quitResponse)
	result.TLSLog = scan.conn.GetTLSLog()
	return zgrab2.SCAN_SUCCESS, &result, nil
}

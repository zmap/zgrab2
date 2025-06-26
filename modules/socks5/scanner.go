// Package socks5 contains the zgrab2 Module implementation for SOCKS5.
package socks5

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// ScanResults is the output of the scan.
type ScanResults struct {
	Version                       string            `json:"version,omitempty"`
	MethodSelection               string            `json:"method_selection,omitempty"`
	ConnectionResponse            string            `json:"connection_response,omitempty"`
	ConnectionResponseExplanation map[string]string `json:"connection_response_explanation,omitempty"`
}

// Flags are the SOCKS5-specific command-line flags.
type Flags struct {
	zgrab2.BaseFlags
	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface, and holds the state
// for a single scan.
type Scanner struct {
	config            *Flags
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

// Connection holds the state for a single connection to the SOCKS5 server.
type Connection struct {
	config  *Flags
	results ScanResults
	conn    net.Conn
}

// RegisterModule registers the socks5 zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("socks5", "Socket Secure Proxy (SOCKS5)", module.Description(), 1080, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns the default flags object to be filled in with the
// command-line arguments.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "Perform a SOCKS5 scan"
}

// Validate flags
func (f *Flags) Validate(_ []string) (err error) {
	return
}

// Help returns this module's help string.
func (f *Flags) Help() string {
	return ""
}

// Protocol returns the protocol identifier for the scanner.
func (s *Scanner) Protocol() string {
	return "socks5"
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

// Init initializes the Scanner instance with the flags from the command line.
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	s.config = f
	s.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

// InitPerSender does nothing in this module.
func (s *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the configured name for the Scanner.
func (s *Scanner) GetName() string {
	return s.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// readResponse reads a response from the SOCKS5 server.
func (conn *Connection) readResponse(expectedLength int) ([]byte, error) {
	resp := make([]byte, expectedLength)
	_, err := conn.conn.Read(resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// sendCommand sends a command to the SOCKS5 server.
func (conn *Connection) sendCommand(cmd []byte) error {
	_, err := conn.conn.Write(cmd)
	return err
}

// explainResponse converts the raw response into a human-readable explanation.
func explainResponse(resp []byte) map[string]string {
	if len(resp) < 10 {
		return map[string]string{"error": "response too short"}
	}

	return map[string]string{
		"Version":       fmt.Sprintf("0x%02x (SOCKS Version 5)", resp[0]),
		"Reply":         fmt.Sprintf("0x%02x (%s)", resp[1], getReplyDescription(resp[1])),
		"Reserved":      fmt.Sprintf("0x%02x", resp[2]),
		"Address Type":  fmt.Sprintf("0x%02x (%s)", resp[3], getAddressTypeDescription(resp[3])),
		"Bound Address": fmt.Sprintf("%d.%d.%d.%d", resp[4], resp[5], resp[6], resp[7]),
		"Bound Port":    strconv.Itoa(int(resp[8])<<8 | int(resp[9])),
	}
}

func getReplyDescription(code byte) string {
	switch code {
	case 0x00:
		return "succeeded"
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unassigned"
	}
}

func getAddressTypeDescription(code byte) string {
	switch code {
	case 0x01:
		return "IPv4 address"
	case 0x03:
		return "Domain name"
	case 0x04:
		return "IPv6 address"
	default:
		return "unknown"
	}
}

// PerformHandshake performs the SOCKS5 handshake.
func (conn *Connection) PerformHandshake() (bool, error) {
	// Send version identifier/method selection message
	verMethodSel := []byte{0x05, 0x01, 0x00} // VER = 0x05, NMETHODS = 1, METHODS = 0x00 (NO AUTHENTICATION REQUIRED)
	err := conn.sendCommand(verMethodSel)
	if err != nil {
		return false, fmt.Errorf("error sending version identifier/method selection: %w", err)
	}
	conn.results.Version = "0x05"

	// Read method selection response
	methodSelResp, err := conn.readResponse(2)
	if err != nil {
		return false, fmt.Errorf("error reading method selection response: %w", err)
	}
	conn.results.MethodSelection = hex.EncodeToString(methodSelResp)

	if methodSelResp[1] == 0xFF {
		return true, errors.New("no acceptable authentication methods")
	}

	return false, nil
}

// PerformConnectionRequest sends a connection request to the SOCKS5 server.
func (conn *Connection) PerformConnectionRequest() error {
	// Send a connection request
	req := []byte{0x05, 0x01, 0x00, 0x01, 0xA6, 0x6F, 0x04, 0x64, 0x00, 0x50} // VER = 0x05, CMD = CONNECT, RSV = 0x00, ATYP = IPv4, DST.ADDR = 166.111.4.100, DST.PORT = 80
	err := conn.sendCommand(req)
	if err != nil {
		return fmt.Errorf("error sending connection request: %w", err)
	}

	// Read connection response
	resp, err := conn.readResponse(10)
	if err != nil {
		return fmt.Errorf("error reading connection response: %w", err)
	}
	conn.results.ConnectionResponse = hex.EncodeToString(resp)
	conn.results.ConnectionResponseExplanation = explainResponse(resp)

	if resp[1] > 0x80 {
		return fmt.Errorf("connection request failed with response: %x", resp)
	}

	return nil
}

// Scan performs the configured scan on the SOCKS5 server.
func (s *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, t *zgrab2.ScanTarget) (status zgrab2.ScanStatus, result any, thrown error) {
	var have_auth bool
	conn, err := dialGroup.Dial(ctx, t)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error opening connection to %s: %w", t.String(), err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	results := ScanResults{}
	socks5Conn := Connection{conn: conn, config: s.config, results: results}

	have_auth, err = socks5Conn.PerformHandshake()
	if err != nil {
		if have_auth {
			return zgrab2.SCAN_SUCCESS, &socks5Conn.results, nil
		} else {
			return zgrab2.TryGetScanStatus(err), &socks5Conn.results, fmt.Errorf("error during handshake: %w", err)
		}
	}

	err = socks5Conn.PerformConnectionRequest()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &socks5Conn.results, fmt.Errorf("error during connection request: %w", err)
	}

	return zgrab2.SCAN_SUCCESS, &socks5Conn.results, nil
}

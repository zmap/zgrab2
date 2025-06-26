// Package pptp contains the zgrab2 Module implementation for PPTP.
package pptp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// ScanResults is the output of the scan.
type ScanResults struct {
	// Banner is the initial data banner sent by the server.
	Banner string `json:"banner,omitempty"`

	// ControlMessage is the received PPTP control message.
	ControlMessage string `json:"control_message,omitempty"`
}

// Flags are the PPTP-specific command-line flags.
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

// RegisterModule registers the pptp zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("pptp", "Point-to-Point Tunneling Protocol (PPTP)", module.Description(), 1723, &module)
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
	return "Scan for PPTP"
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
func (scanner *Scanner) Protocol() string {
	return "pptp"
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

// Init initializes the Scanner instance with the flags from the command line.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

// InitPerSender does nothing in this module.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the configured name for the Scanner.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// PPTP Start-Control-Connection-Request message constants
const (
	PPTP_MAGIC_COOKIE       = 0x1A2B3C4D
	PPTP_CONTROL_MESSAGE    = 1
	PPTP_START_CONN_REQUEST = 1
	PPTP_PROTOCOL_VERSION   = 0x0100 // Split into two 16-bit values for binary.BigEndian.PutUint16
)

// Connection holds the state for a single connection to the PPTP server.
type Connection struct {
	config  *Flags
	results ScanResults
	conn    net.Conn
}

// Create the Start-Control-Connection-Request message
func createSCCRMessage() []byte {
	message := make([]byte, 156)
	binary.BigEndian.PutUint16(message[0:2], 156)                                    // Length
	binary.BigEndian.PutUint16(message[2:4], PPTP_CONTROL_MESSAGE)                   // PPTP Message Type
	binary.BigEndian.PutUint32(message[4:8], PPTP_MAGIC_COOKIE)                      // Magic Cookie
	binary.BigEndian.PutUint16(message[8:10], PPTP_START_CONN_REQUEST)               // Control Message Type
	binary.BigEndian.PutUint16(message[10:12], uint16(PPTP_PROTOCOL_VERSION>>16))    // Protocol Version (high 16 bits)
	binary.BigEndian.PutUint16(message[12:14], uint16(PPTP_PROTOCOL_VERSION&0xFFFF)) // Protocol Version (low 16 bits)
	binary.BigEndian.PutUint32(message[14:18], 0)                                    // Framing Capabilities
	binary.BigEndian.PutUint32(message[18:22], 0)                                    // Bearer Capabilities
	binary.BigEndian.PutUint16(message[22:24], 0)                                    // Maximum Channels
	binary.BigEndian.PutUint16(message[24:26], 0)                                    // Firmware Revision
	copy(message[26:90], "ZGRAB2-SCANNER")                                           // Host Name
	copy(message[90:], "ZGRAB2")                                                     // Vendor Name
	return message
}

// Read response from the PPTP server
func (pptp *Connection) readResponse() (string, error) {
	buffer := make([]byte, 1024)
	if err := pptp.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return "", fmt.Errorf("could not set read deadline: %w", err)
	}
	n, err := pptp.conn.Read(buffer)
	if err != nil {
		return "", err
	}
	return string(buffer[:n]), nil
}

// Scan performs the configured scan on the PPTP server
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, t *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	var err error
	conn, err := dialGroup.Dial(ctx, t)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error opening connection to target %s: %w", t.String(), err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	results := ScanResults{}

	pptp := Connection{conn: conn, config: scanner.config, results: results}

	// Send Start-Control-Connection-Request message
	request := createSCCRMessage()
	_, err = pptp.conn.Write(request)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &pptp.results, fmt.Errorf("error sending PPTP SCCR message to target %s: %w", t.String(), err)
	}

	// Read the response
	response, err := pptp.readResponse()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &pptp.results, fmt.Errorf("error reading PPTP response from target %s: %w", t.String(), err)
	}

	// Store the banner and control message
	pptp.results.Banner = string(request)
	pptp.results.ControlMessage = response

	return zgrab2.SCAN_SUCCESS, &pptp.results, nil
}

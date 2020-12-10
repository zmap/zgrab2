// Package checkpoint contains the zgrab2 Module implementation for checkpoint
//
// The output is the banner, any responses to the AUTH TLS/AUTH SSL commands,
// and any TLS logs.
package checkpoint

import (
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// ScanResults is the output of the scan.
// Identical to the original from zgrab, with the addition of TLSLog.
type ScanResults struct {
    // Firewall Host CN=
	FirewallHost string `json:"firewall_host,omitempty"`
    // Host : 0=
	Host string `json:"host,omitempty"`
}

// Flags
type Flags struct {
	zgrab2.BaseFlags

	Verbose     bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface, and holds the state
// for a single scan.
type Scanner struct {
	config *Flags
}

// Connection holds the state for a single connection to the FTP server.
type Connection struct {
	config  *Flags
	results ScanResults
	conn    net.Conn
}

// RegisterModule registers the checkpoint zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("checkpoint", "CHECKPOINT", module.Description(), 264, &module)
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
	return "Get the Checkpoint Admin interface hostname"
}

// Validate flags
func (f *Flags) Validate(args []string) (err error) {
	return nil
}

// Help returns this module's help string.
func (f *Flags) Help() string {
	return ""
}

// Protocol returns the protocol identifer for the scanner.
func (s *Scanner) Protocol() string {
	return "checkpoint"
}

// Init initializes the Scanner instance with the flags from the command
// line.
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	s.config = f
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

// Send the first header
func (cnx *Connection)sendHeader1() ([]byte, error) {
    _, err := cnx.conn.Write([]byte("\x51\x00\x00\x00\x00\x00\x00\x21"))
    if err != nil {
        return nil, err
    }
    responseBytes, err := zgrab2.ReadAvailable(cnx.conn)
    if err != nil {
        return nil, err
    }
    return responseBytes, nil
}

// Send the first header
func (cnx *Connection)sendHeader2() ([]byte, error) {
    _, err := cnx.conn.Write([]byte("\x00\x00\x00\x0bsecuremote\x00"))
    if err != nil {
        return nil, err
    }
    responseBytes, err := zgrab2.ReadAvailable(cnx.conn)
    if err != nil {
        return nil, err
    }
    return responseBytes, nil
}

func (cnx *Connection)decodeAnswer(answer []byte) {
    if (len(answer) > 12) {
        ret := string(answer[4:len(answer)-8])
        s := strings.Split(ret, ",")
        if len(s) == 2 {
            cnx.results.FirewallHost = s[0][3:]
            cnx.results.Host = s[1][2:]
        }
    }
}

// Scan connects to port 264
// * Send a first header
// * If the answer if indeed from checkpoint, sends a second header
// * Grab the hostname returned
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (status zgrab2.ScanStatus, result interface{}, thrown error) {
	var err error
	conn, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
    defer conn.Close()

	results := ScanResults{}

	cnx := Connection{conn: conn, config: scanner.config, results: results}
    _, err = cnx.sendHeader1()
    if err != nil {
		return zgrab2.TryGetScanStatus(err), &cnx.results, err
    }
    answer, err := cnx.sendHeader2()
    if err != nil {
		return zgrab2.TryGetScanStatus(err), &cnx.results, err
    }
    cnx.decodeAnswer(answer)

	return zgrab2.SCAN_SUCCESS, &cnx.results, nil
}

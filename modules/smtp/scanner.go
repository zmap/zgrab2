// Package smtp provides a zgrab2 module that scans for smtp.
// TODO: Describe module, the flags, the probe, the output, etc.
package smtp

import (
	"errors"
	"fmt"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// ErrInvalidResponse is returned when the server returns an invalid or unexpected response.
var ErrInvalidResponse = errors.New("invalid response")

// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	// Banner is the string sent by the server immediately after connecting.
	Banner string `json:"banner,omitempty"`

	// EHLO is the server's response to the EHLO command, if one is sent.
	EHLO string `json:"ehlo,omitempty"`

	// SMTPHelp is the server's response to the HELP command, if it is sent.
	SMTPHelp string `json:"smtp_help,omitempty"`

	// StartTLS is the server's response to the STARTTLS command, if it is sent.
	StartTLS string `json:"starttls,omitempty"`

	// TLSLog is the standard TLS log, if STARTTLS is sent.
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Flags holds the command-line configuration for the HTTP scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags

	// TODO: HELO?

	// EHLODomain is the domain the client should send in the EHLO command. If omitted, no EHLO is sent.
	// TODO: Allow sending the scan machine's IP?
	EHLODomain string `long:"ehlo" description:"Send the EHLO, using the given domain"`

	// SMTPHelp indicates that the client should send the HELP command after EHLO.
	SMTPHelp bool `long:"smtp-help" description:"Send the HELP command"`

	// StartTLS indicates that the client should attempt to update the connection to TLS.
	StartTLS bool `long:"starttls" description:"Send STARTTLS before negotiating"`

	// Verbose indicates that there should be more verbose logging.
	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("smtp", "smtp", "Probe for smtp", 25, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object.
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string.
func (flags *Flags) Help() string {
	return ""
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	return nil
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "smtp"
}

// GetPort returns the port being scanned.
func (scanner *Scanner) GetPort() uint {
	return scanner.config.Port
}

func getSMTPCode(response string) (int, error) {
	if len(response) < 5 {
		return 0, ErrInvalidResponse
	}
	ret, err := strconv.Atoi(response[0:3])
	if err != nil {
		return 0, ErrInvalidResponse
	}
	return ret, nil
}

// Scan performs the SMTP scan.
// 1. Open a TCP connection to the target port (default 25).
// 2. Read the banner.
// 3. If --ehlo <domain> is sent, send EHLO <domain>, read the result.
// 4. If --smtp-help is sent, send HELP, read the result.
// 5. If --starttls is sent, send STARTTLS, read the result, negotiate a TLS connection.
// 6. Send QUIT, read the result.
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	c, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	conn := Connection{Conn: c}
	banner, err := conn.ReadResponse()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	result := &ScanResults{}
	result.Banner = banner
	if scanner.config.EHLODomain != "" {
		ret, err := conn.SendCommand("EHLO " + scanner.config.EHLODomain)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		result.EHLO = ret
	}
	if scanner.config.SMTPHelp {
		ret, err := conn.SendCommand("HELP")
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		result.SMTPHelp = ret
	}
	if scanner.config.StartTLS {
		ret, err := conn.SendCommand("STARTTLS")
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		result.StartTLS = ret
		code, err := getSMTPCode(ret)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		if code < 200 || code >= 300 {
			return zgrab2.SCAN_APPLICATION_ERROR, result, fmt.Errorf("SMTP error code %d returned from STARTTLS command (%s)", code, ret)
		}
		tlsConn, err := scanner.config.TLSFlags.GetTLSConnection(conn.Conn)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		result.TLSLog = tlsConn.GetLog()
		if err := tlsConn.Handshake(); err != nil {
			return zgrab2.TryGetScanStatus(err), result, err
		}
		conn.Conn = tlsConn
	}
	ret, err := conn.SendCommand("QUIT")
	if err != nil {
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, err
		}
	}
	result.SMTPHelp = ret
	return zgrab2.SCAN_SUCCESS, result, nil
}

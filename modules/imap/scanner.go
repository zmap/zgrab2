// Package imap provides a zgrab2 module that scans for IMAP mail
// servers.
// Default Port: 143 (TCP)
//
// The --imaps flag tells the scanner to perform a TLS handshake
// immediately after connecting, before even attempting to read
// the banner.
// The --starttls flag tells the scanner to send the STARTTLS
// command and then negotiate a TLS connection.
// The scanner uses the standard TLS flags for the handshake.
// --imaps and --starttls are mutually exclusive.
// --imaps does not change the default port number from 143, so
// it should usually be coupled with e.g. --port 993.
//
// The --send-close flag tells the scanner to send a CLOSE command
// before disconnecting.
//
// So, if no flags are specified, the scanner simply reads the banner
// returned by the server and disconnects.
//
// The output contains the banner and the responses to any commands that
// were sent, and if or --imaps --starttls were set, the standard TLS logs.
package imap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	// Banner is the string sent by the server immediately after connecting.
	Banner string `json:"banner,omitempty"`

	// StartTLS is the server's response to the STARTTLS command, if it is sent.
	StartTLS string `json:"starttls,omitempty"`

	// CLOSE is the server's response to the CLOSE command, if it is sent.
	CLOSE string `json:"close,omitempty"`

	// TLSLog is the standard TLS log, if --starttls or --imaps is enabled.
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Flags holds the command-line configuration for the IMAP scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	// SendCLOSE indicates that the CLOSE command should be sent.
	SendCLOSE bool `long:"send-close" description:"Send the CLOSE command before closing."`

	// IMAPSecure indicates that the client should do a TLS handshake immediately after connecting.
	IMAPSecure bool `long:"imaps" description:"Immediately negotiate a TLS connection"`

	// StartTLS indicates that the client should attempt to update the connection to TLS.
	StartTLS bool `long:"starttls" description:"Send STLS before negotiating"`

	// Verbose indicates that there should be more verbose logging.
	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config            *Flags
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("imap", "Internet Message Access Protocol (IMAP)", module.Description(), 143, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object.
func (module *Module) NewFlags() any {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Fetch an IMAP banner, optionally over TLS"
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(_ []string) error {
	if flags.StartTLS && flags.IMAPSecure {
		log.Error("Cannot send both --starttls and --imaps")
		return zgrab2.ErrInvalidArguments
	}
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
	scanner.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		NeedSeparateL4Dialer:            true,
		BaseFlags:                       &f.BaseFlags,
		TLSEnabled:                      true,
		TLSFlags:                        &f.TLSFlags,
	}
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

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "imap"
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

func getIMAPError(response string) error {
	if strings.HasPrefix(response, "a001 OK") {
		return nil
	}
	return fmt.Errorf("error: %s", response)
}

// Check the contents of the IMAP banner and return a relevant ScanStatus
func VerifyIMAPContents(banner string) zgrab2.ScanStatus {
	lowerBanner := strings.ToLower(banner)
	switch {
	case strings.HasPrefix(banner, "* NO"),
		strings.HasPrefix(banner, "* BAD"):
		return zgrab2.SCAN_APPLICATION_ERROR
	case strings.HasPrefix(banner, "* OK"),
		strings.HasPrefix(banner, "* PREAUTH"),
		strings.HasPrefix(banner, "* BYE"),
		strings.HasPrefix(banner, "* OKAY"),
		strings.Contains(banner, "IMAP"),
		strings.Contains(lowerBanner, "blacklist"),
		strings.Contains(lowerBanner, "abuse"),
		strings.Contains(lowerBanner, "rbl"),
		strings.Contains(lowerBanner, "spamhaus"),
		strings.Contains(lowerBanner, "relay"):
		return zgrab2.SCAN_SUCCESS
	default:
		return zgrab2.SCAN_PROTOCOL_ERROR
	}
}

// Scan performs the IMAP scan.
//  1. Open a TCP connection to the target port (default 143).
//  2. If --imaps is set, perform a TLS handshake using the command-line
//     flags.
//  3. Read the banner.
//  6. If --starttls is sent, send a001 STARTTLS, read the result, negotiate a
//     TLS connection using the command-line flags.
//  7. If --send-close is sent, send a001 CLOSE and read the result.
//  8. Close the connection.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))
	l4Dialer := dialGroup.L4Dialer
	if l4Dialer == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no L4Dialer set")
	}
	if (scanner.config.IMAPSecure || scanner.config.StartTLS) && dialGroup.TLSWrapper == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("TLS wrapper required in dialer group for IMAPSecure or STARTTLS")
	}
	c, err := l4Dialer(target)(ctx, "tcp", addr)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer zgrab2.CloseConnAndHandleError(c)
	result := &ScanResults{}
	if scanner.config.IMAPSecure {
		var tlsConn *zgrab2.TLSConnection
		tlsConn, err = dialGroup.TLSWrapper(ctx, target, c)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error wrapping TLS connection for target %s: %w", target.String(), err)
		}
		result.TLSLog = tlsConn.GetLog()
		c = tlsConn
	}
	conn := Connection{Conn: c}
	banner, err := conn.ReadResponse()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	// Quit early if we didn't get a valid response
	// OR save a valid scan result for later
	sr := VerifyIMAPContents(banner)
	if sr == zgrab2.SCAN_PROTOCOL_ERROR {
		return sr, nil, errors.New("invalid response for IMAP")
	}
	result.Banner = banner
	var ret string
	if scanner.config.StartTLS {
		ret, err = conn.SendCommand("a001 STARTTLS")
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("error sending STLS command for IMAP %s: %w", target.String(), err)
		}
		result.StartTLS = ret
		if err = getIMAPError(ret); err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("error in response to STLS command for IMAP %s: %w", target.String(), err)
		}
		tlsConn, err := dialGroup.TLSWrapper(ctx, target, c)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error wrapping TLS connection for target %s: %w", target.String(), err)
		}
		result.TLSLog = tlsConn.GetLog()
		conn.Conn = tlsConn
	}
	if scanner.config.SendCLOSE {
		ret, err := conn.SendCommand("a001 CLOSE")
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error sending CLOSE command for IMAP %s: %w", target.String(), err)
		}
		result.CLOSE = ret
	}
	return sr, result, nil
}

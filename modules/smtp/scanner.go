// Package smtp provides a zgrab2 module that scans for SMTP mail
// servers.
// Default Port: 25 (TCP)
//
// The --smtps command tells the scanner to wrap the entire connection
// in a TLS session.
//
// The --send-ehlo and --send-helo flags tell the scanner to first send
// the EHLO/HELO command; if a --ehlo-domain or --helo-domain is present
// that domain will be used, otherwise it is omitted.
// The EHLO and HELO flags are mutually exclusive.
//
// The --send-help flag tells the scanner to send a HELP command.
//
// The --starttls flag tells the scanner to send the STARTTLS command,
// and then negotiate a TLS connection.
// The scanner uses the standard TLS flags for the handshake.
//
// The --send-quit flag tells the scanner to send a QUIT command.
//
// So, if no flags are specified, the scanner simply reads the banner
// returned by the server and disconnects.
//
// The output contains the banner and the responses to any commands that
// were sent, and if --starttls or --smtps was sent, the standard TLS logs.
package smtp

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

// ErrInvalidResponse is returned when the server returns an invalid or unexpected response.
var ErrInvalidResponse = zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, errors.New("Invalid response for SMTP"))

// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	// Banner is the string sent by the server immediately after connecting.
	Banner string `json:"banner,omitempty"`

	// HELO is the server's response to the HELO command, if one is sent.
	HELO string `json:"helo,omitempty"`

	// EHLO is the server's response to the EHLO command, if one is sent.
	EHLO string `json:"ehlo,omitempty"`

	// HELP is the server's response to the HELP command, if it is sent.
	HELP string `json:"help,omitempty"`

	// StartTLS is the server's response to the STARTTLS command, if it is sent.
	StartTLS string `json:"starttls,omitempty"`

	// QUIT is the server's response to the QUIT command, if it is sent.
	QUIT string `json:"quit,omitempty"`

	// ImplicitTLS is true if the connection was wrapped in TLS, as opposed
	// to using StartTls
	ImplicitTLS bool `json:"implicit_tls,omitempty"`

	// TLSLog is the standard TLS log, if STARTTLS is sent.
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Flags holds the command-line configuration for the HTTP scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	// SendEHLO indicates that the EHLO command should be set.
	SendEHLO bool `long:"send-ehlo" description:"Send the EHLO command; use --ehlo-domain to set a domain."`

	// SendHELO indicates that the HELO command should be set.
	SendHELO bool `long:"send-helo" description:"Send the HELO command; use --helo-domain to set a domain."`

	// SendHELP indicates that the client should send the HELP command (after HELO/EHLO).
	SendHELP bool `long:"send-help" description:"Send the HELP command"`

	// SendQUIT indicates that the QUIT command should be set.
	SendQUIT bool `long:"send-quit" description:"Send the QUIT command before closing."`

	// HELODomain is the domain the client should send in the HELO command.
	HELODomain string `long:"helo-domain" description:"Set the domain to use with the HELO command. Implies --send-helo."`

	// EHLODomain is the domain the client should send in the EHLO command.
	EHLODomain string `long:"ehlo-domain" description:"Set the domain to use with the EHLO command. Implies --send-ehlo."`

	// SMTPSecure indicates that the entire transaction should be wrapped in a TLS session.
	SMTPSecure bool `long:"smtps" description:"Perform a TLS handshake immediately upon connecting."`

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
	config             *Flags
	defaultDialerGroup *zgrab2.DialerGroup
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("smtp", "smtp", module.Description(), 25, &module)
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
	return "Fetch an SMTP server banner, optionally over TLS"
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate() error {
	if flags.StartTLS && flags.SMTPSecure {
		log.Errorln("Cannot specify both --smtps and --starttls")
		return zgrab2.ErrInvalidArguments
	}
	if flags.EHLODomain != "" {
		flags.SendEHLO = true
	}
	if flags.HELODomain != "" {
		flags.SendHELO = true
	}
	if flags.SendHELO && flags.SendEHLO {
		log.Errorln("Cannot provide both EHLO and HELO")
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
	scanner.defaultDialerGroup = new(zgrab2.DialerGroup)
	scanner.defaultDialerGroup.L4Dialer = func(scanTarget *zgrab2.ScanTarget) func(ctx context.Context, network, address string) (net.Conn, error) {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return zgrab2.DialTimeoutConnection(ctx, network, address, f.BaseFlags.Timeout, f.BaseFlags.BytesReadLimit)
		}
	}
	scanner.defaultDialerGroup.TLSWrapper = zgrab2.GetDefaultTLSWrapper(&f.TLSFlags)
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
	return "smtp"
}

func (scanner *Scanner) GetDefaultDialerGroup() *zgrab2.DialerGroup {
	return scanner.defaultDialerGroup
}

func (scanner *Scanner) GetDefaultPort() uint {
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

// Get a command with an optional argument (so if the argument is absent, there is no trailing space)
func getCommand(cmd string, arg string) string {
	if arg == "" {
		return cmd
	}
	return cmd + " " + arg
}

// Verify that an SMTP code was returned, and that it is a successful one!
// Return code on SCAN_APPLICATION_ERROR for better info
func VerifySMTPContents(banner string) (zgrab2.ScanStatus, int) {
	code, err := getSMTPCode(banner)
	lowerBanner := strings.ToLower(banner)
	switch {
	case err == nil && (code < 200 || code >= 300):
		return zgrab2.SCAN_APPLICATION_ERROR, code
	case err == nil,
		strings.Contains(banner, "SMTP"),
		strings.Contains(lowerBanner, "blacklist"),
		strings.Contains(lowerBanner, "abuse"),
		strings.Contains(lowerBanner, "rbl"),
		strings.Contains(lowerBanner, "spamhaus"),
		strings.Contains(lowerBanner, "relay"):
		return zgrab2.SCAN_SUCCESS, 0
	default:
		return zgrab2.SCAN_PROTOCOL_ERROR, 0
	}
}

// Scan performs the SMTP scan.
//  1. Open a TCP connection to the target port (default 25).
//  2. If --smtps is set, perform a TLS handshake.
//  3. Read the banner.
//  4. If --send-ehlo or --send-helo is sent, send the corresponding EHLO
//     or HELO command.
//  5. If --send-help is sent, send HELP, read the result.
//  6. If --starttls is sent, send STARTTLS, read the result, negotiate a
//     TLS connection.
//  7. If --send-quit is sent, send QUIT and read the result.
//  8. Close the connection.
func (scanner *Scanner) Scan(ctx context.Context, target *zgrab2.ScanTarget, dialer *zgrab2.DialerGroup) (zgrab2.ScanStatus, any, error) {
	l4Dialer := dialer.GetL4Dialer()
	if l4Dialer == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no L4 dialer found. SMTP requires a L4 dialer")
	}
	conn, err := l4Dialer(target)(ctx, "tcp", net.JoinHostPort(target.Host(), strconv.FormatUint(uint64(target.Port), 10)))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer zgrab2.CloseConnAndHandleError(conn)
	result := &ScanResults{}
	if scanner.config.SMTPSecure {
		tlsWrapper := dialer.GetTLSWrapper()
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no TLS wrapper found. SMTP with SMTPSecure requires a TLS wrapper")
		}
		var tlsConn *zgrab2.TLSConnection
		tlsConn, err = tlsWrapper(ctx, target, conn)
		if err != nil {
			return zgrab2.SCAN_HANDSHAKE_ERROR, nil, fmt.Errorf("could not initiate a TLS connection to target %v: %v", target, err)
		}
		result.TLSLog = tlsConn.GetLog()
		result.ImplicitTLS = true
		conn = tlsConn
	}
	smtpConn := Connection{Conn: conn}
	banner, err := smtpConn.ReadResponse()
	if err != nil {
		if !scanner.config.SMTPSecure {
			result = nil
		}
		return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not read response from %s: %v", target.String(), err)
	}
	// Quit early if we didn't get a valid response
	// OR save response to return later
	sr, bannerResponseCode := VerifySMTPContents(banner)
	if sr == zgrab2.SCAN_PROTOCOL_ERROR {
		return sr, nil, errors.New("invalid response for SMTP")
	}
	result.Banner = banner
	if scanner.config.SendHELO {
		ret, err := smtpConn.SendCommand(getCommand("HELO", scanner.config.HELODomain))
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not send HELO command to target %s: %v", target.String(), err)
		}
		result.HELO = ret
	}
	if scanner.config.SendEHLO {
		ret, err := smtpConn.SendCommand(getCommand("EHLO", scanner.config.EHLODomain))
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not send EHLO command to target %s: %v", target.String(), err)
		}
		result.EHLO = ret
	}
	if scanner.config.SendHELP {
		ret, err := smtpConn.SendCommand("HELP")
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not send HELP command to target %s: %v", target.String(), err)
		}
		result.HELP = ret
	}
	if scanner.config.StartTLS {
		ret, err := smtpConn.SendCommand("STARTTLS")
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not send STARTTLS request to %s: %v", target.String(), err)
		}
		result.StartTLS = ret
		code, err := getSMTPCode(ret)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not get SMTP STARTTLS code for %s: %v", target.String(), err)
		}
		if code < 200 || code >= 300 {
			return zgrab2.SCAN_APPLICATION_ERROR, result, fmt.Errorf("SMTP error code %d returned from STARTTLS command (%s) for target %s", code, strings.TrimSpace(ret), target.String())
		}
		tlsWrapper := dialer.GetTLSWrapper()
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("no TLS wrapper found. SMTP with SMTPSecure requires a TLS wrapper")
		}
		tlsConn, err := tlsWrapper(ctx, target, smtpConn.Conn)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), result, fmt.Errorf("could not initiate a TLS connection to target %s: %v", target.String(), err)
		}
		result.TLSLog = tlsConn.GetLog()
		smtpConn.Conn = tlsConn
	}
	if scanner.config.SendQUIT {
		ret, err := smtpConn.SendCommand("QUIT")
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("failed to send QUIT command for SMTP %s: %v", target.String(), err)
		}
		result.QUIT = ret
	}
	if sr == zgrab2.SCAN_APPLICATION_ERROR {
		return sr, result, fmt.Errorf("SMTP error code %d returned in banner grab for target %s", bannerResponseCode, target.String())
	}
	return sr, result, nil
}

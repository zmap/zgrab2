// Package ftp contains the zgrab2 Module implementation for FTP(S).
//
// Setting the --authtls flag will cause the scanner to attempt a upgrade the
// connection to TLS. Settings for the TLS handshake / probe can be set with
// the standard TLSFlags.
//
// The scan performs a banner grab and (optionally) a TLS handshake.
//
// The output is the banner, any responses to the AUTH TLS/AUTH SSL commands,
// and any TLS logs.
package ftp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// ScanResults is the output of the scan.
// Identical to the original from zgrab, with the addition of TLSLog.
type ScanResults struct {
	// Banner is the initial data banner sent by the server.
	Banner string `json:"banner,omitempty"`

	// AuthTLSResp is the response to the AUTH TLS command.
	// Only present if the FTPAuthTLS flag is set.
	AuthTLSResp string `json:"auth_tls,omitempty"`

	// AuthSSLResp is the response to the AUTH SSL command.
	// Only present if the FTPAuthTLS flag is set and AUTH TLS failed.
	AuthSSLResp string `json:"auth_ssl,omitempty"`

	// ImplicitTLS is true if the connection is wrapped in TLS, as opposed
	// to via AUTH TLS or AUTH SSL.
	ImplicitTLS bool `json:"implicit_tls,omitempty"`

	// TLSLog is the standard shared TLS handshake log.
	// Only present if the FTPAuthTLS flag is set.
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Flags are the FTP-specific command-line flags. Taken from the original zgrab.
// (TODO: should FTPAuthTLS be on by default?).
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	Verbose     bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
	FTPAuthTLS  bool `long:"authtls" description:"Collect FTPS certificates in addition to FTP banners"`
	ImplicitTLS bool `long:"implicit-tls" description:"Attempt to connect via a TLS wrapped connection"`
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

// Connection holds the state for a single connection to the FTP server.
type Connection struct {
	// buffer is a temporary buffer for sending commands -- so, never interleave
	// sendCommand calls on a given connection
	buffer  [10000]byte
	config  *Flags
	results ScanResults
	conn    net.Conn
}

// RegisterModule registers the ftp zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("ftp", "File Transfer Protocol (FTP)", module.Description(), 21, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns the default flags object to be filled in with the
// command-line arguments.
func (m *Module) NewFlags() any {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "Grab an FTP banner"
}

// Validate flags
func (f *Flags) Validate(_ []string) (err error) {
	if f.FTPAuthTLS && f.ImplicitTLS {
		err = errors.New("cannot specify both '--authtls' and '--implicit-tls' together")
	}
	return
}

// Help returns this module's help string.
func (f *Flags) Help() string {
	return ""
}

// Protocol returns the protocol identifer for the scanner.
func (scanner *Scanner) Protocol() string {
	return "ftp"
}

// Init initializes the Scanner instance with the flags from the command line.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		NeedSeparateL4Dialer:            true,
		BaseFlags:                       &f.BaseFlags,
		TLSEnabled:                      f.FTPAuthTLS || f.ImplicitTLS,
		TLSFlags:                        &f.TLSFlags,
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

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

// ftpEndRegex matches zero or more lines followed by a numeric FTP status code
// and linebreak, e.g. "200 OK\r\n"
var ftpEndRegex = regexp.MustCompile(`^(?:.*\r?\n)*([0-9]{3})( [^\r\n]*)?\r?\n$`)

// isOKResponse returns true iff and only if the given response code indicates
// success (e.g. 2XX)
func (ftp *Connection) isOKResponse(retCode string) bool {
	// TODO: This is the current behavior; should it check that it isn't
	// garbage that happens to start with 2 (e.g. it's only ASCII chars, the
	// prefix is 2[0-9]+, etc)?
	return strings.HasPrefix(retCode, "2")
}

// readResponse reads an FTP response chunk from the server.
// It returns the full response, as well as the status code alone.
func (ftp *Connection) readResponse() (string, string, error) {
	respLen, err := zgrab2.ReadUntilRegex(ftp.conn, ftp.buffer[:], ftpEndRegex)
	if err != nil {
		return "", "", err
	}
	ret := string(ftp.buffer[0:respLen])
	retCode := ftpEndRegex.FindStringSubmatch(ret)[1]
	return ret, retCode, nil
}

// GetFTPBanner reads the data sent by the server immediately after connecting.
// Returns true if and only if the server returns a success status code.
// Taken over from the original zgrab.
func (ftp *Connection) GetFTPBanner() (bool, error) {
	banner, retCode, err := ftp.readResponse()
	if err != nil {
		return false, err
	}
	ftp.results.Banner = banner
	return ftp.isOKResponse(retCode), nil
}

// sendCommand sends a command and waits for / reads / returns the response.
func (ftp *Connection) sendCommand(cmd string) (string, string, error) {
	if n, err := ftp.conn.Write([]byte(cmd + "\r\n")); err != nil {
		return "", "", fmt.Errorf("error when writing command %q after %d bytes: %w", cmd, n, err)
	}
	return ftp.readResponse()
}

// SetupFTPS returns true if and only if the server reported support for FTPS.
// First attempt AUTH TLS; if that fails, try AUTH SSL.
// Taken over from the original zgrab.
func (ftp *Connection) SetupFTPS() (bool, error) {
	ret, retCode, err := ftp.sendCommand("AUTH TLS")
	if err != nil {
		return false, err
	}
	ftp.results.AuthTLSResp = ret
	if ftp.isOKResponse(retCode) {
		return true, nil
	}
	ret, retCode, err = ftp.sendCommand("AUTH SSL")
	if err != nil {
		return false, err
	}
	ftp.results.AuthSSLResp = ret

	if ftp.isOKResponse(retCode) {
		return true, nil
	}
	return false, nil
}

// GetFTPSCertificates attempts to perform a TLS handshake with the server so
// that the TLS certificates will end up in the TLSLog.
// First sends the AUTH TLS/AUTH SSL command to tell the server we want to
// do a TLS handshake. If that fails, break. Otherwise, perform the handshake.
// Taken over from the original zgrab.
func (ftp *Connection) GetFTPSCertificates(ctx context.Context, target *zgrab2.ScanTarget, tlsWrapper func(ctx context.Context, target *zgrab2.ScanTarget, l4Conn net.Conn) (*zgrab2.TLSConnection, error)) error {
	ftpsReady, err := ftp.SetupFTPS()

	if err != nil {
		return fmt.Errorf("error setting up FTPS: %w", err)
	}
	if !ftpsReady {
		return nil
	}
	var conn *zgrab2.TLSConnection
	if conn, err = tlsWrapper(ctx, target, ftp.conn); err != nil {
		return fmt.Errorf("error setting up TLS connection to target %s: %w", target.String(), err)
	}
	ftp.results.TLSLog = conn.GetLog()

	ftp.conn = conn
	return nil
}

// Scan performs the configured scan on the FTP server, as follows:
//   - Read the banner into results.Banner (if it is not a 2XX response, bail)
//   - If the FTPAuthTLS flag is not set, finish.
//   - Send the AUTH TLS command to the server. If the response is not 2XX, then
//     send the AUTH SSL command. If the response is not 2XX, then finish.
//   - Perform ths TLS handshake / any configured TLS scans, populating
//     results.TLSLog.
//   - Return SCAN_SUCCESS, &results, nil
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, t *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	var err error
	if dialGroup.L4Dialer == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("l4 dialer is required for FTP")
	}
	if (scanner.config.FTPAuthTLS || scanner.config.ImplicitTLS) && dialGroup.TLSWrapper == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("must specify a TLS wrapper for FTPS")
	}
	conn, err := dialGroup.L4Dialer(t)(ctx, "tcp", net.JoinHostPort(t.Host(), strconv.Itoa(int(t.Port))))
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error opening connection to target %v: %w", t.String(), err)
	}
	if scanner.config.ImplicitTLS {
		tlsWrapper := dialGroup.TLSWrapper
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("TLS wrapper is required for implicit TLS")
		}
		conn, err = tlsWrapper(ctx, t, conn)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error wrapping connection in TLS for target %s: %w", t.String(), err)
		}
	}
	results := ScanResults{
		ImplicitTLS: scanner.config.ImplicitTLS,
	}
	defer func() {
		// Check if we have a TLS conn and grab the log
		if tlsConn, ok := conn.(*zgrab2.TLSConnection); ok {
			results.TLSLog = tlsConn.GetLog()
		}
		// cleanup conn
		zgrab2.CloseConnAndHandleError(conn)
	}()
	ftp := Connection{conn: conn, config: scanner.config, results: results}
	is200Banner, err := ftp.GetFTPBanner()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &ftp.results, fmt.Errorf("error reading FTP banner for target %s: %w", t.String(), err)
	}
	if scanner.config.FTPAuthTLS && is200Banner {
		tlsWrapper := dialGroup.TLSWrapper
		if tlsWrapper == nil {
			return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("TLS wrapper is required for FTPS")
		}
		if err := ftp.GetFTPSCertificates(ctx, t, tlsWrapper); err != nil {
			return zgrab2.TryGetScanStatus(err), &ftp.results, fmt.Errorf("error getting FTPS certificates for target %s: %w", t.String(), err)
		}
	}
	return zgrab2.SCAN_SUCCESS, &ftp.results, nil
}

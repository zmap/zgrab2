// Package telnet provides a zgrab2 module that scans for telnet daemons.
// Default Port: 23 (TCP)
//
// The --max-read-size flag allows setting a ceiling to the number of bytes
// that will be read for the banner.
//
// The scan negotiates the options and attempts to grab the banner, using the
// same behavior as the original zgrab.
//
// The output contains the banner and the negotiated options, in the same
// format as the original zgrab.
package telnet

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the Telnet scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	MaxReadSize       int  `long:"max-read-size" description:"Set the maximum number of bytes to read when grabbing the banner" default:"65536"`
	Banner            bool `long:"force-banner" description:"Always return banner if it has non-zero bytes"`
	UseTLS            bool `long:"tls" description:"Sends probe with TLS connection. Loads TLS module command options."`
	AllowTLSDowngrade bool `long:"allow-tls-downgrade" description:"If --tls is enabled and the TLS handshake fails, fall back to plaintext instead of aborting. Requires --tls."`
}

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner]("telnet", "Telnet Remote Terminal Communication (Telnet)", "Fetch a telnet banner", 23)
}

func (f Flags) Validate(_ []string) error {
	if f.AllowTLSDowngrade && !f.UseTLS {
		log.Fatal("--allow-tls-downgrade requires --tls")
		return zgrab2.ErrInvalidArguments
	}
	return nil
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.SetBaseFlags(&f.BaseFlags)
	scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
		TLSEnabled:                      f.UseTLS,
		NeedSeparateL4Dialer:            f.AllowTLSDowngrade,
	}
	if f.UseTLS {
		scanner.DialerGroupConfig.TLSFlags = &f.TLSFlags
	}
	return nil
}

// Scan connects to the target (default port TCP 23) and attempts to grab the Telnet banner.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {

	var (
		conn net.Conn
		err  error
	)

	result := new(TelnetLog)

	if scanner.config.AllowTLSDowngrade {
		conn, _, err = dialGroup.DialTLSDowngrade(ctx, target, true)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, err
		}
	} else {
		conn, err = dialGroup.Dial(ctx, target)
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not establish connection to telnet server %s: %w", target.String(), err)
		}
	}

	defer func() {
		// attempt to collect TLS Log
		if tlsConn, ok := conn.(*zgrab2.TLSConnection); ok {
			result.TLSLog = tlsConn.GetLog()
		}
		// cleanup our connection
		zgrab2.CloseConnAndHandleError(conn)
	}()

	if err := GetTelnetBanner(result, conn, scanner.config.MaxReadSize); err != nil {
		if scanner.config.Banner && len(result.Banner) > 0 {
			return zgrab2.TryGetScanStatus(err), result, err
		} else {
			return zgrab2.TryGetScanStatus(err), result.getResult(), err
		}
	}
	return zgrab2.SCAN_SUCCESS, result, nil
}

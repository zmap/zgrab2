// Package fox provides a zgrab2 module that scans for fox.
// Default port: 1911 (TCP)
//
// Copied unmodified from the original zgrab.
// Connects, sends a static query, and reads the banner. Parses out as much of the response as possible.
package fox

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the fox scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags  `group:"Basic Options"`
	zgrab2.TLSFlags   `group:"TLS Options"`
	UseTLS            bool `long:"use-tls" description:"Sends probe with a TLS connection. Loads TLS module command options."`
	AllowTLSDowngrade bool `long:"allow-tls-downgrade" description:"If --use-tls is enabled and the TLS handshake fails, fall back to plaintext instead of aborting. Requires --use-tls."`
}

// Module implements the zgrab2.Module interface.
type Module struct {
	*zgrab2.BaseModule
}

func NewModule() *Module {
	return &Module{
		BaseModule: zgrab2.NewBaseModule("fox", "Niagara Fox IoT and Building Automation Communication Protocol (Fox)", "Probe for Tridium Fox", 1911),
	}
}

func (m *Module) NewFlags() any { return new(Flags) }

func (m *Module) NewScanner() zgrab2.Scanner {
	return &Scanner{BaseScanner: zgrab2.NewBaseScanner(m.Protocol())}
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	*zgrab2.BaseScanner
	config *Flags
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	zgrab2.RegisterModule(NewModule())
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(_ []string) error {
	if flags.AllowTLSDowngrade && !flags.UseTLS {
		return errors.New("--allow-tls-downgrade requires --use-tls")
	}
	return nil
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.SetBaseFlags(&f.BaseFlags)
	scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
		TLSEnabled:                      scanner.config.UseTLS,
		TLSFlags:                        &f.TLSFlags,
		NeedSeparateL4Dialer:            f.AllowTLSDowngrade,
	}
	return nil
}

// Scan probes for a Tridium Fox service.
// 1. Opens a TCP connection to the configured port (default 1911)
// 2. Sends a static query
// 3. Attempt to read the response (up to 8k + 4 bytes -- larger responses trigger an error)
// 4. If the response has the Fox response prefix, mark the scan as having detected the service.
// 5. Attempt to read any / all of the data fields from the Log struct
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	var (
		conn net.Conn
		err  error
	)

	if scanner.config.AllowTLSDowngrade {
		conn, _, err = dialGroup.DialTLSDowngrade(ctx, target, true)
	} else {
		conn, err = dialGroup.Dial(ctx, target)
	}
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("unable to dial target (%s): %w", target.String(), err)
	}
	defer func(conn net.Conn) {
		// cleanup conn
		zgrab2.CloseConnAndHandleError(conn)
	}(conn)
	result := new(FoxLog)
	// Attempt to read TLS Log from connection. If it's not a TLS connection then the log will just be empty.
	if tlsConn, ok := conn.(*zgrab2.TLSConnection); ok {
		result.TLSLog = tlsConn.GetLog()
	}

	err = GetFoxBanner(result, conn)
	if !result.IsFox {
		result = nil
		err = &zgrab2.ScanError{
			Err:    errors.New("host responds, but is not a fox service"),
			Status: zgrab2.SCAN_PROTOCOL_ERROR,
		}
	}
	return zgrab2.TryGetScanStatus(err), result, err
}

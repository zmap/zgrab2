// Package dnp3 provides a zgrab2 module that scans for dnp3.
// Default port: 20000 (TCP)
//
// Copied unmodified from the original zgrab.
// Connects, and reads the banner. Returns the raw response.
package dnp3

import (
	"context"
	"fmt"
	"net"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the dnp3 scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"` // TODO: Support UDP?
}

// Module implements the zgrab2.Module interface.
type Module struct {
	*zgrab2.BaseModule
}

func NewModule() *Module {
	return &Module{
		BaseModule: zgrab2.NewBaseModule("dnp3", "Distributed Network Protocol 3 (DNP3)", "Probe for DNP3, a SCADA protocol", 20000),
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

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(_ []string) error {
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
	}
	return nil
}

// Scan probes for a DNP3 service.
// Connects to the configured TCP port (default 20000) and reads the banner.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not dial target %s: %w", target.String(), err)
	}
	defer func(conn net.Conn) {
		// cleanup connection
		zgrab2.CloseConnAndHandleError(conn)
	}(conn)
	ret := new(DNP3Log)
	if err = GetDNP3Banner(ret, conn); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not get DNP3 banner for target %s: %w", target.String(), err)
	}
	return zgrab2.SCAN_SUCCESS, ret, nil
}

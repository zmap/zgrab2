// Package siemens provides a zgrab2 module that scans for Siemens S7.
// Default port: TCP 102
// Ported from the original zgrab. Input and output are identical.
package siemens

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the siemens scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"` // TODO: configurable TSAP source / destination, etc
	ReadTimeout      time.Duration           `long:"read-timeout" default:"500ms" description:"Timeout for reading S7 responses"`
}

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner]("siemens", "Siemens S7 Communication Protocol (Siemens)", "Probe for Siemens S7 devices", 102)
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	zgrab2.BaseScanner
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

// Scan probes for Siemens S7 services.
// 1. Connect to TCP port 102
// 2. Send a COTP connection packet with destination TSAP 0x0102, source TSAP 0x0100
// 3. If that fails, reconnect and send a COTP connection packet with destination TSAP 0x0200, source 0x0100
// 4. Negotiate S7
// 5. Request to read the module identification (and store it in the output)
// 6. Request to read the component identification (and store it in the output)
// 7. Return the output
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not establish connection to target %s: %w", target.String(), err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)
	result := new(S7Log)
	err = GetS7Banner(result, conn, func() (net.Conn, error) { return dialGroup.Dial(ctx, target) }, scanner.config.ReadTimeout)
	if !result.IsS7 {
		result = nil
	}
	return zgrab2.TryGetScanStatus(err), result, err
}

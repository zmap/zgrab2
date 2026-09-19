package crimson

import (
	"context"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for this scan module.
type Flags struct {
	zgrab2.BaseFlags
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

// NewModule returns a module for the Crimson scanner.
func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner](
		"crimson",
		"Red Lion Crimson",
		"Probe for Red Lion Crimson V3 HMI/PLC configuration devices",
		789,
	)
}

// Init implements zgrab2.Scanner.
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

// Scan implements zgrab2.Scanner. It queries the manufacturer and model CR3
// properties over a single TCP connection. Some devices only answer one
// query per session, so if the model query comes back empty after a
// successful manufacturer query, it's retried on a fresh connection.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	result := &DeviceInfo{}

	if mfgResp, err := exchange(conn, probeManufacturer); err == nil {
		result.Manufacturer = parseCR3String(mfgResp)
	}
	if modelResp, err := exchange(conn, probeModel); err == nil {
		result.Model = parseCR3String(modelResp)
	}

	if result.Manufacturer != "" && result.Model == "" {
		if conn2, err := dialGroup.Dial(ctx, target); err == nil {
			if resp, err := exchange(conn2, probeModel); err == nil {
				result.Model = parseCR3String(resp)
			}
			conn2.Close()
		}
	}

	if result.Manufacturer == "" && result.Model == "" {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, ErrNotCrimson
	}
	return zgrab2.SCAN_SUCCESS, result, nil
}

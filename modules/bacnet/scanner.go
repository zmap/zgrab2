// Package bacnet provides a zgrab2 module that scans for bacnet.
// Default Port: 47808 / 0xBAC0 (UDP)
//
// Behavior and output copied identically from original zgrab.
package bacnet

import (
	"context"
	"fmt"
	"net"

	"github.com/zmap/zgrab2"
)

// Scan results are in log.go

// Flags holds the command-line configuration for the bacnet scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
	*zgrab2.BaseModule
}

func NewModule() *Module {
	return &Module{
		BaseModule: zgrab2.NewBaseModule("bacnet", "Building Automation and Control Network (BACNET)", "Probe for devices that speak Bacnet, commonly used for HVAC control.", 0xBAC0),
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
func (flags *Flags) Validate(_ []string) error {
	return nil
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.SetBaseFlags(&f.BaseFlags)
	scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportUDP,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

// Scan probes for a BACNet service.
// Behavior taken from original zgrab.
// Connects to the configured port over UDP (default 47808/0xBAC0).
// Attempts to query the following in sequence; if any fails, returning anything that has been detected so far.
// (Unless QueryDeviceID fails, the service is considered to be detected)
// 1. Device ID
// 2. Vendor Number
// 3. Vendor Name
// 4. Firmware Revision
// 5. App software revision
// 6. Object name
// 7. Model  name
// 8. Description
// 9. Location
// The result is a bacnet.Log, and contains any of the above.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error dialing a connection to target %v: %w", target.String(), err)
	}
	defer func(conn net.Conn) {
		zgrab2.CloseConnAndHandleError(conn)
	}(conn)
	ret := new(Log)
	// TODO: if one fails, try others?
	// TODO: distinguish protocol vs app errors
	if err := ret.QueryDeviceID(conn); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error querying device id for target %v: %w", target.String(), err)
	}
	if err := ret.QueryVendorNumber(conn); err != nil {
		return zgrab2.TryGetScanStatus(err), ret, fmt.Errorf("error querying vendor number for target %v: %w", target.String(), err)
	}
	if err := ret.QueryVendorName(conn); err != nil {
		return zgrab2.TryGetScanStatus(err), ret, fmt.Errorf("error querying vendor name for target %v: %w", target.String(), err)
	}
	if err := ret.QueryFirmwareRevision(conn); err != nil {
		return zgrab2.TryGetScanStatus(err), ret, fmt.Errorf("error querying firmware revision for target %v: %w", target.String(), err)
	}
	if err := ret.QueryApplicationSoftwareRevision(conn); err != nil {
		return zgrab2.TryGetScanStatus(err), ret, fmt.Errorf("error querying application software revision for target %v: %w", target.String(), err)
	}
	if err := ret.QueryObjectName(conn); err != nil {
		return zgrab2.TryGetScanStatus(err), ret, fmt.Errorf("error querying object name for target %v: %w", target.String(), err)
	}
	if err := ret.QueryModelName(conn); err != nil {
		return zgrab2.TryGetScanStatus(err), ret, fmt.Errorf("error querying model name for target %v: %w", target.String(), err)
	}
	if err := ret.QueryDescription(conn); err != nil {
		return zgrab2.TryGetScanStatus(err), ret, fmt.Errorf("error querying description for target %v: %w", target.String(), err)
	}
	if err := ret.QueryLocation(conn); err != nil {
		return zgrab2.TryGetScanStatus(err), ret, fmt.Errorf("error querying location for target %v: %w", target.String(), err)
	}

	return zgrab2.SCAN_SUCCESS, ret, nil
}

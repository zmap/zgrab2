// Package bacnet provides a zgrab2 module that scans for bacnet.
// Default Port: 47808 / 0xBAC0 (UDP)
//
// Behavior and output copied identically from original zgrab.
package bacnet

import (
	"context"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// Scan results are in log.go

// Flags holds the command-line configuration for the bacnet scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`

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
	_, err := zgrab2.AddCommand("bacnet", "Building Automation and Control Network (BACNET)", module.Description(), 0xBAC0, &module)
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

// Description returns text uses in the help for this module.
func (module *Module) Description() string {
	return "Probe for devices that speak Bacnet, commonly used for HVAC control."
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(_ []string) error {
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
		TransportAgnosticDialerProtocol: zgrab2.TransportUDP,
		BaseFlags:                       &f.BaseFlags,
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
	return "bacnet"
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
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

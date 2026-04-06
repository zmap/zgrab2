package omronfins

import (
	"context"
	"errors"

	"github.com/zmap/zgrab2"
)

// Based on nmap omron fins scan script:https://github.com/nmap/nmap/blob/master/scripts/omron-info.nse
// Protocol was two version TCP and UDP both works on port 9600
// This protocol has also a Wireshark Dissector: https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-omron-fins.c

// Flags holds the command-line configuration for this scan module,
// you can add custom command-line flags you would want to pass in
// in this module.
type Flags struct {
	zgrab2.BaseFlags

	TCP bool `long:"tcp" description:"runs this module in TCP mode"`
}

// Scanner implements the `zgrab2.Scanner` interface, can be used to
// store scanner's state.
type Scanner struct {
	zgrab2.BaseScanner
	config            *Flags
}

// Init implements zgrab2.Scanner
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.SetBaseFlags(&f.BaseFlags)

	if scanner.config.TCP {
		scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
			TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
			BaseFlags:                       &f.BaseFlags,
		}
	} else {
		scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
			TransportAgnosticDialerProtocol: zgrab2.TransportUDP,
			BaseFlags:                       &f.BaseFlags,
		}
	}
	return nil
}

// Scan implements zgrab2.Scanner
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	// Open a connection to the target
	scantarget, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	var result DeviceInfo
	if scanner.config.TCP {
		result, err = QueryDeviceTCP(scantarget)
	} else {
		result, err = QueryDeviceUDP(scantarget)
	}
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	} else if result.ResponseCode != 0 {
		return zgrab2.SCAN_PROTOCOL_ERROR, &result, errors.New("got error response code from the device")
	}

	return zgrab2.SCAN_SUCCESS, &result, err
}


// Module is the implementation of the zgrab2.Module interface.
func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner](
		"omronfins",
		"Module for the omron fins protocol",
		"Module for the omron fins protocol",
		9600,
	)
}

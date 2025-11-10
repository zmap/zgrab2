package enip

// Based on well documented protocol Ethernet/IP OR CIP: Ethernet/IP is transport protocol
//https://www.odva.org/wp-content/uploads/2020/05/PUB00213R0_EtherNetIP_Developers_Guide.pdf
// There is a Wireshark dissector for the protocol:https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-enip.c
// Using the following port: 44818 TCP
// The protocol has two version little and big endian

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

type Flags struct {
	zgrab2.BaseFlags
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
	_, err := zgrab2.AddCommand("enip", "enip", module.Description(), 44818, &module)
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
	return "Probe for Ethernet/IP devices, usually PLCs as part of a SCADA system"
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
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
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
	return "enip"
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

// GetScanMetadata returns any metadata on the scan itself from this module.
func (scanner *Scanner) GetScanMetadata() any {
	return nil
}

type EnipDeviceInfo struct {
	// Unique ID that identity the vendor of the device: Can see the full map at the EnipVendorMap under enip.go
	VendorID int `json:"vendor_id"`

	// The vendor the device(taken from the map)
	Vendor string `json:"vendor"`

	// Unique ID that identity the type of the device: Can see the full map at the EnipDeviceTypeMap under enip.go
	DeviceTypeID int `json:"device_type_id"`

	// The type the device(taken from the map)
	DeviceType string `json:"device_type"`

	// Unique id of the vendor that identity the product
	ProductCode int `json:"product_code"`

	// The firmware version of the device
	Revision string `json:"revision"`

	// The serial number of the device
	Serial string `json:"serial"`

	// The name of the product: same as the model of the device
	ProductName string `json:"product_name"`
}

func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	log.Debugf("Trying to connect to the target...")
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()
	enipConn := EnipCon{Conn: conn, Session: 0}
	identity, err := enipConn.GetCIPIdentity()
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}
	vendor, err := identity.GetVendorString()
	if err != nil {
		log.Infof("Get unknown Vendor ID: %d", identity.VendorID)
	}
	deviceType, err := identity.GetDeviceTypeString()
	if err != nil {
		log.Infof("Get unknown Device Type: %d", identity.DeviceType)
	}
	revision := fmt.Sprintf("%d.%02d", identity.Revision>>8, identity.Revision&0xff)
	scanResult := EnipDeviceInfo{
		VendorID:     int(identity.VendorID),
		Vendor:       vendor,
		DeviceTypeID: int(identity.DeviceType),
		DeviceType:   deviceType,
		ProductCode:  int(identity.ProductCode),
		Revision:     revision,
		Serial:       fmt.Sprintf("0x%08x", identity.Serial),
		ProductName:  identity.ProductName,
	}

	return zgrab2.SCAN_SUCCESS, scanResult, err
}

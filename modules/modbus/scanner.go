// Package modbus provides a zgrab2 module that scans for modbus.
// Default Port: 502 (TCP)
//
// The --unit-id flag allows overriding the default value of 0 (the simulator
// for example does not respond at all to UnitID == 0; other servers may
// interpret it as a broadcast).
//
// The --object-id flag allows reading a different object ID's information.
// The default of 0x00 is the VendorName, which is required.
//
// The --request-id flag allows setting a custom request identifier (which
// the server will use in its response).
//
// The --strict flag allows turning on new validity checks beyond those
// done in the original zgrab, to help rule out false matches.
//
// The output is the same as the original ZGrab: a "modbus event" object,
// with either the parsed MEI response or the parsed exception info.
// The only addition is a "raw" field containing the raw response data.
package modbus

import (
	"encoding/hex"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the modbus scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	// Protocols that support TLS should include zgrab2.TLSFlags
	UnitID    uint8  `long:"unit-id" description:"The UnitID / Station ID to probe"`
	ObjectID  uint8  `long:"object-id" description:"The ObjectID of the object to be read." default:"0x00"`
	Strict    bool   `long:"strict" description:"If set, perform stricter checks on the response data to get fewer false positives"`
	RequestID uint16 `long:"request-id" description:"Override the default request ID." default:"0x5A47"`
	Verbose   bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("modbus", "modbus", module.Description(), 502, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object.
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Probe for Modbus devices, usually PLCs as part of a SCADA system"
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(args []string) error {
	if flags.Verbose {
		// If --verbose is set, do some extra checking but don't fail.
		if flags.ObjectID >= 0x07 && flags.ObjectID < 0x80 {
			log.Warnf("ObjectIDs 0x07...0x7F are reserved (requested 0x%02x)", flags.ObjectID)
		}
	}
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
	return "modbus"
}

// Conn wraps the connection state (more importantly, it provides the interface used by the old zgrab code, so that it
// could be taken over as-is).
type Conn struct {
	Conn    net.Conn
	scanner *Scanner
}

func (c *Conn) getUnderlyingConn() net.Conn {
	return c.Conn
}

// Scan probes for a modbus service.
// It connects to the configured TCP port (default 502) and sends a packet with:
//	 UnitID = <flags.UnitID, default 0>
//   FunctionCode = 0x2B: Encapsulated Interface Transport)
//   MEI Type = 0x0E: Read Device Info
//   Category = 0x01: Basic
//	 ObjectID = <flags.ObjectID, default 0: VendorName>
// If the response is not a valid modbus response to this packet, then fail with a SCAN_PROTOCOL_ERROR.
// Otherwise, return the parsed response and status (SCAN_SUCCESS or SCAN_APPLICATION_ERROR)
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	conn, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	c := Conn{Conn: conn, scanner: scanner}
	req := ModbusRequest{
		UnitID:   int(scanner.config.UnitID),
		Function: ModbusFunctionEncapsulatedInterface,
		Data: []byte{
			0x0E, // 0x0E = MEI Read Device Identification
			0x01, // 0x01 = "Category" = basic (02 = regular, 03 = extended, 04 = specific)
			scanner.config.ObjectID,
		},
	}

	data, err := c.MarshalRequest(&req)
	if err != nil {
		log.Fatalf("Unexpected error marshaling modbus packet: %v", err)
	}
	w := 0
	for w < len(data) {
		written, err := c.getUnderlyingConn().Write(data[w:])
		w += written
		if err != nil {
			return zgrab2.TryGetScanStatus(err), nil, err
		}
	}

	res, err := c.GetModbusResponse()
	if res == nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	// if there was an error but we still got a response, try to continue
	if scanner.config.Verbose {
		log.Debugf("Got non-fatal error while reading modbus response: %v", err)
	}

	if res.Function&0x7F != ModbusFunctionEncapsulatedInterface {
		// The server should always return a response for the same function
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("Invalid response function code 0x%02x (raw = %s)", res.Function, hex.Dump(res.Raw))
	}
	if scanner.config.Strict && (scanner.config.UnitID != 0 && res.UnitID != int(scanner.config.UnitID)) {
		// response for different unitID.
		// If request unit ID was 0, don't enforce matching since that may be interpreted as a broadcast.
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("Invalid response unit ID 0x%02x (raw = %s)", res.UnitID, hex.Dump(res.Raw))
	}

	if res.Length != len(res.Data)+2 {
		// data not expected size
		// Let this one slide with a debug-only warning, since some actual servers seem to behave this way
		log.Debugf("Server advertised %d bytes of data, received %d", res.Length, len(res.Data)+2)
	}

	ret, err := res.getEvent(scanner.config.Strict)
	if err != nil {
		// Unable to parse the response as a valid event
		log.Debugf("Unable to process response as modbus: %v. Raw response data=[\n%s\n]", err, hex.Dump(res.Raw))
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}

	status := zgrab2.SCAN_SUCCESS
	if res.IsException() {
		// Note the exception, but note that the modbus protocol was detected
		status = zgrab2.SCAN_APPLICATION_ERROR
	}
	return status, ret, nil
}

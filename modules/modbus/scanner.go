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
	"context"
	"encoding/hex"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the modbus scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"` // Protocols that support TLS should include zgrab2.TLSFlags
	UnitID           uint8                   `long:"unit-id" description:"The UnitID / Station ID to probe"`
	ObjectID         uint8                   `long:"object-id" description:"The ObjectID of the object to be read." default:"0x00"`
	Strict           bool                    `long:"strict" description:"If set, perform stricter checks on the response data to get fewer false positives"`
	RequestID        uint16                  `long:"request-id" description:"Override the default request ID." default:"0x5A47"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
	*zgrab2.BaseModule
}

func NewModule() *Module {
	return &Module{
		BaseModule: zgrab2.NewBaseModule("modbus", "Open-source PLC Communication Protocol (Modbus)", "Probe for Modbus devices, usually PLCs as part of a SCADA system", 502),
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
	if flags.Verbose {
		// If --verbose is set, do some extra checking but don't fail.
		if flags.ObjectID >= 0x07 && flags.ObjectID < 0x80 {
			log.Warnf("ObjectIDs 0x07...0x7F are reserved (requested 0x%02x)", flags.ObjectID)
		}
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
	}
	return nil
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
//
//		 UnitID = <flags.UnitID, default 0>
//	  FunctionCode = 0x2B: Encapsulated Interface Transport)
//	  MEI Type = 0x0E: Read Device Info
//	  Category = 0x01: Basic
//		 ObjectID = <flags.ObjectID, default 0: VendorName>
//
// If the response is not a valid modbus response to this packet, then fail with a SCAN_PROTOCOL_ERROR.
// Otherwise, return the parsed response and status (SCAN_SUCCESS or SCAN_APPLICATION_ERROR)
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not dial target %s: %w", target.String(), err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)

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
	var written int
	for w < len(data) {
		written, err = c.getUnderlyingConn().Write(data[w:])
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
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("invalid response function code 0x%02x (raw = %s)", res.Function, hex.Dump(res.Raw))
	}
	if scanner.config.Strict && (scanner.config.UnitID != 0 && res.UnitID != int(scanner.config.UnitID)) {
		// response for different unitID.
		// If request unit ID was 0, don't enforce matching since that may be interpreted as a broadcast.
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("invalid response unit ID 0x%02x (raw = %s)", res.UnitID, hex.Dump(res.Raw))
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

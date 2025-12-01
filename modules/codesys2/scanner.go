package codesys2

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// Based on internal research of the protocol strucuture: https://microsoft.sharepoint.com/:w:/t/section52/ET2CESsVyoJCpgUbxaJMay8B8zTu_SdFnd2a41Xd_7X-RQ?e=HoOV4I
// Using the following ports: 1200, 1201, 2455 over TCP
// The protocol has two version little and big endiness
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
	_, err := zgrab2.AddCommand("codesys2", "codesys2", module.Description(), 1200, &module)
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
	return "Probe for CodeSysV2 devices, usually PLCs as part of a SCADA system"
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
	return "codesys2"
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

// GetScanMetadata returns any metadata on the scan itself from this module.
func (scanner *Scanner) GetScanMetadata() any {
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

func (scanner *Scanner) ScanWithByteOrder(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget, order binary.ByteOrder) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	c := Conn{Conn: conn, scanner: scanner}
	req := CodeSysV2LoginRequest{}
	req.New()

	data, err := Marshal(req, order)
	if err != nil {
		log.Fatalf("Unexpected error marshaling CodesysV2 packet: %v", err)
	}
	w := 0
	for w < len(data) {
		written, writeerr := c.getUnderlyingConn().Write(data[w:])
		w += written
		if writeerr != nil {
			log.Fatalf("Unexpected error sending CodesysV2 Login Request: %v", err)
			return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
		}
	}

	headerbytes := make([]byte, HeaderSize)
	var header CodeSysV2Header
	_, err = io.ReadFull(c.getUnderlyingConn(), headerbytes)
	if err != nil {
		//log.Fatalf("Unexpected error reading CodesysV2 header: %v", err)
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}
	err = UnMarshal(headerbytes, order, &header)
	if err != nil {
		//log.Fatalf("Unexpected error unmarshaling CodesysV2 packet: %v", err)
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, errors.New("failed to read CodeSysV2 Header")
	} else if header.Magic != CodeSysV2Magic {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, errors.New("didn't receive CodesysV2 packet magic")
	} else if (header.Length & 0xff000000) != 0 {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, errors.New("seems like the wrong byte order of the protocol")
	}
	payloadbytes := make([]byte, header.Length)
	_, err = io.ReadFull(c.getUnderlyingConn(), payloadbytes)
	if err != nil {
		//log.Fatalf("Unexpected error reading CodesysV2 payload: %v", err)
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}
	fullpacketbytes := append(headerbytes, payloadbytes...)
	var res CodeSysV2LoginResponse
	err = UnMarshal(fullpacketbytes, order, &res)
	if err != nil {
		//log.Fatalf("Unexpected error unmarshaling CodesysV2 packet: %v", err)
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}

	DeviceInfo := CodeSysV2DeviceInfo{OsType: strings.ReplaceAll(string(res.OsType[:]), "\000", ""),
		OsVersion: strings.ReplaceAll(string(res.OsVersion[:]), "\000", ""),
		Vendor:    strings.ReplaceAll(string(res.Vendor[:]), "\000", "")}
	return zgrab2.SCAN_SUCCESS, DeviceInfo, nil
}

// Scanner needs to scan the ports 1200, 1201, 2455
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	log.Debugf("Trying to connect to the target with Little Endian version of the protocol...")
	scanResult, event, err := scanner.ScanWithByteOrder(ctx, dialGroup, target, binary.LittleEndian)
	if scanResult == zgrab2.SCAN_PROTOCOL_ERROR {
		log.Debugf("Trying to connect to the target with Big Endian version of the protocol...")
		scanResult, event, err = scanner.ScanWithByteOrder(ctx, dialGroup, target, binary.BigEndian)
	}
	return scanResult, event, err
}

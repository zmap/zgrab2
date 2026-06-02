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

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner]("codesys2", "codesys2", "Probe for CodeSysV2 devices, usually PLCs as part of a SCADA system", 1200)
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
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}
	err = UnMarshal(headerbytes, order, &header)
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, errors.New("failed to read CodeSysV2 Header")
	} else if header.Magic != CodeSysV2Magic {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, errors.New("didn't receive CodesysV2 packet magic")
	} else if (header.Length & 0xff000000) != 0 {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, errors.New("seems like the wrong byte order of the protocol")
	}
	// Now we know the total size, create the full buffer
	fullPacketBytes := make([]byte, HeaderSize+header.Length)
	copy(fullPacketBytes, headerbytes)
	_, err = io.ReadFull(c.getUnderlyingConn(), fullPacketBytes[HeaderSize:])
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}
	var res CodeSysV2LoginResponse
	err = UnMarshal(fullPacketBytes, order, &res)
	if err != nil {
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

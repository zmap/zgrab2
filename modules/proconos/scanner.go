package proconos

import (
	"context"
	"net"

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

// NewModule returns a module for the ProConOS scanner.
func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner](
		"proconos",
		"ProConOS",
		"Probe for Phoenix Contact / KW-Software ProConOS PLC runtimes",
		20547,
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

// exchange writes probe to conn and returns whatever response comes back.
func exchange(conn net.Conn, probe []byte) ([]byte, error) {
	if _, err := conn.Write(probe); err != nil {
		return nil, err
	}
	buf := make([]byte, readBufSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// Scan implements zgrab2.Scanner. It sends the fixed ProConOS device-info
// request and parses the resulting NUL-delimited string table.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	resp, err := exchange(conn, probe)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	result, err := parseResponse(resp)
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}
	return zgrab2.SCAN_SUCCESS, result, nil
}

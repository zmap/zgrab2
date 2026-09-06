package pcworx

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

// NewModule returns a module for the PC WorX scanner.
func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner](
		"pcworx",
		"PC WorX (Phoenix Contact)",
		"Probe for Phoenix Contact PC WorX PLC runtimes",
		1962,
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

// exchange writes req to conn and returns whatever response comes back.
func exchange(conn net.Conn, req []byte) ([]byte, error) {
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// Scan implements zgrab2.Scanner. The initial handshake alone is enough to
// confirm a PC WorX device; the two follow-up requests that pull PLC
// identity fields are best-effort and don't affect the scan status if a
// device doesn't answer them.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	handshakeResp, err := exchange(conn, initComms)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	if !matchesHandshake(handshakeResp) {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, ErrNotPCWorx
	}
	sid := handshakeResp[sessionIDOffset]

	result := &DeviceInfo{}
	if _, err := exchange(conn, buildSetSessionRequest(sid)); err == nil {
		if infoResp, err := exchange(conn, buildInfoRequest(sid)); err == nil {
			if info := parseInfoResponse(infoResp); info != nil {
				result = info
			}
		}
	}

	return zgrab2.SCAN_SUCCESS, result, nil
}

package codesysv3

import (
	"context"
	"errors"
	"math/rand"
	"net"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for this scan module.
type Flags struct {
	zgrab2.BaseFlags

	// UDP switches the scanner to the UDP NameService variant (usually
	// ports 1740-1743) instead of the default TCP CmpBlkDrvTcp variant
	// (usually ports 11740-11743). The UDP variant expects the request to
	// originate from the matching reserved local port (1740 + port index);
	// pair --udp with --local-port to set that explicitly.
	UDP bool `long:"udp" description:"use the UDP NameService variant instead of the default TCP block-driver variant"`
}

// Help returns additional help text for the flags.
func (f Flags) Help() string {
	return "The UDP variant expects the request to come from local port 1740 + (port - 1740); pair --udp with --local-port to control that."
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

// NewModule returns a module for the CODESYS V3 scanner.
func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner](
		"codesys3",
		"codesys3",
		"Probe for CODESYS V3 runtimes via the NameService ResolveAddr/Identification exchange",
		11740,
	)
}

// Init implements zgrab2.Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.SetBaseFlags(&f.BaseFlags)
	protocol := zgrab2.TransportTCP
	if f.UDP {
		protocol = zgrab2.TransportUDP
	}
	scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: protocol,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

// buildRequest constructs the ResolveAddr request appropriate for the
// established connection's transport, using its real local/remote addresses.
func (scanner *Scanner) buildRequest(conn net.Conn, target *zgrab2.ScanTarget) ([]byte, error) {
	broadcastID := uint16(rand.Intn(0x10000))
	requestID := rand.Uint32()

	if scanner.config.UDP {
		localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
		if !ok {
			return nil, errors.New("expected a UDP local address")
		}
		portIndex := int(target.Port) - 1740
		return BuildUDPResolveRequest(localAddr.IP, portIndex, 24, broadcastID, requestID)
	}

	localAddr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, errors.New("expected a TCP local address")
	}
	remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, errors.New("expected a TCP remote address")
	}
	return BuildTCPResolveRequest(localAddr.IP, uint16(localAddr.Port), remoteAddr.IP, uint16(remoteAddr.Port), broadcastID, requestID)
}

// Scan implements zgrab2.Scanner.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()

	req, err := scanner.buildRequest(conn, target)
	if err != nil {
		return zgrab2.SCAN_APPLICATION_ERROR, nil, err
	}
	if _, err = conn.Write(req); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	result, err := ParseResponse(buf[:n])
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, err
	}
	return zgrab2.SCAN_SUCCESS, result, nil
}

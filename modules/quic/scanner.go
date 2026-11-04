// Package quic contains the zgrab2 module for QUIC (RFC 9000).
//
// The scan has two steps, each of which can be disabled:
//
//  1. Version negotiation: send a datagram carrying a reserved QUIC version.
//     A conforming server answers with a Version Negotiation packet that lists
//     every version it supports (QUIC v1, v2, IETF drafts, Google QUIC, ...).
//  2. Handshake: perform a full QUIC handshake (using quic-go) and record the
//     negotiated version, ALPN, TLS parameters, the server's certificate chain,
//     whether the server required a Retry, and the server's transport
//     parameters. The connection is closed as soon as the handshake completes;
//     no application data is exchanged.
package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"
	ztls "github.com/zmap/zcrypto/tls"
	"github.com/zmap/zcrypto/x509"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the QUIC scan module.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`

	ALPN                   string        `long:"alpn" default:"h3" description:"Comma-separated list of ALPN protocols to offer in the handshake (e.g. h3,h3-29,hq-interop)"`
	ServerName             string        `long:"server-name" description:"Server name (SNI) to send. Defaults to the target's domain, if any."`
	ProbeTimeout           time.Duration `long:"probe-timeout" default:"3s" description:"How long to wait for a reply to the version negotiation probe"`
	HandshakeTimeout       time.Duration `long:"handshake-timeout" default:"5s" description:"How long to wait for the QUIC handshake to complete"`
	SkipVersionNegotiation bool          `long:"skip-version-negotiation" description:"Do not send the version negotiation probe"`
	SkipHandshake          bool          `long:"skip-handshake" description:"Only send the version negotiation probe; do not attempt a handshake"`
}

// Validate checks that the flags are consistent.
func (f Flags) Validate(_ []string) error {
	if f.SkipVersionNegotiation && f.SkipHandshake {
		return errors.New("--skip-version-negotiation and --skip-handshake cannot both be set")
	}
	if !f.SkipHandshake && len(f.alpnList()) == 0 {
		return errors.New("--alpn must list at least one protocol")
	}
	return nil
}

// Help returns the module's help string.
func (f Flags) Help() string {
	return ""
}

func (f Flags) alpnList() []string {
	var protos []string
	for _, p := range strings.Split(f.ALPN, ",") {
		if p = strings.TrimSpace(p); p != "" {
			protos = append(protos, p)
		}
	}
	return protos
}

// NewModule returns the QUIC module.
func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner](
		"quic",
		"QUIC",
		"Probe for QUIC version negotiation and perform a QUIC/TLS 1.3 handshake, recording supported versions, ALPN, certificates and transport parameters.",
		443,
	)
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.SetBaseFlags(&f.BaseFlags)
	scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportUDP,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

// Scan probes the target for QUIC support.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	result := &Log{}
	var probeErr error

	if !scanner.config.SkipVersionNegotiation {
		result.VersionNegotiation, probeErr = scanner.probeVersions(ctx, dialGroup, target)
		if scanner.config.SkipHandshake {
			if probeErr != nil {
				return zgrab2.TryGetScanStatus(probeErr), nil, probeErr
			}
			return zgrab2.SCAN_SUCCESS, result, nil
		}
	}

	hs, err := scanner.handshake(ctx, dialGroup, target)
	result.Handshake = hs
	switch {
	case err == nil:
		return zgrab2.SCAN_SUCCESS, result, nil
	case hs == nil:
		// The connection could not be set up locally.
		return zgrab2.TryGetScanStatus(err), nil, err
	case result.VersionNegotiation != nil || hs.serverResponded:
		// The target speaks QUIC, but the handshake did not complete.
		return zgrab2.SCAN_HANDSHAKE_ERROR, result, err
	default:
		// Nothing came back from the target at all.
		if probeErr != nil {
			err = fmt.Errorf("%w (version negotiation probe: %v)", err, probeErr)
		}
		return zgrab2.SCAN_IO_TIMEOUT, nil, err
	}
}

// probeVersions sends a packet with a reserved version and parses the
// server's Version Negotiation response.
func (scanner *Scanner) probeVersions(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (*VersionNegotiationLog, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("could not dial %s: %w", target.String(), err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	probe, err := newVersionProbe()
	if err != nil {
		return nil, fmt.Errorf("could not build version negotiation probe: %w", err)
	}
	if _, err = conn.Write(probe.Packet); err != nil {
		return nil, fmt.Errorf("could not send version negotiation probe: %w", err)
	}
	if err = conn.SetReadDeadline(time.Now().Add(scanner.config.ProbeTimeout)); err != nil {
		return nil, fmt.Errorf("could not set read deadline: %w", err)
	}

	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("no version negotiation response: %w", err)
		}
		vn, err := parseVersionNegotiation(buf[:n])
		if err != nil {
			// Ignore anything else (e.g. stray packets) until the deadline.
			continue
		}
		log := &VersionNegotiationLog{
			SupportedVersions: make([]Version, 0, len(vn.Versions)),
			// The server swaps the connection IDs (RFC 8999, Section 6).
			ConnectionIDsEchoed: string(vn.DestConnID) == string(probe.SrcConnID) &&
				string(vn.SrcConnID) == string(probe.DestConnID),
		}
		for _, v := range vn.Versions {
			log.SupportedVersions = append(log.SupportedVersions, newVersion(v))
		}
		return log, nil
	}
}

// handshake performs a QUIC handshake with the target. The returned log is nil
// only if the connection could not be set up locally.
func (scanner *Scanner) handshake(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (*HandshakeLog, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("could not dial %s: %w", target.String(), err)
	}

	serverName := scanner.config.ServerName
	if serverName == "" {
		serverName = target.Domain
	}
	log := &HandshakeLog{
		OfferedALPN: scanner.config.alpnList(),
		ServerName:  serverName,
	}

	tracer := &handshakeTracer{}
	tr := &quic.Transport{Conn: &connectedPacketConn{Conn: conn}}
	defer func() {
		// Closing the connection first unblocks quic-go's read loop, which
		// Transport.Close waits for.
		zgrab2.CloseConnAndHandleError(conn)
		_ = tr.Close()
	}()

	tlsConf := &tls.Config{
		// The scan records certificates; it does not validate them.
		InsecureSkipVerify: true,
		NextProtos:         log.OfferedALPN,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS13,
	}
	quicConf := &quic.Config{
		HandshakeIdleTimeout: scanner.config.HandshakeTimeout,
		Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
			return tracer
		},
	}

	dialCtx, cancel := context.WithTimeout(ctx, scanner.config.HandshakeTimeout)
	defer cancel()
	qconn, err := tr.Dial(dialCtx, conn.RemoteAddr(), tlsConf, quicConf)
	tracer.fill(log)
	if err != nil {
		log.CloseError = newCloseError(err)
		if log.CloseError.Type == "version_negotiation" {
			log.VersionNegotiationFailed = true
		}
		if errors.Is(err, context.DeadlineExceeded) {
			log.CloseError.Type = "handshake_timeout"
		}
		return log, fmt.Errorf("QUIC handshake with %s failed: %w", target.String(), err)
	}
	defer func() { _ = qconn.CloseWithError(0, "") }()

	state := qconn.ConnectionState()
	log.Complete = true
	version := newVersion(uint32(state.Version))
	log.Version = &version
	log.ALPN = state.TLS.NegotiatedProtocol
	log.TLSVersion = tls.VersionName(state.TLS.Version)
	log.CipherSuite = tls.CipherSuiteName(state.TLS.CipherSuite)
	for _, cert := range state.TLS.PeerCertificates {
		simple := ztls.SimpleCertificate{Raw: cert.Raw}
		if parsed, err := x509.ParseCertificate(cert.Raw); err == nil {
			simple.Parsed = parsed
		}
		log.Certificates = append(log.Certificates, simple)
	}
	// Transport parameters may be logged after Dial returns; read them again.
	tracer.fill(log)
	return log, nil
}

// newCloseError describes an error returned by a QUIC dial.
func newCloseError(err error) *CloseError {
	ce := &CloseError{Type: "other", Message: err.Error()}
	var (
		transportErr   *quic.TransportError
		applicationErr *quic.ApplicationError
		versionErr     *quic.VersionNegotiationError
		idleErr        *quic.IdleTimeoutError
		handshakeErr   *quic.HandshakeTimeoutError
		resetErr       *quic.StatelessResetError
	)
	switch {
	case errors.As(err, &transportErr):
		ce.Type = "transport"
		ce.Remote = transportErr.Remote
		ce.Code = uint64(transportErr.ErrorCode)
		ce.Name = transportErr.ErrorCode.String()
		ce.Reason = transportErr.ErrorMessage
		if transportErr.ErrorCode.IsCryptoError() {
			ce.TLSAlert = transportErr.ErrorCode.Message()
		}
	case errors.As(err, &applicationErr):
		ce.Type = "application"
		ce.Remote = applicationErr.Remote
		ce.Code = uint64(applicationErr.ErrorCode)
		ce.Reason = applicationErr.ErrorMessage
	case errors.As(err, &versionErr):
		ce.Type = "version_negotiation"
		ce.Remote = true
	case errors.As(err, &idleErr):
		ce.Type = "idle_timeout"
	case errors.As(err, &handshakeErr):
		ce.Type = "handshake_timeout"
	case errors.As(err, &resetErr):
		ce.Type = "stateless_reset"
		ce.Remote = true
	}
	return ce
}

// connectedPacketConn adapts a connected UDP net.Conn, as returned by the
// zgrab2 dialer (which applies the configured source address, timeouts and
// read limits), to the net.PacketConn interface expected by quic-go.
type connectedPacketConn struct {
	net.Conn
}

func (c *connectedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.RemoteAddr(), err
}

func (c *connectedPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

// SetDeadline, SetReadDeadline and SetWriteDeadline are no-ops: the zgrab2
// connection enforces the scan's own timeouts, and quic-go only uses read
// deadlines to stop its read loop on Close, which closing the connection
// already does.
func (c *connectedPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *connectedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *connectedPacketConn) SetWriteDeadline(time.Time) error { return nil }

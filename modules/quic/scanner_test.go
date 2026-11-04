package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/zmap/zgrab2"
)

const testServerCommonName = "quic-test.example"

// newTestCertificate returns a self-signed certificate for testServerCommonName.
func newTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: testServerCommonName},
		DNSNames:     []string{testServerCommonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// testServer is a local QUIC server.
type testServer struct {
	addr *net.UDPAddr

	mu         sync.Mutex
	serverName string
}

func (s *testServer) lastServerName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serverName
}

// startTestServer starts a QUIC server on localhost that accepts connections
// offering ALPN "h3". If retry is set, the server requires address validation
// with a Retry packet.
func startTestServer(t *testing.T, retry bool) *testServer {
	t.Helper()
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	srv := &testServer{addr: udpConn.LocalAddr().(*net.UDPAddr)}
	tr := &quic.Transport{Conn: udpConn}
	if retry {
		tr.VerifySourceAddress = func(net.Addr) bool { return true }
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{newTestCertificate(t)},
		NextProtos:   []string{"h3"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			srv.mu.Lock()
			srv.serverName = hello.ServerName
			srv.mu.Unlock()
			return nil, nil
		},
	}
	ln, err := tr.Listen(tlsConf, &quic.Config{
		MaxIncomingStreams:    42,
		MaxIncomingUniStreams: 7,
		MaxIdleTimeout:        12 * time.Second,
		EnableDatagrams:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go func() {
				<-conn.Context().Done()
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		tr.Close()
		udpConn.Close()
	})
	return srv
}

// startSilentServer returns the address of a UDP socket that never replies.
func startSilentServer(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := conn.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr)
}

// newTestScanner returns a scanner with the given flags applied on top of
// the defaults.
func newTestScanner(t *testing.T, modify func(*Flags)) *Scanner {
	t.Helper()
	flags := &Flags{
		ALPN:             "h3",
		ProbeTimeout:     time.Second,
		HandshakeTimeout: 2 * time.Second,
	}
	if modify != nil {
		modify(flags)
	}
	if err := flags.Validate(nil); err != nil {
		t.Fatal(err)
	}
	scanner := new(Scanner)
	if err := scanner.Init(flags); err != nil {
		t.Fatal(err)
	}
	return scanner
}

// udpDialerGroup dials UDP connections to addr, wrapped in a
// zgrab2.TimeoutConnection as the default zgrab2 UDP dialer does.
func udpDialerGroup(addr *net.UDPAddr) *zgrab2.DialerGroup {
	return &zgrab2.DialerGroup{
		TransportAgnosticDialer: func(ctx context.Context, _ *zgrab2.ScanTarget) (net.Conn, error) {
			conn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				return nil, err
			}
			return zgrab2.NewTimeoutConnection(ctx, conn, 10*time.Second, 0, 0, zgrab2.DefaultBytesReadLimit)
		},
	}
}

func scan(t *testing.T, scanner *Scanner, addr *net.UDPAddr, domain string) (zgrab2.ScanStatus, *Log, error) {
	t.Helper()
	target := &zgrab2.ScanTarget{IP: addr.IP, Port: uint(addr.Port), Domain: domain}
	status, result, err := scanner.Scan(context.Background(), udpDialerGroup(addr), target)
	log, _ := result.(*Log)
	return status, log, err
}

func TestScanSuccess(t *testing.T) {
	srv := startTestServer(t, false)
	status, log, err := scan(t, newTestScanner(t, nil), srv.addr, "")
	if status != zgrab2.SCAN_SUCCESS || err != nil {
		t.Fatalf("status = %s, err = %v", status, err)
	}

	vn := log.VersionNegotiation
	if vn == nil {
		t.Fatal("no version negotiation result")
	}
	if !vn.ConnectionIDsEchoed {
		t.Error("connection IDs were not echoed")
	}
	found := map[string]bool{}
	for _, v := range vn.SupportedVersions {
		found[v.Name] = true
	}
	if !found["QUICv1"] || !found["QUICv2"] {
		t.Errorf("supported versions %+v do not include QUICv1 and QUICv2", vn.SupportedVersions)
	}

	hs := log.Handshake
	if hs == nil || !hs.Complete {
		t.Fatalf("handshake not complete: %+v", hs)
	}
	if hs.Version == nil || hs.Version.Name != "QUICv1" {
		t.Errorf("negotiated version = %+v, want QUICv1", hs.Version)
	}
	if hs.ALPN != "h3" {
		t.Errorf("ALPN = %q, want h3", hs.ALPN)
	}
	if hs.TLSVersion != "TLS 1.3" {
		t.Errorf("TLS version = %q", hs.TLSVersion)
	}
	if hs.CipherSuite == "" {
		t.Error("cipher suite not recorded")
	}
	if hs.RetryReceived {
		t.Error("RetryReceived set without a Retry")
	}
	if hs.CloseError != nil {
		t.Errorf("unexpected close error %+v", hs.CloseError)
	}
	if len(hs.Certificates) != 1 || len(hs.Certificates[0].Raw) == 0 || hs.Certificates[0].Parsed == nil ||
		hs.Certificates[0].Parsed.Subject.String() != "CN="+testServerCommonName {
		t.Fatalf("unexpected certificates: %+v", hs.Certificates)
	}

	tp := hs.TransportParameters
	if tp == nil {
		t.Fatal("no transport parameters recorded")
	}
	if tp.InitialMaxStreamsBidi != 42 || tp.InitialMaxStreamsUni != 7 {
		t.Errorf("stream limits = %d/%d, want 42/7", tp.InitialMaxStreamsBidi, tp.InitialMaxStreamsUni)
	}
	if tp.MaxIdleTimeoutMS != 12000 {
		t.Errorf("max idle timeout = %dms, want 12000", tp.MaxIdleTimeoutMS)
	}
	if tp.MaxDatagramFrameSize == nil || *tp.MaxDatagramFrameSize <= 0 {
		t.Errorf("max datagram frame size not recorded: %v", tp.MaxDatagramFrameSize)
	}
	if !tp.StatelessResetToken {
		t.Error("stateless reset token not recorded")
	}

	// The result must serialize to JSON, including the zcrypto certificates.
	out, err := json.Marshal(log)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	certs := decoded["handshake"].(map[string]any)["certificates"].([]any)
	cert := certs[0].(map[string]any)
	if _, ok := cert["raw"]; !ok {
		t.Errorf("certificate JSON has no raw field: %s", out)
	}
	if _, ok := cert["parsed"]; !ok {
		t.Errorf("certificate JSON has no parsed field: %s", out)
	}
}

func TestScanServerName(t *testing.T) {
	srv := startTestServer(t, false)

	// The target's domain is used for SNI by default.
	if status, _, err := scan(t, newTestScanner(t, nil), srv.addr, "from-target.example"); status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("status = %s, err = %v", status, err)
	}
	if got := srv.lastServerName(); got != "from-target.example" {
		t.Errorf("server saw SNI %q, want from-target.example", got)
	}

	// --server-name overrides it.
	scanner := newTestScanner(t, func(f *Flags) { f.ServerName = "from-flag.example" })
	status, log, err := scan(t, scanner, srv.addr, "from-target.example")
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("status = %s, err = %v", status, err)
	}
	if got := srv.lastServerName(); got != "from-flag.example" {
		t.Errorf("server saw SNI %q, want from-flag.example", got)
	}
	if log.Handshake.ServerName != "from-flag.example" {
		t.Errorf("logged server name %q", log.Handshake.ServerName)
	}
}

func TestScanRetry(t *testing.T) {
	srv := startTestServer(t, true)
	status, log, err := scan(t, newTestScanner(t, nil), srv.addr, "")
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("status = %s, err = %v", status, err)
	}
	if !log.Handshake.RetryReceived {
		t.Error("Retry was not recorded")
	}
}

func TestScanALPNMismatch(t *testing.T) {
	srv := startTestServer(t, false)
	scanner := newTestScanner(t, func(f *Flags) { f.ALPN = "hq-interop, smb" })
	status, log, err := scan(t, scanner, srv.addr, "")
	if status != zgrab2.SCAN_HANDSHAKE_ERROR || err == nil {
		t.Fatalf("status = %s, err = %v; want handshake error", status, err)
	}
	if log == nil || log.VersionNegotiation == nil {
		t.Fatal("version negotiation result should be kept when the handshake fails")
	}
	hs := log.Handshake
	if hs.Complete {
		t.Error("handshake marked complete")
	}
	if got := hs.OfferedALPN; len(got) != 2 || got[0] != "hq-interop" || got[1] != "smb" {
		t.Errorf("offered ALPN = %v", got)
	}
	ce := hs.CloseError
	if ce == nil || ce.Type != "transport" || !ce.Remote {
		t.Fatalf("close error = %+v, want a remote transport error", ce)
	}
	if ce.Code != 0x178 || ce.TLSAlert != "tls: no application protocol" {
		t.Errorf("close error code %#x / alert %q, want 0x178 / no application protocol", ce.Code, ce.TLSAlert)
	}
}

func TestScanSkipHandshake(t *testing.T) {
	srv := startTestServer(t, false)
	scanner := newTestScanner(t, func(f *Flags) { f.SkipHandshake = true })
	status, log, err := scan(t, scanner, srv.addr, "")
	if status != zgrab2.SCAN_SUCCESS || err != nil {
		t.Fatalf("status = %s, err = %v", status, err)
	}
	if log.VersionNegotiation == nil || log.Handshake != nil {
		t.Errorf("unexpected result %+v", log)
	}
}

func TestScanSkipVersionNegotiation(t *testing.T) {
	srv := startTestServer(t, false)
	scanner := newTestScanner(t, func(f *Flags) { f.SkipVersionNegotiation = true })
	status, log, err := scan(t, scanner, srv.addr, "")
	if status != zgrab2.SCAN_SUCCESS || err != nil {
		t.Fatalf("status = %s, err = %v", status, err)
	}
	if log.VersionNegotiation != nil || log.Handshake == nil || !log.Handshake.Complete {
		t.Errorf("unexpected result %+v", log)
	}
}

func TestScanNoResponse(t *testing.T) {
	addr := startSilentServer(t)
	scanner := newTestScanner(t, func(f *Flags) {
		f.ProbeTimeout = 200 * time.Millisecond
		f.HandshakeTimeout = 500 * time.Millisecond
	})
	start := time.Now()
	status, log, err := scan(t, scanner, addr, "")
	if status != zgrab2.SCAN_IO_TIMEOUT || err == nil {
		t.Fatalf("status = %s, err = %v; want io-timeout", status, err)
	}
	if log != nil {
		t.Errorf("expected no result, got %+v", log)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("scan took %v; timeouts not honored", elapsed)
	}

	// With only the probe enabled, a silent target is also a timeout.
	scanner = newTestScanner(t, func(f *Flags) {
		f.ProbeTimeout = 200 * time.Millisecond
		f.SkipHandshake = true
	})
	if status, _, err := scan(t, scanner, addr, ""); status != zgrab2.SCAN_IO_TIMEOUT || err == nil {
		t.Errorf("probe-only: status = %s, err = %v; want io-timeout", status, err)
	}
}

func TestFlagsValidate(t *testing.T) {
	if err := (Flags{ALPN: "h3"}).Validate(nil); err != nil {
		t.Errorf("valid flags rejected: %v", err)
	}
	if err := (Flags{ALPN: " , "}).Validate(nil); err == nil {
		t.Error("empty ALPN list accepted")
	}
	if err := (Flags{ALPN: "", SkipHandshake: true}).Validate(nil); err != nil {
		t.Errorf("empty ALPN should be fine when the handshake is skipped: %v", err)
	}
	if err := (Flags{ALPN: "h3", SkipHandshake: true, SkipVersionNegotiation: true}).Validate(nil); err == nil {
		t.Error("skipping both steps accepted")
	}
}

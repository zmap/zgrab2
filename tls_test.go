package zgrab2

import (
	"crypto/rand"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	zcryptotls "github.com/zmap/zcrypto/tls"
)

// generateTLSTestCert generates a self-signed RSA certificate for use in tests.
// Uses stdlib crypto/x509 so the server side can use stdlib crypto/tls.
func generateTLSTestCert(t *testing.T) stdtls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := stdtls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("create TLS cert: %v", err)
	}

	return cert
}

func TestHandshakeCompletedSuccessfully_FalseAfterFailedHandshake(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	// Close server immediately so the TLS handshake has nowhere to go.
	serverConn.Close()

	tlsConn := TLSConnection{
		Conn: *zcryptotls.Client(clientConn, &zcryptotls.Config{InsecureSkipVerify: true}),
	}
	_ = tlsConn.Handshake() // expected to fail

	log := tlsConn.GetLog()
	if log.HandshakeCompletedSuccessfully {
		t.Error("HandshakeCompletedSuccessfully should be false after a failed handshake")
	}
}

func TestHandshakeCompletedSuccessfully_TrueAfterSuccessfulHandshake(t *testing.T) {
	cert := generateTLSTestCert(t)
	clientConn, serverConn := net.Pipe()

	done := make(chan error, 1)
	go func() {
		srv := stdtls.Server(serverConn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
		done <- srv.Handshake()
		srv.Close()
	}()

	flags := &TLSFlags{EnableJA4SSignatures: true}
	tlsConn := TLSConnection{
		Conn:  *zcryptotls.Client(clientConn, &zcryptotls.Config{InsecureSkipVerify: true}),
		flags: flags,
	}
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("unexpected handshake error: %v", err)
	}
	if srvErr := <-done; srvErr != nil {
		t.Fatalf("server-side handshake error: %v", srvErr)
	}

	log := tlsConn.GetLog()
	if !log.HandshakeCompletedSuccessfully {
		t.Error("HandshakeCompletedSuccessfully should be true after a successful handshake")
	}
}

func TestTLSLogJSON(t *testing.T) {
	t.Run("ja3s and ja4s omitted when empty", func(t *testing.T) {
		tlsLog := &TLSLog{
			HandshakeLog: &zcryptotls.ServerHandshake{},
		}
		b, err := json.Marshal(tlsLog)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if strings.Contains(s, "ja3s") {
			t.Errorf("expected ja3s to be omitted when empty, got: %s", s)
		}
		if strings.Contains(s, "ja4s") {
			t.Errorf("expected ja4s to be omitted when empty, got: %s", s)
		}
	})

	t.Run("ja3s and ja4s present when set", func(t *testing.T) {
		tlsLog := &TLSLog{
			HandshakeLog: &zcryptotls.ServerHandshake{},
			JA3S:         "eb1d94daa7e0344597e756a1fb6e7054",
			JA4S:         "t130200_1301_234ea6891581",
		}
		b, err := json.Marshal(tlsLog)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		if got, ok := out["ja3s"]; !ok || got != tlsLog.JA3S {
			t.Errorf("ja3s: got %v, want %q", got, tlsLog.JA3S)
		}
		if got, ok := out["ja4s"]; !ok || got != tlsLog.JA4S {
			t.Errorf("ja4s: got %v, want %q", got, tlsLog.JA4S)
		}
	})

	t.Run("handshake_log always present even when nil", func(t *testing.T) {
		tlsLog := &TLSLog{}
		b, err := json.Marshal(tlsLog)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "handshake_log") {
			t.Errorf("expected handshake_log key to always be present, got: %s", string(b))
		}
	})
}

func TestHandshakeJA3SAlwaysComputed(t *testing.T) {
	cert := generateTLSTestCert(t)
	clientConn, serverConn := net.Pipe()

	done := make(chan error, 1)
	go func() {
		srv := stdtls.Server(serverConn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
		done <- srv.Handshake()
		srv.Close()
	}()

	tlsConn := TLSConnection{
		Conn: *zcryptotls.Client(clientConn, &zcryptotls.Config{InsecureSkipVerify: true}),
	}
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("unexpected handshake error: %v", err)
	}
	if srvErr := <-done; srvErr != nil {
		t.Fatalf("server-side handshake error: %v", srvErr)
	}

	tlsLog := tlsConn.GetLog()
	if tlsLog.JA3S == "" {
		t.Error("JA3S should be computed after a successful handshake (always enabled)")
	}
	if tlsLog.JA4S != "" {
		t.Error("JA4S should not be computed when --enable-ja4s-signatures flag is not set")
	}
}

func TestHandshakeJA4SComputedOnlyWhenEnabled(t *testing.T) {
	cert := generateTLSTestCert(t)
	clientConn, serverConn := net.Pipe()

	done := make(chan error, 1)
	go func() {
		srv := stdtls.Server(serverConn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
		done <- srv.Handshake()
		srv.Close()
	}()

	flags := &TLSFlags{EnableJA4SSignatures: true}
	tlsConn := TLSConnection{
		Conn:  *zcryptotls.Client(clientConn, &zcryptotls.Config{InsecureSkipVerify: true}),
		flags: flags,
	}
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("unexpected handshake error: %v", err)
	}
	if srvErr := <-done; srvErr != nil {
		t.Fatalf("server-side handshake error: %v", srvErr)
	}

	tlsLog := tlsConn.GetLog()
	if tlsLog.JA3S == "" {
		t.Error("JA3S should be computed after a successful handshake")
	}
	if tlsLog.JA4S == "" {
		t.Error("JA4S should be computed when --enable-ja4s-signatures is set")
	}
}

// generateZcryptoCert creates a self-signed RSA cert for use with zcrypto's tls.Server.
// The existing generateTLSTestCert returns a stdlib cert; this one returns a zcrypto cert
// so the server side can use zcrypto's GetHandshakeLog and GetConfigForClient.
func generateZcryptoCert(t *testing.T) zcryptotls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := zcryptotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("create zcrypto TLS cert: %v", err)
	}
	return cert
}

// ---- Tier 1: Config-level tests ----
// These test that TLSFlags.GetTLSConfigForTarget correctly translates CLI flags
// into the right tls.Config fields. No network required; failures here mean the
// flag is mis-parsed or not wired into the config at all.

func TestGetTLSConfig_CipherSuiteHex(t *testing.T) {
	// Scenario: --cipher-suite given as hex value(s). Assert tls.Config.CipherSuites
	// is set to exactly the parsed values in the given order.
	tests := []struct {
		flag       string
		wantSuites []uint16
	}{
		{"0x1301", []uint16{0x1301}},
		{"0x1301,0x1302", []uint16{0x1301, 0x1302}},
		{"1301", []uint16{0x1301}}, // without 0x prefix
		{"0x1301, 0x1302", []uint16{0x1301, 0x1302}}, // spaces around comma
	}
	for _, tt := range tests {
		t.Run(tt.flag, func(t *testing.T) {
			flags := &TLSFlags{CipherSuite: tt.flag}
			cfg, err := flags.GetTLSConfigForTarget(nil)
			if err != nil {
				t.Fatalf("GetTLSConfigForTarget: %v", err)
			}
			if !slices.Equal(cfg.CipherSuites, tt.wantSuites) {
				t.Errorf("CipherSuites: got %#04x, want %#04x", cfg.CipherSuites, tt.wantSuites)
			}
		})
	}
}

func TestGetTLSConfig_CipherSuiteNamedGroup(t *testing.T) {
	// Scenario: --cipher-suite given as a named group (e.g. "chrome-only"). Assert
	// tls.Config.CipherSuites is set to the corresponding zcrypto preset slice.
	tests := []struct {
		name       string
		flag       string
		wantSuites []uint16
	}{
		{"chrome-only", "chrome-only", zcryptotls.ChromeCiphers},
		{"firefox-only", "firefox-only", zcryptotls.FirefoxCiphers},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := &TLSFlags{CipherSuite: tt.flag}
			cfg, err := flags.GetTLSConfigForTarget(nil)
			if err != nil {
				t.Fatalf("GetTLSConfigForTarget: %v", err)
			}
			if !slices.Equal(cfg.CipherSuites, tt.wantSuites) {
				t.Errorf("CipherSuites: got %v, want %v", cfg.CipherSuites, tt.wantSuites)
			}
		})
	}
}

func TestGetTLSConfig_MinMaxVersion(t *testing.T) {
	// Scenario: --min-version and --max-version set. Assert tls.Config.MinVersion
	// and MaxVersion are wired to the values given by the flags.
	flags := &TLSFlags{
		MinVersion: zcryptotls.VersionTLS12,
		MaxVersion: zcryptotls.VersionTLS13,
	}
	cfg, err := flags.GetTLSConfigForTarget(nil)
	if err != nil {
		t.Fatalf("GetTLSConfigForTarget: %v", err)
	}
	if cfg.MinVersion != zcryptotls.VersionTLS12 {
		t.Errorf("MinVersion: got %d, want %d", cfg.MinVersion, zcryptotls.VersionTLS12)
	}
	if cfg.MaxVersion != zcryptotls.VersionTLS13 {
		t.Errorf("MaxVersion: got %d, want %d", cfg.MaxVersion, zcryptotls.VersionTLS13)
	}
}

func TestGetTLSConfig_NoECDHE(t *testing.T) {
	// Scenario: --no-ecdhe set. Assert ExplicitCurvePreferences is true and
	// CurvePreferences is nil, which together tell zcrypto to omit the supported_curves
	// extension and decline ECDHE key exchange entirely.
	flags := &TLSFlags{NoECDHE: true}
	cfg, err := flags.GetTLSConfigForTarget(nil)
	if err != nil {
		t.Fatalf("GetTLSConfigForTarget: %v", err)
	}
	if !cfg.ExplicitCurvePreferences {
		t.Error("ExplicitCurvePreferences should be true when --no-ecdhe is set")
	}
	if len(cfg.CurvePreferences) != 0 {
		t.Errorf("CurvePreferences should be nil when --no-ecdhe is set, got: %v", cfg.CurvePreferences)
	}
}

// ---- Tier 2: ClientHello inspection tests ----
// These verify that flags produce the correct advertisement in the ClientHello
// by capturing ClientHelloInfo via GetConfigForClient on a zcrypto server.
// Failures here mean the flag is parsed into tls.Config correctly (tier 1 passes)
// but zcrypto is not respecting the config when building the ClientHello.

func runZcryptoHandshakeWithCapture(t *testing.T, clientCfg *zcryptotls.Config, capture func(*zcryptotls.ClientHelloInfo)) error {
	t.Helper()
	cert := generateZcryptoCert(t)
	clientConn, serverConn := net.Pipe()

	done := make(chan error, 1)
	go func() {
		srv := zcryptotls.Server(serverConn, &zcryptotls.Config{
			Certificates: []zcryptotls.Certificate{cert},
			GetConfigForClient: func(chi *zcryptotls.ClientHelloInfo) (*zcryptotls.Config, error) {
				capture(chi)
				return nil, nil // proceed with original server config
			},
		})
		done <- srv.Handshake()
		srv.Close()
	}()

	clientCfg.InsecureSkipVerify = true
	tlsConn := TLSConnection{Conn: *zcryptotls.Client(clientConn, clientCfg)}
	clientErr := tlsConn.Handshake()
	<-done
	return clientErr
}

func TestClientHello_AdvertisedCipherSuites(t *testing.T) {
	// Scenario: --cipher-suite 0x1302 with TLS 1.3 minimum. Assert that only
	// TLS_AES_256_GCM_SHA384 appears in the ClientHello cipher suite list, and that
	// the other two TLS 1.3 suites (0x1301, 0x1303) are absent. This catches the class
	// of bug where zcrypto ignores CipherSuites and always sends the full TLS 1.3 set.
	wantSuites := []uint16{zcryptotls.TLS_AES_256_GCM_SHA384} // only one TLS 1.3 cipher

	flags := &TLSFlags{
		CipherSuite: "0x1302",
		MinVersion:  zcryptotls.VersionTLS13,
	}
	clientCfg, err := flags.GetTLSConfigForTarget(nil)
	if err != nil {
		t.Fatalf("GetTLSConfigForTarget: %v", err)
	}

	var gotSuites []uint16
	if err := runZcryptoHandshakeWithCapture(t, clientCfg, func(chi *zcryptotls.ClientHelloInfo) {
		gotSuites = chi.CipherSuites
	}); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	if !slices.Contains(gotSuites, wantSuites[0]) {
		t.Errorf("ClientHello cipher suites %#04x missing expected suite 0x%04x", gotSuites, wantSuites[0])
	}
	for _, s := range gotSuites {
		// TLS 1.3 suites are 0x1301–0x1303; verify no unrequested ones appear
		if s == zcryptotls.TLS_AES_128_GCM_SHA256 || s == zcryptotls.TLS_CHACHA20_POLY1305_SHA256 {
			t.Errorf("ClientHello advertised unrequested TLS 1.3 cipher 0x%04x", s)
		}
	}
}

func TestClientHello_AdvertisedCurves(t *testing.T) {
	// Scenario: CurvePreferences restricted to P-256 with ExplicitCurvePreferences set.
	// Assert only P-256 appears in the ClientHello supported_curves extension.
	// Note: --curve-preferences is not yet implemented as a flag, so this test sets
	// the config directly to verify zcrypto's curve handling in isolation.
	clientCfg := &zcryptotls.Config{
		CurvePreferences:       []zcryptotls.CurveID{zcryptotls.CurveP256},
		ExplicitCurvePreferences: true,
	}

	var gotCurves []zcryptotls.CurveID
	if err := runZcryptoHandshakeWithCapture(t, clientCfg, func(chi *zcryptotls.ClientHelloInfo) {
		gotCurves = chi.SupportedCurves
	}); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	if !slices.Contains(gotCurves, zcryptotls.CurveP256) {
		t.Errorf("ClientHello missing expected curve P-256; got %v", gotCurves)
	}
	for _, c := range gotCurves {
		if c == zcryptotls.CurveP384 || c == zcryptotls.CurveP521 || c == zcryptotls.X25519 {
			t.Errorf("ClientHello advertised unrequested curve %v", c)
		}
	}
}

// ---- Tier 3: Negotiation tests ----
// These assert on what was actually chosen by the server, using HandshakeLog
// which zgrab2 already captures. The server is configured to only accept a
// specific cipher/version so we can assert the outcome precisely.
// Failures here that pass tier 1 and tier 2 indicate the bug is in zcrypto,
// not in zgrab2's flag wiring.

func runZcryptoHandshakeWithServerConfig(t *testing.T, clientCfg *zcryptotls.Config, serverCfg *zcryptotls.Config) (*TLSConnection, error) {
	t.Helper()
	cert := generateZcryptoCert(t)
	clientConn, serverConn := net.Pipe()

	serverCfg.Certificates = []zcryptotls.Certificate{cert}
	done := make(chan error, 1)
	go func() {
		srv := zcryptotls.Server(serverConn, serverCfg)
		done <- srv.Handshake()
		srv.Close()
	}()

	clientCfg.InsecureSkipVerify = true
	tlsConn := &TLSConnection{Conn: *zcryptotls.Client(clientConn, clientCfg)}
	clientErr := tlsConn.Handshake()
	<-done
	return tlsConn, clientErr
}

func TestNegotiated_CipherSuite_TLS13(t *testing.T) {
	// Client requests only TLS_AES_256_GCM_SHA384; server accepts only that cipher.
	// Assert the negotiated cipher matches — this is the exact scenario that was broken
	// before the zcrypto fix where TLS 1.3 cipher suites were always sent as the full set.
	const wantCipher = zcryptotls.TLS_AES_256_GCM_SHA384

	flags := &TLSFlags{
		CipherSuite: "0x1302",
		MinVersion:  zcryptotls.VersionTLS13,
	}
	clientCfg, err := flags.GetTLSConfigForTarget(nil)
	if err != nil {
		t.Fatalf("GetTLSConfigForTarget: %v", err)
	}

	serverCfg := &zcryptotls.Config{
		CipherSuites:             []uint16{wantCipher},
		PreferServerCipherSuites: true,
		MinVersion:               zcryptotls.VersionTLS13,
	}

	conn, err := runZcryptoHandshakeWithServerConfig(t, clientCfg, serverCfg)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	log := conn.GetLog()
	if log.HandshakeLog == nil || log.HandshakeLog.ServerHello == nil {
		t.Fatal("no ServerHello in handshake log")
	}
	got := uint16(log.HandshakeLog.ServerHello.CipherSuite)
	if got != wantCipher {
		t.Errorf("negotiated cipher: got 0x%04x, want 0x%04x", got, wantCipher)
	}
}

func TestNegotiated_CipherSuite_TLS13_MismatchFails(t *testing.T) {
	// Client restricted to TLS_AES_256_GCM_SHA384 (0x1302).
	// Server only accepts TLS_AES_128_GCM_SHA256 (0x1301).
	// With the zcrypto fix: client only advertises 0x1302 → no common cipher → handshake fails.
	// Without the fix: client advertises all TLS 1.3 ciphers → handshake wrongly succeeds.
	flags := &TLSFlags{
		CipherSuite: "0x1302",
		MinVersion:  zcryptotls.VersionTLS13,
	}
	clientCfg, err := flags.GetTLSConfigForTarget(nil)
	if err != nil {
		t.Fatalf("GetTLSConfigForTarget: %v", err)
	}

	serverCfg := &zcryptotls.Config{
		CipherSuites:             []uint16{zcryptotls.TLS_AES_128_GCM_SHA256},
		PreferServerCipherSuites: true,
		MinVersion:               zcryptotls.VersionTLS13,
	}

	_, err = runZcryptoHandshakeWithServerConfig(t, clientCfg, serverCfg)
	if err == nil {
		t.Error("expected handshake to fail when client and server have no cipher suites in common, but it succeeded")
	}
}

func TestNegotiated_CipherSuite_TLS12(t *testing.T) {
	// Scenario: --cipher-suite 0xC02F (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) with
	// TLS 1.2 pinned on both sides. Assert HandshakeLog.ServerHello.CipherSuite == 0xC02F.
	// Covers the same negotiation correctness check as the TLS 1.3 test but for TLS 1.2.
	const wantCipher = uint16(zcryptotls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	flags := &TLSFlags{
		CipherSuite: "0xC02F", // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		MinVersion:  zcryptotls.VersionTLS12,
		MaxVersion:  zcryptotls.VersionTLS12,
	}
	clientCfg, err := flags.GetTLSConfigForTarget(nil)
	if err != nil {
		t.Fatalf("GetTLSConfigForTarget: %v", err)
	}

	serverCfg := &zcryptotls.Config{
		CipherSuites:             []uint16{wantCipher},
		PreferServerCipherSuites: true,
		MaxVersion:               zcryptotls.VersionTLS12,
	}

	conn, err := runZcryptoHandshakeWithServerConfig(t, clientCfg, serverCfg)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	log := conn.GetLog()
	if log.HandshakeLog == nil || log.HandshakeLog.ServerHello == nil {
		t.Fatal("no ServerHello in handshake log")
	}
	got := uint16(log.HandshakeLog.ServerHello.CipherSuite)
	if got != wantCipher {
		t.Errorf("negotiated cipher: got 0x%04x, want 0x%04x", got, wantCipher)
	}
}

// ---- Curve preference tests (tier 1, 2, 3) ----

func TestGetTLSConfig_EnableMLKEM(t *testing.T) {
	// Scenario: --enable-mlkem set. Assert CurvePreferences has X25519MLKEM768 as the
	// first entry, followed by the standard ECDHE curves, so that PQ hybrid key exchange
	// is attempted before classical curves.
	flags := &TLSFlags{EnableMLKEM: true}
	cfg, err := flags.GetTLSConfigForTarget(nil)
	if err != nil {
		t.Fatalf("GetTLSConfigForTarget: %v", err)
	}
	if len(cfg.CurvePreferences) == 0 {
		t.Fatal("CurvePreferences should be non-empty when --enable-mlkem is set")
	}
	if cfg.CurvePreferences[0] != zcryptotls.X25519MLKEM768 {
		t.Errorf("CurvePreferences[0]: got %v, want X25519MLKEM768", cfg.CurvePreferences[0])
	}
	if !slices.Contains(cfg.CurvePreferences, zcryptotls.X25519) {
		t.Error("CurvePreferences should include X25519 when --enable-mlkem is set")
	}
}

func TestClientHello_AdvertisedCurves_EnableMLKEM(t *testing.T) {
	// Scenario: --enable-mlkem set. Assert that X25519MLKEM768 appears in the
	// ClientHello supported_curves extension, verifying the flag is plumbed through
	// GetTLSConfigForTarget all the way into what zcrypto puts on the wire.
	flags := &TLSFlags{EnableMLKEM: true}
	clientCfg, err := flags.GetTLSConfigForTarget(nil)
	if err != nil {
		t.Fatalf("GetTLSConfigForTarget: %v", err)
	}

	var gotCurves []zcryptotls.CurveID
	if err := runZcryptoHandshakeWithCapture(t, clientCfg, func(chi *zcryptotls.ClientHelloInfo) {
		gotCurves = chi.SupportedCurves
	}); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	if !slices.Contains(gotCurves, zcryptotls.X25519MLKEM768) {
		t.Errorf("ClientHello missing X25519MLKEM768; got curves: %v", gotCurves)
	}
}

func TestNegotiated_Curve_TLS13(t *testing.T) {
	// Scenario: Client and server both configured with only X25519. Assert that
	// HandshakeLog.ServerHello.KeyShare.KeyExchange == X25519, confirming that
	// CurvePreferences is honored end-to-end during TLS 1.3 key exchange.
	flags := &TLSFlags{
		MinVersion: zcryptotls.VersionTLS13,
	}
	clientCfg, err := flags.GetTLSConfigForTarget(nil)
	if err != nil {
		t.Fatalf("GetTLSConfigForTarget: %v", err)
	}
	clientCfg.CurvePreferences = []zcryptotls.CurveID{zcryptotls.X25519}
	clientCfg.ExplicitCurvePreferences = true

	serverCfg := &zcryptotls.Config{
		CurvePreferences:         []zcryptotls.CurveID{zcryptotls.X25519},
		ExplicitCurvePreferences: true,
		MinVersion:               zcryptotls.VersionTLS13,
	}

	conn, err := runZcryptoHandshakeWithServerConfig(t, clientCfg, serverCfg)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	log := conn.GetLog()
	if log.HandshakeLog == nil || log.HandshakeLog.ServerHello == nil {
		t.Fatal("no ServerHello in handshake log")
	}
	ks := log.HandshakeLog.ServerHello.KeyShare
	if ks == nil || ks.KeyExchange == nil {
		t.Fatal("no KeyShare in ServerHello")
	}
	if *ks.KeyExchange != zcryptotls.X25519 {
		t.Errorf("negotiated curve: got %v, want X25519", *ks.KeyExchange)
	}
}

func TestNegotiated_Curve_TLS13_MismatchFails(t *testing.T) {
	// Scenario: Client configured with only P-256; server configured with only P-384.
	// Assert the handshake fails because there is no common key exchange group.
	// This mirrors the cipher suite mismatch test and catches bugs where curve
	// preferences on the client are silently ignored.
	flags := &TLSFlags{
		MinVersion: zcryptotls.VersionTLS13,
	}
	clientCfg, err := flags.GetTLSConfigForTarget(nil)
	if err != nil {
		t.Fatalf("GetTLSConfigForTarget: %v", err)
	}
	clientCfg.CurvePreferences = []zcryptotls.CurveID{zcryptotls.CurveP256}
	clientCfg.ExplicitCurvePreferences = true

	serverCfg := &zcryptotls.Config{
		CurvePreferences:         []zcryptotls.CurveID{zcryptotls.CurveP384},
		ExplicitCurvePreferences: true,
		MinVersion:               zcryptotls.VersionTLS13,
	}

	_, err = runZcryptoHandshakeWithServerConfig(t, clientCfg, serverCfg)
	if err == nil {
		t.Error("expected handshake to fail when client and server have no curve in common, but it succeeded")
	}
}

// ---- Signature scheme tests (tier 1, 2) ----
// Note: --signature-algorithms is not yet implemented as a flag, and
// Config.SignatureAndHashes does not control what is advertised in the ClientHello
// (zcrypto hardcodes the list in handshake_client.go). These tests document current
// advertised behavior and will be extended once the flag is implemented.

func TestGetTLSConfig_OverrideSH(t *testing.T) {
	// Scenario: --override-sig-hash set. Assert Config.SignatureAndHashes is populated
	// with the expanded set. Note this controls which server signatures the client will
	// *accept*, not what it advertises in the ClientHello (see tier 2 test below).
	flags := &TLSFlags{OverrideSH: true}
	cfg, err := flags.GetTLSConfigForTarget(nil)
	if err != nil {
		t.Fatalf("GetTLSConfigForTarget: %v", err)
	}
	if len(cfg.SignatureAndHashes) == 0 {
		t.Error("SignatureAndHashes should be populated when --override-sig-hash is set")
	}
}

func TestClientHello_AdvertisedSignatureSchemes(t *testing.T) {
	// Scenario: Default TLS config (no signature flags set). Assert that the ClientHello
	// signature_algorithms extension contains the expected zcrypto defaults: at minimum
	// PSSWithSHA256, ECDSAWithP256AndSHA256, and PKCS1WithSHA256.
	//
	// This test documents the current hardcoded behavior in zcrypto's handshake_client.go.
	// When --signature-algorithms is implemented, this test should be updated to drive
	// the advertised list through flags and assert specific overrides here.
	clientCfg := &zcryptotls.Config{}

	var gotSchemes []zcryptotls.SignatureScheme
	if err := runZcryptoHandshakeWithCapture(t, clientCfg, func(chi *zcryptotls.ClientHelloInfo) {
		gotSchemes = chi.SignatureSchemes
	}); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	wantPresent := []zcryptotls.SignatureScheme{
		zcryptotls.PSSWithSHA256,
		zcryptotls.ECDSAWithP256AndSHA256,
		zcryptotls.PKCS1WithSHA256,
	}
	for _, want := range wantPresent {
		if !slices.Contains(gotSchemes, want) {
			t.Errorf("ClientHello missing expected signature scheme 0x%04x; got: %v", want, gotSchemes)
		}
	}
}

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

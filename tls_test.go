package zgrab2

import (
	"crypto/rand"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
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

	tlsConn := TLSConnection{
		Conn: *zcryptotls.Client(clientConn, &zcryptotls.Config{InsecureSkipVerify: true}),
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

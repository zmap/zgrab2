package smtp

import (
	stdtls "crypto/tls"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"context"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	zcryptotls "github.com/zmap/zcrypto/tls"
	"github.com/zmap/zgrab2"
)

func TestVerifySMTPContents(t *testing.T) {
	type Test struct {
		Banner         string
		ExpectedStatus zgrab2.ScanStatus
		ExpectedCode   int
	}
	testTable := map[string]Test{
		"success with code": {
			Banner: `220-some.host.com ESMTP Exim 4.93 #2 Thu, 04 Feb 2021 13:34:12 -0500
220-We do not authorize the use of this system to transport unsolicited,
220 and/or bulk e-mail.`,
			ExpectedStatus: zgrab2.SCAN_SUCCESS,
			ExpectedCode:   0,
		},
		"success without code": {
			Banner: `ESMTP Exim 4.93 #2 Thu, 04 Feb 2021 13:34:12 -0500
220-We do not authorize the use of this system to transport unsolicited,
220 and/or bulk e-mail.`,
			ExpectedStatus: zgrab2.SCAN_SUCCESS,
			ExpectedCode:   0,
		},
		"invalid protocol": {
			Banner:         "gibberish that doesnt match expected response",
			ExpectedStatus: zgrab2.SCAN_PROTOCOL_ERROR,
			ExpectedCode:   0,
		},
		"error response": {
			Banner:         "500-some.host.com ESMTP something went horribly wrong.",
			ExpectedStatus: zgrab2.SCAN_APPLICATION_ERROR,
			ExpectedCode:   500,
		},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			status, code := VerifySMTPContents(test.Banner)
			if status != test.ExpectedStatus {
				t.Errorf("recieved unexpected status: %s, wanted: %s", status, test.ExpectedStatus)
			}
			if code != test.ExpectedCode {
				t.Errorf("recieved unexpected code: %d, wanted: %d", code, test.ExpectedCode)
			}
		})
	}
}

// makeL4Dialer returns an L4Dialer that always returns conn.
func makeL4Dialer(conn net.Conn) func(*zgrab2.ScanTarget) func(context.Context, string, string) (net.Conn, error) {
	return func(*zgrab2.ScanTarget) func(context.Context, string, string) (net.Conn, error) {
		return func(context.Context, string, string) (net.Conn, error) {
			return conn, nil
		}
	}
}

// generateSMTPTestCert generates a throwaway self-signed RSA certificate for
// use in TLS tests. Uses stdlib crypto so the server side can use stdlib crypto/tls.
func generateSMTPTestCert(t *testing.T) stdtls.Certificate {
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

// TestScanSMTPSHandshakeError verifies that when the TLS wrapper fails during
// an implicit-TLS (SMTPS) scan, the scanner returns SCAN_HANDSHAKE_ERROR.
func TestScanSMTPSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	scanner := &Scanner{config: &Flags{SMTPSecure: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 465}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer: makeL4Dialer(clientConn),
		TLSWrapper: func(_ context.Context, _ *zgrab2.ScanTarget, conn net.Conn) (*zgrab2.TLSConnection, error) {
			conn.Close()

			return nil, errors.New("tls: handshake failure")
		},
	}

	status, _, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
}

// TestScanSTARTTLSHandshakeError verifies that when the TLS upgrade fails
// after the STARTTLS command is accepted, the scanner returns SCAN_HANDSHAKE_ERROR.
func TestScanSTARTTLSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	// Fake SMTP server: send banner, handle EHLO, accept STARTTLS, then the
	// TLSWrapper mock will return an error before any further I/O.
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 512)
		serverConn.Write([]byte("220 test.example.com ESMTP\r\n"))
		serverConn.Read(buf)                                                 // EHLO
		serverConn.Write([]byte("250-test.example.com\r\n250 STARTTLS\r\n")) // advertise STARTTLS
		serverConn.Read(buf)                                                 // STARTTLS command
		serverConn.Write([]byte("220 Ready to start TLS\r\n"))
		// TLSWrapper is called next; it returns an error and we're done.
	}()

	scanner := &Scanner{config: &Flags{}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 587}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer: makeL4Dialer(clientConn),
		TLSWrapper: func(_ context.Context, _ *zgrab2.ScanTarget, conn net.Conn) (*zgrab2.TLSConnection, error) {
			return nil, errors.New("tls: handshake failure")
		},
	}

	status, _, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
}

// TestScanSMTPSAppError verifies that when the TLS handshake succeeds but the
// server sends an SMTP error banner over TLS, the scanner returns
// SCAN_TLS_APPLICATION_ERROR with HandshakeComplete = true in TLSLog.
func TestScanSMTPSAppError(t *testing.T) {
	cert := generateSMTPTestCert(t)
	clientConn, serverConn := net.Pipe()

	// Real TLS server: complete the handshake, then send an SMTP error banner.
	srvDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		srv := stdtls.Server(serverConn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
		if err := srv.Handshake(); err != nil {
			srvDone <- err

			return
		}
		srv.Write([]byte("500 Server Error\r\n"))
		srvDone <- nil
	}()

	scanner := &Scanner{config: &Flags{SMTPSecure: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 465}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer: makeL4Dialer(clientConn),
		// Use the real TLS wrapper with InsecureSkipVerify so our self-signed
		// test cert is accepted by the zcrypto client.
		TLSWrapper: zgrab2.GetDefaultTLSWrapper(&zgrab2.TLSFlags{
			Config: &zcryptotls.Config{InsecureSkipVerify: true},
		}),
	}

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)

	if err := <-srvDone; err != nil {
		t.Fatalf("server-side TLS handshake error: %v", err)
	}
	if status != zgrab2.SCAN_TLS_APPLICATION_ERROR {
		t.Errorf("expected SCAN_TLS_APPLICATION_ERROR, got %s", status)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	smtpResult := result.(*ScanResults)
	if smtpResult.TLSLog == nil {
		t.Fatal("expected TLSLog to be populated")
	}
	if !smtpResult.TLSLog.HandshakeComplete {
		t.Error("expected HandshakeComplete = true after successful TLS handshake")
	}
}

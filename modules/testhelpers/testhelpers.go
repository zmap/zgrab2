// Package testhelpers provides shared utilities for zgrab2 module scanner tests.
package testhelpers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	zcryptotls "github.com/zmap/zcrypto/tls"

	"github.com/zmap/zgrab2"
)

// MakeL4Dialer returns an L4Dialer that always returns conn regardless of the
// target or address arguments.
func MakeL4Dialer(conn net.Conn) func(*zgrab2.ScanTarget) func(context.Context, string, string) (net.Conn, error) {
	return func(*zgrab2.ScanTarget) func(context.Context, string, string) (net.Conn, error) {
		return func(context.Context, string, string) (net.Conn, error) {
			return conn, nil
		}
	}
}

// GenerateTestCert generates a throwaway self-signed RSA certificate suitable
// for use in TLS tests. The server side can use stdlib crypto/tls with this
// certificate and the client side can accept it with InsecureSkipVerify.
func GenerateTestCert(t *testing.T) stdtls.Certificate {
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
		t.Fatalf("load TLS cert: %v", err)
	}

	return cert
}

// RunTLSServer starts a stdlib TLS server on serverConn using cert, completes
// the handshake, calls fn with the established connection for any
// protocol-specific writes, and returns a channel that receives the first
// server-side error (nil on success). The caller should drain the channel to
// detect handshake failures in the server goroutine.
func RunTLSServer(t *testing.T, serverConn net.Conn, cert stdtls.Certificate, fn func(*stdtls.Conn)) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		srv := stdtls.Server(serverConn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
		if err := srv.Handshake(); err != nil {
			done <- err

			return
		}
		fn(srv)
		done <- nil
	}()

	return done
}

// MakeFailingTLSWrapper returns a TLS wrapper that immediately returns a
// handshake error without attempting a real handshake.
func MakeFailingTLSWrapper() func(context.Context, *zgrab2.ScanTarget, net.Conn) (*zgrab2.TLSConnection, error) {
	return func(_ context.Context, _ *zgrab2.ScanTarget, _ net.Conn) (*zgrab2.TLSConnection, error) {
		return nil, errors.New("tls: handshake failure")
	}
}

// MakeInsecureTLSWrapper returns a real zcrypto TLS wrapper with
// InsecureSkipVerify set, allowing it to accept the self-signed test
// certificates produced by GenerateTestCert.
func MakeInsecureTLSWrapper() func(context.Context, *zgrab2.ScanTarget, net.Conn) (*zgrab2.TLSConnection, error) {
	return zgrab2.GetDefaultTLSWrapper(&zgrab2.BaseFlags{}, &zgrab2.TLSFlags{
		Config: &zcryptotls.Config{InsecureSkipVerify: true},
	})
}

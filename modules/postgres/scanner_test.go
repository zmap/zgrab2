package postgres

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"testing"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/testhelpers"
)

// runPostgresSSLServer accepts a single Postgres SSLRequest (8 bytes), replies
// 'S' (SSL supported), then calls fn with the raw conn for the TLS phase.
// Runs in a goroutine; the caller is responsible for closing serverConn via
// the done channel or fn.
func runPostgresSSLServer(serverConn net.Conn, fn func(net.Conn)) <-chan error {
	done := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 8)
		if _, err := serverConn.Read(buf); err != nil { // SSLRequest
			done <- err

			return
		}
		if _, err := serverConn.Write([]byte{'S'}); err != nil { // SSL supported
			done <- err

			return
		}
		fn(serverConn)
		done <- nil
	}()

	return done
}

func TestPostgresTLSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	srvDone := runPostgresSSLServer(serverConn, func(_ net.Conn) {
		// TLS wrapper is called next and fails; nothing to do here.
	})

	scanner := &Scanner{Config: &Flags{}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 5432}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}

	status, _, _ := scanner.Scan(context.Background(), dialGroup, target)
	if err := <-srvDone; err != nil {
		t.Logf("server goroutine: %v", err) // may see a write error after client fails
	}
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
}

func TestPostgresHandshakeCompletedSuccessfully(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()

	srvDone := runPostgresSSLServer(serverConn, func(conn net.Conn) {
		srv := stdtls.Server(conn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
		srv.Handshake() //nolint:errcheck // close is handled by defer in runPostgresSSLServer
		// Close after handshake; the scanner will get an error on its subsequent
		// StartupMessage write, but results.TLSLog will already be set.
	})

	scanner := &Scanner{Config: &Flags{}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 5432}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeInsecureTLSWrapper(),
	}

	_, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if err := <-srvDone; err != nil {
		t.Logf("server goroutine: %v", err)
	}
	// The scan may not return SCAN_SUCCESS (post-TLS postgres conversation
	// fails since the server closed), but TLSLog must be populated.
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	pgResult, ok := result.(*Results)
	if !ok {
		t.Fatal("expected *Results")
	}
	if pgResult.TLSLog == nil {
		t.Fatal("expected TLSLog to be populated")
	}
	if !pgResult.TLSLog.HandshakeCompletedSuccessfully {
		t.Error("expected HandshakeCompletedSuccessfully = true")
	}
}

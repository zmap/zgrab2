package managesieve

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/testhelpers"
)

// runManageSievePreTLS performs the pre-STARTTLS exchange on serverConn
// (banner → CAPABILITY → STARTTLS response) and then calls fn with serverConn
// so the caller can handle the TLS phase. Runs in a goroutine; closes
// serverConn when done.
func runManageSievePreTLS(serverConn net.Conn, fn func(net.Conn)) {
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 512)
		serverConn.Write([]byte("OK\r\n"))                 // initial greeting
		serverConn.Read(buf)                               // CAPABILITY command
		serverConn.Write([]byte("\"STARTTLS\"\r\nOK\r\n")) // capabilities with STARTTLS
		serverConn.Read(buf)                               // STARTTLS command
		serverConn.Write([]byte("OK\r\n"))                 // STARTTLS accepted
		fn(serverConn)
	}()
}

func TestManageSieveSTARTTLSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	runManageSievePreTLS(serverConn, func(_ net.Conn) {
		// TLS wrapper will be called next and will fail; nothing to do here.
	})

	scanner := &Scanner{config: &Flags{BannerTimeout: 5 * time.Second}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 4190}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
	if result == nil {
		t.Fatal("expected non-nil result on handshake error")
	}
}

func TestManageSievePostTLSCapabilitiesError(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()

	// Complete STARTTLS exchange and TLS handshake, then close without sending
	// post-TLS capabilities to trigger SCAN_POST_TLS_APPLICATION_ERROR.
	runManageSievePreTLS(serverConn, func(conn net.Conn) {
		srv := stdtls.Server(conn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
		srv.Handshake() //nolint:errcheck // close on error is handled by defer in runManageSievePreTLS
		// Close immediately — scanner's readResponse on the TLS conn will get EOF.
	})

	scanner := &Scanner{config: &Flags{BannerTimeout: 5 * time.Second}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 4190}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeInsecureTLSWrapper(),
	}

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status != zgrab2.SCAN_POST_TLS_APPLICATION_ERROR {
		t.Errorf("expected SCAN_POST_TLS_APPLICATION_ERROR, got %s", status)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	msResult, ok := result.(*ScanResults)
	if !ok {
		t.Fatal("expected *ScanResults")
	}
	if msResult.TLSLog == nil {
		t.Fatal("expected TLSLog to be populated")
	}
	if !msResult.TLSLog.HandshakeCompletedSuccessfully {
		t.Error("expected HandshakeCompletedSuccessfully = true after successful TLS handshake")
	}
}

func TestManageSieveHandshakeCompletedSuccessfully(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()

	done := make(chan error, 1)
	runManageSievePreTLS(serverConn, func(conn net.Conn) {
		srv := stdtls.Server(conn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
		if err := srv.Handshake(); err != nil {
			done <- err

			return
		}
		// Send post-TLS capabilities so the scanner reaches SCAN_SUCCESS.
		srv.Write([]byte("OK\r\n"))
		done <- nil
	})

	scanner := &Scanner{config: &Flags{BannerTimeout: 5 * time.Second}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 4190}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeInsecureTLSWrapper(),
	}

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if err := <-done; err != nil {
		t.Fatalf("server-side TLS error: %v", err)
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Errorf("expected SCAN_SUCCESS, got %s", status)
	}
	msResult, ok := result.(*ScanResults)
	if !ok || msResult == nil {
		t.Fatal("expected non-nil *ScanResults")
	}
	if msResult.TLSLog == nil {
		t.Fatal("expected TLSLog to be populated")
	}
	if !msResult.TLSLog.HandshakeCompletedSuccessfully {
		t.Error("expected HandshakeCompletedSuccessfully = true")
	}
}

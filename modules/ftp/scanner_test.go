package ftp

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"testing"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/testhelpers"
)

func TestFTPImplicitTLSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	scanner := &Scanner{config: &Flags{ImplicitTLS: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 990}
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

func TestFTPAuthTLSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	// Fake FTP server: send banner, accept AUTH TLS, then the TLS wrapper fails.
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 512)
		serverConn.Write([]byte("220 FTP server ready\r\n"))
		serverConn.Read(buf) // AUTH TLS
		serverConn.Write([]byte("234 AUTH TLS OK\r\n"))
	}()

	scanner := &Scanner{config: &Flags{FTPAuthTLS: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 21}
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

func TestFTPImplicitTLSHandshakeCompletedSuccessfully(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()

	srvDone := testhelpers.RunTLSServer(t, serverConn, cert, func(srv *stdtls.Conn) {
		srv.Write([]byte("220 FTP server ready\r\n"))
	})

	scanner := &Scanner{config: &Flags{ImplicitTLS: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 990}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeInsecureTLSWrapper(),
	}

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if err := <-srvDone; err != nil {
		t.Fatalf("server-side TLS error: %v", err)
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Errorf("expected SCAN_SUCCESS, got %s", status)
	}
	ftpResult, ok := result.(*ScanResults)
	if !ok || ftpResult == nil {
		t.Fatal("expected non-nil *ScanResults")
	}
	if ftpResult.TLSLog == nil {
		t.Fatal("expected TLSLog to be populated")
	}
	if !ftpResult.TLSLog.HandshakeCompletedSuccessfully {
		t.Error("expected HandshakeCompletedSuccessfully = true")
	}
}

package imap

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"testing"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/testhelpers"
)

func TestIMAPSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	scanner := &Scanner{config: &Flags{IMAPSecure: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 993}
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

func TestIMAPSTARTTLSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	go func() {
		defer serverConn.Close()
		buf := make([]byte, 512)
		serverConn.Write([]byte("* OK IMAP4 ready\r\n"))
		serverConn.Read(buf) // a001 STARTTLS
		serverConn.Write([]byte("a001 OK Begin TLS\r\n"))
	}()

	scanner := &Scanner{config: &Flags{StartTLS: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 143}
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

func TestIMAPSHandshakeCompletedSuccessfully(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()

	srvDone := testhelpers.RunTLSServer(t, serverConn, cert, func(srv *stdtls.Conn) {
		srv.Write([]byte("* OK IMAP4 ready\r\n"))
	})

	scanner := &Scanner{config: &Flags{IMAPSecure: true}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 993}
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
	imapResult, ok := result.(*ScanResults)
	if !ok || imapResult == nil {
		t.Fatal("expected non-nil *ScanResults")
	}
	if imapResult.TLSLog == nil {
		t.Fatal("expected TLSLog to be populated")
	}
	if !imapResult.TLSLog.HandshakeCompletedSuccessfully {
		t.Error("expected HandshakeCompletedSuccessfully = true")
	}
}

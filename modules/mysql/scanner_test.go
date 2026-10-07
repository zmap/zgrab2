package mysql

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"testing"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/modules/testhelpers"
)

// mysqlHandshakeV10 returns a minimal MySQL HandshakeV10 packet with the
// CLIENT_SSL capability flag set so that SupportsTLS() returns true.
//
// Byte layout (4-byte packet header + 38-byte payload):
//
//	header:  [0x26, 0x00, 0x00, 0x00]  length=38, sequence=0
//	payload: protocol_version(1) + server_version("5.7.0\0", 6) +
//	         connection_id(4) + auth_plugin_data_1(8) + filler(1) +
//	         capability_flags_lower(2, CLIENT_SSL=0x0800 LE) +
//	         character_set(1) + status_flags(2) +
//	         capability_flags_upper(2) + auth_plugin_data_len(1) +
//	         reserved(10)
func mysqlHandshakeV10() []byte {
	payload := []byte{
		0x0a,                               // protocol version 10
		0x35, 0x2e, 0x37, 0x2e, 0x30, 0x00, // "5.7.0\0"
		0x01, 0x00, 0x00, 0x00, // connection_id = 1 (LE)
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, // auth-plugin-data-1
		0x00,       // filler
		0x00, 0x08, // capability flags lower: CLIENT_SSL (0x0800, LE)
		0x21,       // character set (utf8_general_ci)
		0x00, 0x00, // status flags
		0x00, 0x00, // capability flags upper
		0x00,                                                       // auth_plugin_data_len
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved (10 bytes)
	}
	return append([]byte{byte(len(payload)), 0x00, 0x00, 0x00}, payload...)
}

func TestMySQLTLSHandshakeError(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	go func() {
		defer serverConn.Close()
		serverConn.Write(mysqlHandshakeV10())
		buf := make([]byte, 64)
		serverConn.Read(buf) // SSLRequest from client
		// TLS wrapper is called next and fails.
	}()

	scanner := &Scanner{config: &Flags{}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 3306}
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

func TestMySQLHandshakeCompletedSuccessfully(t *testing.T) {
	cert := testhelpers.GenerateTestCert(t)
	clientConn, serverConn := net.Pipe()

	srvDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		serverConn.Write(mysqlHandshakeV10())
		buf := make([]byte, 64)
		serverConn.Read(buf) // SSLRequest from client
		// Now perform the TLS handshake as the server.
		srv := stdtls.Server(serverConn, &stdtls.Config{Certificates: []stdtls.Certificate{cert}})
		if err := srv.Handshake(); err != nil {
			srvDone <- err

			return
		}
		srvDone <- nil
	}()

	scanner := &Scanner{config: &Flags{}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 3306}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeInsecureTLSWrapper(),
	}

	_, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if err := <-srvDone; err != nil {
		t.Fatalf("server-side TLS error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	mysqlResult, ok := result.(*ScanResults)
	if !ok {
		t.Fatal("expected *ScanResults")
	}
	if mysqlResult.TLSLog == nil {
		t.Fatal("expected TLSLog to be populated")
	}
	if !mysqlResult.TLSLog.HandshakeCompletedSuccessfully {
		t.Error("expected HandshakeCompletedSuccessfully = true")
	}
}

// mysqlHostNotPrivilegedERR returns the ERR packet a server sends instead of
// a handshake when it refuses the client's host (ER_HOST_NOT_PRIVILEGED,
// 1130). No capabilities are negotiated yet, so there is no SQL state.
func mysqlHostNotPrivilegedERR(msg string) []byte {
	payload := append([]byte{0xff, 0x6a, 0x04}, msg...) // header, 1130 (LE)
	return append([]byte{byte(len(payload)), 0x00, 0x00, 0x00}, payload...)
}

// TestMySQLConnectERRPreservesError checks that an ERR packet received in
// place of the server handshake is returned in the result rather than
// discarded along with the connect error.
func TestMySQLConnectERRPreservesError(t *testing.T) {
	const msg = "Host '192.0.2.1' is not allowed to connect to this MySQL server"
	clientConn, serverConn := net.Pipe()

	go func() {
		defer serverConn.Close()
		serverConn.Write(mysqlHostNotPrivilegedERR(msg))
	}()

	scanner := &Scanner{config: &Flags{}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 3306}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer:   testhelpers.MakeL4Dialer(clientConn),
		TLSWrapper: testhelpers.MakeFailingTLSWrapper(),
	}

	status, result, err := scanner.Scan(context.Background(), dialGroup, target)
	if err == nil {
		t.Fatal("expected a connect error")
	}
	if status != zgrab2.SCAN_APPLICATION_ERROR {
		t.Errorf("expected SCAN_APPLICATION_ERROR, got %s", status)
	}
	mysqlResult, ok := result.(*ScanResults)
	if !ok || mysqlResult == nil {
		t.Fatalf("expected non-nil *ScanResults, got %T", result)
	}
	if mysqlResult.ErrorCode == nil || *mysqlResult.ErrorCode != 1130 {
		t.Errorf("error code = %v, want 1130", mysqlResult.ErrorCode)
	}
	if mysqlResult.ErrorID != "ER_HOST_NOT_PRIVILEGED" {
		t.Errorf("error ID = %q, want ER_HOST_NOT_PRIVILEGED", mysqlResult.ErrorID)
	}
	if mysqlResult.ErrorMessage != msg {
		t.Errorf("error message = %q, want %q", mysqlResult.ErrorMessage, msg)
	}
}

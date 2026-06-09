package postgres

import (
	"context"
	stdtls "crypto/tls"
	"encoding/binary"
	"net"
	"strings"
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

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if err := <-srvDone; err != nil {
		t.Logf("server goroutine: %v", err)
	}
	// The server closes after the handshake, so the scan will not reach
	// SCAN_SUCCESS, but the TLS handshake did complete — SCAN_HANDSHAKE_ERROR
	// would indicate a regression where HandshakeCompletedSuccessfully is lost.
	if status == zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("unexpected SCAN_HANDSHAKE_ERROR: TLS handshake completed successfully")
	}
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

func TestIsValidPostgresError(t *testing.T) {
	tests := []struct {
		name  string
		err   *PostgresError
		valid bool
	}{
		{"nil error", nil, false},
		{"empty error", &PostgresError{}, false},
		{"severity only", &PostgresError{"severity": "FATAL"}, false},
		{"severity and code", &PostgresError{"severity": "FATAL", "code": "08P01"}, false},
		{"severity_v and code and message", &PostgresError{"severity_v": "FATAL", "code": "08P01", "message": "unsupported version"}, true},
		{"full valid error", &PostgresError{"severity": "FATAL", "code": "08P01", "message": "unsupported version"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidPostgresError(tt.err); got != tt.valid {
				t.Errorf("isValidPostgresError() = %v, want %v", got, tt.valid)
			}
		})
	}
}

// makePostgresErrorPacket builds a raw Postgres 'E'-type response packet from
// a map of field tag -> value. The packet format is:
// byte 'E' | uint32 length | (byte tag + string value + \0)... | \0
func makePostgresErrorPacket(fields map[byte]string) []byte {
	var body []byte
	for tag, val := range fields {
		body = append(body, tag)
		body = append(body, []byte(val)...)
		body = append(body, 0)
	}
	body = append(body, 0) // terminator

	length := uint32(len(body) + 4) // length includes itself
	pkt := make([]byte, 1+4+len(body))
	pkt[0] = 'E'
	binary.BigEndian.PutUint32(pkt[1:5], length)
	copy(pkt[5:], body)
	return pkt
}

// validPostgresError is a reusable valid Postgres error packet
var validPostgresError = makePostgresErrorPacket(map[byte]string{
	'S': "FATAL",
	'V': "FATAL",
	'C': "08P01",
	'M': "unsupported frontend protocol",
})

// makeConnPairFunc returns a function that, on each call, returns a new
// client-side net.Conn and starts a goroutine running serverFn on the server side.
func makeConnPairFunc(serverFn func(net.Conn)) func() net.Conn {
	return func() net.Conn {
		client, server := net.Pipe()
		go serverFn(server)
		return client
	}
}

// makeMultiL4Dialer returns an L4Dialer that calls newConn() for each dial,
// allowing the postgres scanner to open multiple sequential connections.
func makeMultiL4Dialer(newConn func() net.Conn) func(*zgrab2.ScanTarget) func(context.Context, string, string) (net.Conn, error) {
	return func(*zgrab2.ScanTarget) func(context.Context, string, string) (net.Conn, error) {
		return func(context.Context, string, string) (net.Conn, error) {
			return newConn(), nil
		}
	}
}

// drainAndRespond reads one request from conn, writes response, then closes.
func drainAndRespond(conn net.Conn, response []byte) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.Read(buf) //nolint:errcheck
	if len(response) > 0 {
		conn.Write(response) //nolint:errcheck
	}
}

func newTestScanner() *Scanner {
	return &Scanner{Config: &Flags{SkipSSL: true, ProtocolVersion: "3.0"}}
}

func TestFalsePositiveDetection_NonPostgresServer(t *testing.T) {
	// Simulates a non-Postgres service that responds 'N' to any request.
	// The scanner should bail with SCAN_PROTOCOL_ERROR since 'N' is not a
	// valid Postgres 'E' error response.
	newConn := makeConnPairFunc(func(conn net.Conn) {
		drainAndRespond(conn, []byte{'N'})
	})
	scanner := newTestScanner()
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 5432}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer: makeMultiL4Dialer(newConn),
	}

	status, _, err := scanner.Scan(context.Background(), dialGroup, target)
	if status == zgrab2.SCAN_SUCCESS {
		t.Errorf("expected non-success status for non-Postgres server, got %s", status)
	}
	if status != zgrab2.SCAN_PROTOCOL_ERROR {
		t.Errorf("expected SCAN_PROTOCOL_ERROR, got %s (err: %v)", status, err)
	}
}

func TestFalsePositiveDetection_InvalidErrorFields(t *testing.T) {
	// Server returns an 'E'-type packet but with no structured fields — just
	// garbage data. Should fail isValidPostgresError.
	badErrorPkt := makePostgresErrorPacket(map[byte]string{
		'X': "unknown",
	})
	newConn := makeConnPairFunc(func(conn net.Conn) {
		drainAndRespond(conn, badErrorPkt)
	})
	scanner := newTestScanner()
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 5432}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer: makeMultiL4Dialer(newConn),
	}

	status, _, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status == zgrab2.SCAN_SUCCESS {
		t.Errorf("expected non-success for invalid error fields, got %s", status)
	}
	if status != zgrab2.SCAN_PROTOCOL_ERROR {
		t.Errorf("expected SCAN_PROTOCOL_ERROR, got %s", status)
	}
}

func TestValidPostgresServer_PassesVersionProbe(t *testing.T) {
	// Server returns a valid Postgres error for the version 0.0 probe.
	// The scanner should accept it and populate SupportedVersions.
	newConn := makeConnPairFunc(func(conn net.Conn) {
		drainAndRespond(conn, validPostgresError)
	})
	scanner := newTestScanner()
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 5432}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer: makeMultiL4Dialer(newConn),
	}

	status, result, _ := scanner.Scan(context.Background(), dialGroup, target)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	pgResult, ok := result.(*Results)
	if !ok {
		t.Fatal("expected *Results")
	}
	if pgResult.SupportedVersions == "" {
		t.Error("expected SupportedVersions to be populated after valid error response")
	}
	// The scan may fail on subsequent connections (our fake server only handles
	// one exchange per connection), but the first probe should pass validation.
	// SCAN_PROTOCOL_ERROR from the detection check would be a regression.
	if status == zgrab2.SCAN_PROTOCOL_ERROR && strings.Contains(pgResult.SupportedVersions, "unsupported") {
		t.Error("valid Postgres error was rejected by detection check")
	}
}

func TestFalsePositive_ServerClosesImmediately(t *testing.T) {
	// Server accepts the connection but closes immediately without sending
	// any data. Should not result in SCAN_SUCCESS.
	newConn := makeConnPairFunc(func(conn net.Conn) {
		conn.Close()
	})
	scanner := newTestScanner()
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 5432}
	dialGroup := &zgrab2.DialerGroup{
		L4Dialer: makeMultiL4Dialer(newConn),
	}

	status, _, _ := scanner.Scan(context.Background(), dialGroup, target)
	if status == zgrab2.SCAN_SUCCESS {
		t.Errorf("expected non-success for immediately-closing server, got %s", status)
	}
}

package snmp

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
)

func buildTestResponse(version string) []byte {
	versionNumber, err := snmpVersionNumber(version)
	if err != nil {
		panic(err)
	}
	return wrap(tagSequence, concat(
		wrap(tagInteger, encodeInteger(versionNumber)),
		wrap(tagOctetString, []byte("public")),
		wrap(tagGetResponse, concat(
			wrap(tagInteger, encodeInteger(1)),
			wrap(tagInteger, encodeInteger(0)),
			wrap(tagInteger, encodeInteger(0)),
			wrap(tagSequence, nil),
		)),
	))
}

func pipeDialer(responses ...[]byte) (*zgrab2.DialerGroup, *atomic.Int32) {
	var calls atomic.Int32
	return &zgrab2.DialerGroup{
		TransportAgnosticDialer: func(context.Context, *zgrab2.ScanTarget) (net.Conn, error) {
			call := int(calls.Add(1)) - 1
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				buf := make([]byte, 65535)
				if _, err := server.Read(buf); err != nil {
					return
				}
				if call < len(responses) && responses[call] != nil {
					_, _ = server.Write(responses[call])
				}
			}()
			return client, nil
		},
	}, &calls
}

func TestAutoFallsBackToSNMPv1(t *testing.T) {
	scanner := &Scanner{config: &Flags{Community: "public", Version: "auto"}}
	dialGroup, calls := pipeDialer(nil, nil, buildTestResponse("1"))
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 161}

	status, result, err := scanner.Scan(context.Background(), dialGroup, target)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("Scan() status = %v", status)
	}
	log := result.(*Log)
	if log.Version != "1" || log.Probe != "community-get" {
		t.Fatalf("Scan() result = %+v", log)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("dial count = %d, want 3", got)
	}
}

func TestInitRejectsUnsupportedVersion(t *testing.T) {
	scanner := &Scanner{}
	if err := scanner.Init(&Flags{Version: "4"}); err == nil {
		t.Fatal("Init() unexpectedly accepted SNMPv4")
	}
}

func TestExplicitVersionOnTrapPortScansAgent(t *testing.T) {
	scanner := &Scanner{config: &Flags{Community: "public", Version: "1"}}
	dialGroup, calls := pipeDialer(buildTestResponse("1"))
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 162}

	status, result, err := scanner.Scan(context.Background(), dialGroup, target)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("Scan() status = %v", status)
	}
	log := result.(*Log)
	if log.Version != "1" || log.Probe != "community-get" || log.Role != "agent" {
		t.Fatalf("Scan() result = %+v", log)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("dial count = %d, want 1", got)
	}
}

func TestTrapReceiverReadErrorIsInconclusive(t *testing.T) {
	readErr := errors.New("read failed")
	dialGroup := &zgrab2.DialerGroup{
		TransportAgnosticDialer: func(context.Context, *zgrab2.ScanTarget) (net.Conn, error) {
			return &readErrorConn{readErr: readErr}, nil
		},
	}
	scanner := &Scanner{config: &Flags{Community: "public", Version: "auto"}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 162}

	status, result, err := scanner.scanTrapReceiver(context.Background(), dialGroup, target)
	if err != nil {
		t.Fatalf("scanTrapReceiver() error = %v", err)
	}
	if status != zgrab2.SCAN_UNKNOWN_ERROR {
		t.Fatalf("scanTrapReceiver() status = %v", status)
	}
	log := result.(*Log)
	if log.Probe != "v2-inform" || log.Role != "trap_receiver" {
		t.Fatalf("scanTrapReceiver() result = %+v", log)
	}
}

type readErrorConn struct {
	readErr error
}

func (c *readErrorConn) Read([]byte) (int, error)         { return 0, c.readErr }
func (c *readErrorConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *readErrorConn) Close() error                     { return nil }
func (c *readErrorConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *readErrorConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *readErrorConn) SetDeadline(time.Time) error      { return nil }
func (c *readErrorConn) SetReadDeadline(time.Time) error  { return nil }
func (c *readErrorConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }

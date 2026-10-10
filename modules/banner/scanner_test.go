package banner

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/zmap/zgrab2"
)

type addressedConn struct {
	net.Conn
	localAddress  net.Addr
	remoteAddress net.Addr
}

func (conn *addressedConn) LocalAddr() net.Addr {
	return conn.localAddress
}

func (conn *addressedConn) RemoteAddr() net.Addr {
	return conn.remoteAddress
}

func TestScannerProbeExpansion(t *testing.T) {
	testScannerProbe(t, Flags{
		Probe:       "${SADDR}:${SPORT}->${DADDR}:${DPORT}",
		ExpandProbe: true,
	}, "192.0.2.1:12345->198.51.100.2:80")
}

func TestScannerProbeExpansionDisabledByDefault(t *testing.T) {
	testScannerProbe(t, Flags{
		Probe: "${DADDR}:${DPORT}",
	}, "${DADDR}:${DPORT}")
}

func TestScannerProbeFileExpansion(t *testing.T) {
	probePath := filepath.Join(t.TempDir(), "probe.tpl")
	if err := os.WriteFile(probePath, []byte("${DADDR}:${DPORT}"), 0o600); err != nil {
		t.Fatalf("write probe: %v", err)
	}
	testScannerProbe(t, Flags{
		Probe:       "\\n",
		ProbeFile:   probePath,
		ExpandProbe: true,
	}, "198.51.100.2:80")
}

func testScannerProbe(t *testing.T, flags Flags, expectedProbe string) {
	t.Helper()
	flags.Port = 80
	flags.MaxTries = 1
	flags.BufferSize = 1024
	flags.MaxReadSize = 1
	flags.ReadTimeout = 100

	scanner := &Scanner{}
	if err := scanner.Init(&flags); err != nil {
		t.Fatalf("Init() error = %v", err)
	}

	client, server := net.Pipe()
	clientConn := &addressedConn{
		Conn:          client,
		localAddress:  &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345},
		remoteAddress: &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 80},
	}
	received := make(chan string, 1)
	go func() {
		defer server.Close()
		probe := make([]byte, len(expectedProbe))
		if _, err := io.ReadFull(server, probe); err != nil {
			received <- "read error: " + err.Error()
			return
		}
		received <- string(probe)
		_, _ = server.Write([]byte("ok"))
		_, _ = io.Copy(io.Discard, server)
	}()

	dialGroup := &zgrab2.DialerGroup{
		TransportAgnosticDialer: func(context.Context, *zgrab2.ScanTarget) (net.Conn, error) {
			return clientConn, nil
		},
	}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("198.51.100.2"), Port: 80}
	status, result, err := scanner.Scan(context.Background(), dialGroup, target)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("Scan() status = %s, want %s", status, zgrab2.SCAN_SUCCESS)
	}
	if got := <-received; got != expectedProbe {
		t.Fatalf("sent probe = %q, want %q", got, expectedProbe)
	}
	typedResult, ok := result.(*Results)
	if !ok {
		t.Fatalf("Scan() result type = %T, want *Results", result)
	}
	if typedResult.Banner != "ok" {
		t.Fatalf("Scan() banner = %q, want %q", typedResult.Banner, "ok")
	}
}

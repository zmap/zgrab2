package crimson

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
)

func getScanner(t *testing.T, port int) *Scanner {
	m := NewModule()
	scanner := m.NewScanner()
	flags := m.NewFlags().(*Flags)
	flags.Port = uint(port)
	flags.TargetTimeout = 2 * time.Second
	if err := scanner.Init(flags); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	return scanner.(*Scanner)
}

// buildFakeCR3Response hand-builds a CR3 "get property" response: a 6-byte
// header (ignored by the parser) followed by a NUL-terminated ASCII string.
func buildFakeCR3Response(s string) []byte {
	buf := make([]byte, headerSize, headerSize+len(s)+1)
	buf = append(buf, []byte(s)...)
	buf = append(buf, 0x00)
	return buf
}

// runFakeServer accepts a single connection and answers each request it
// reads with the next response in order (one per probe).
func runFakeServer(t *testing.T, port int, responses ...[]byte) net.Listener {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go func() {
		sock, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer sock.Close()
		buf := make([]byte, 1024)
		for _, resp := range responses {
			if _, err := sock.Read(buf); err != nil && err != io.EOF {
				return
			}
			if _, err := sock.Write(resp); err != nil {
				return
			}
		}
	}()
	return listener
}

func scanTarget(port int) *zgrab2.ScanTarget {
	return &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: uint(port)}
}

func TestScanSuccess(t *testing.T) {
	const port = 20789
	listener := runFakeServer(t, port,
		buildFakeCR3Response("Red Lion Controls"),
		buildFakeCR3Response("CR3000"),
	)
	defer listener.Close()

	scanner := getScanner(t, port)
	dialerGroup, err := scanner.GetDialerGroupConfig().GetDefaultDialerGroupFromConfig()
	if err != nil {
		t.Fatalf("failed to get dialer group: %v", err)
	}

	status, result, err := scanner.Scan(context.Background(), dialerGroup, scanTarget(port))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("status = %v, want SCAN_SUCCESS", status)
	}
	info, ok := result.(*DeviceInfo)
	if !ok {
		t.Fatalf("result is not *DeviceInfo: %T", result)
	}
	if info.Manufacturer != "Red Lion Controls" {
		t.Errorf("Manufacturer = %q, want %q", info.Manufacturer, "Red Lion Controls")
	}
	if info.Model != "CR3000" {
		t.Errorf("Model = %q, want %q", info.Model, "CR3000")
	}
}

func TestScanNoResponse(t *testing.T) {
	const port = 20790
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()
	go func() {
		sock, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer sock.Close()
	}()

	scanner := getScanner(t, port)
	dialerGroup, err := scanner.GetDialerGroupConfig().GetDefaultDialerGroupFromConfig()
	if err != nil {
		t.Fatalf("failed to get dialer group: %v", err)
	}

	status, _, err := scanner.Scan(context.Background(), dialerGroup, scanTarget(port))
	if err == nil {
		t.Fatal("expected an error when the device answers with nothing, got nil")
	}
	if status != zgrab2.SCAN_PROTOCOL_ERROR {
		t.Errorf("status = %v, want SCAN_PROTOCOL_ERROR", status)
	}
}

func TestParseCR3String(t *testing.T) {
	tests := []struct {
		name string
		resp []byte
		want string
	}{
		{"valid", buildFakeCR3Response("Red Lion Controls"), "Red Lion Controls"},
		{"too short", []byte{0x00, 0x01, 0x02}, ""},
		{"no alnum", buildFakeCR3Response("!!!"), ""},
		{"empty body", buildFakeCR3Response(""), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseCR3String(tt.resp); got != tt.want {
				t.Errorf("parseCR3String() = %q, want %q", got, tt.want)
			}
		})
	}
}

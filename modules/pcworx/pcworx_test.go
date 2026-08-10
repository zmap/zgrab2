package pcworx

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

func scanTarget(port int) *zgrab2.ScanTarget {
	return &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: uint(port)}
}

// buildFakeHandshakeResponse builds a valid handshake reply carrying the
// given session id byte.
func buildFakeHandshakeResponse(sid byte) []byte {
	resp := append([]byte{}, handshakePrefix...)
	resp = append(resp, sid, 0x00, 0x00)
	return resp
}

// buildFakeInfoResponse builds a third-stage response with PLC identity
// fields at the fixed offsets parseInfoResponse expects.
func buildFakeInfoResponse(plcType, model, fwVersion, fwDate, fwTime string) []byte {
	buf := make([]byte, 200)
	buf[0] = 0x81
	putCStr := func(s string, offset int) {
		copy(buf[offset:], s)
	}
	putCStr(plcType, 30)
	putCStr(fwVersion, 66)
	putCStr(fwDate, 79)
	putCStr(fwTime, 91)
	putCStr(model, 152)
	return buf
}

// runFakeServer accepts a single connection and answers each request it
// reads with the next response in order (one per protocol stage).
func runFakeServer(t *testing.T, port int, responses ...[]byte) net.Listener {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go func() {
		sock, err := listener.Accept()
		if err != nil {
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

func TestScanSuccess(t *testing.T) {
	const port = 21962
	const sid = byte(0x07)
	listener := runFakeServer(t, port,
		buildFakeHandshakeResponse(sid),
		[]byte{0x81, 0x01}, // set-session ack, contents unchecked by the scanner
		buildFakeInfoResponse("ILC 350 PN", "2700981", "4.65", "Jan 1 2024", "12:00:00"),
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
	if info.PLCType != "ILC 350 PN" {
		t.Errorf("PLCType = %q, want %q", info.PLCType, "ILC 350 PN")
	}
	if info.ModelNumber != "2700981" {
		t.Errorf("ModelNumber = %q, want %q", info.ModelNumber, "2700981")
	}
	if info.FirmwareVersion != "4.65" {
		t.Errorf("FirmwareVersion = %q, want %q", info.FirmwareVersion, "4.65")
	}
}

func TestScanHandshakeOnlySucceedsWithEmptyIdentity(t *testing.T) {
	// A device that answers the handshake but never the follow-up requests
	// still counts as a confirmed PC WorX detection.
	const port = 21963
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
		buf := make([]byte, 1024)
		if _, readErr := sock.Read(buf); readErr != nil && readErr != io.EOF {
			return
		}
		_, _ = sock.Write(buildFakeHandshakeResponse(0x01))
		// No further responses; the scanner's follow-up requests will fail
		// to read and it should fall back to an empty DeviceInfo.
	}()

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
	info := result.(*DeviceInfo)
	if info.PLCType != "" || info.ModelNumber != "" {
		t.Errorf("expected empty DeviceInfo, got %+v", info)
	}
}

func TestScanRejectsBadHandshake(t *testing.T) {
	const port = 21964
	listener := runFakeServer(t, port, []byte("not pcworx"))
	defer listener.Close()

	scanner := getScanner(t, port)
	dialerGroup, err := scanner.GetDialerGroupConfig().GetDefaultDialerGroupFromConfig()
	if err != nil {
		t.Fatalf("failed to get dialer group: %v", err)
	}

	status, _, err := scanner.Scan(context.Background(), dialerGroup, scanTarget(port))
	if err == nil {
		t.Fatal("expected an error for a non-PCWorx handshake, got nil")
	}
	if status != zgrab2.SCAN_PROTOCOL_ERROR {
		t.Errorf("status = %v, want SCAN_PROTOCOL_ERROR", status)
	}
}

func TestMatchesHandshake(t *testing.T) {
	if !matchesHandshake(buildFakeHandshakeResponse(0x07)) {
		t.Error("expected a well-formed handshake response to match")
	}
	if matchesHandshake([]byte("too short")) {
		t.Error("expected a too-short response to not match")
	}
	if matchesHandshake(append(append([]byte{}, handshakePrefix...), 0x07, 0x01, 0x00)) {
		t.Error("expected a response with a non-zero byte after the session id to not match")
	}
}

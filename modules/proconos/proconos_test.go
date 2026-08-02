package proconos

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

// buildFakeDeviceInfoResponse hand-builds a ProConOS device-info response
// matching the layout decoded by parseResponse, so the decoder can be
// exercised without a live PLC.
func buildFakeDeviceInfoResponse(osVersion, version, plc, projectA, projectB, source string) []byte {
	buf := []byte{0xcc, 0x01, 0x00, 0x0b, 0x40, 0x02, 0x92, 0x00, 'V'}
	buf = append(buf, []byte(osVersion)...)
	buf = append(buf, []byte("ProConOS V")...)
	buf = append(buf, []byte(version)...)
	buf = append(buf, []byte(" Jan  1 2024")...)
	buf = append(buf, 0x00, 0x00) // date terminator + padding, consumed by skipNulls
	buf = append(buf, []byte(plc)...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte(projectA)...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte(projectB)...)
	buf = append(buf, 0x00)
	buf = append(buf, []byte(source)...)
	buf = append(buf, 0x00)
	return buf
}

func runFakeServer(t *testing.T, port int, response []byte) net.Listener {
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
		if _, err := sock.Read(buf); err != nil && err != io.EOF {
			return
		}
		_, _ = sock.Write(response)
	}()
	return listener
}

func TestScanSuccess(t *testing.T) {
	const port = 21547
	response := buildFakeDeviceInfoResponse("3.90", "5.10", "PLC-X20", "ProjA", "ProjB", "USB:MyProject.pro")
	listener := runFakeServer(t, port, response)
	defer listener.Close()

	scanner := getScanner(t, port)
	dialerGroup, err := scanner.GetDialerGroupConfig().GetDefaultDialerGroupFromConfig()
	if err != nil {
		t.Fatalf("failed to get dialer group: %v", err)
	}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: uint(port)}

	status, result, err := scanner.Scan(context.Background(), dialerGroup, target)
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
	if info.OSVersion != "3.90" {
		t.Errorf("OSVersion = %q, want %q", info.OSVersion, "3.90")
	}
	if info.Version != "5.10" {
		t.Errorf("Version = %q, want %q", info.Version, "5.10")
	}
	if info.PLC != "PLC-X20" {
		t.Errorf("PLC = %q, want %q", info.PLC, "PLC-X20")
	}
	if info.Project != "ProjA/ProjB" {
		t.Errorf("Project = %q, want %q", info.Project, "ProjA/ProjB")
	}
	if info.Source != "USB:MyProject.pro" {
		t.Errorf("Source = %q, want %q", info.Source, "USB:MyProject.pro")
	}
}

func TestScanSameProjectNames(t *testing.T) {
	const port = 21548
	response := buildFakeDeviceInfoResponse("3.90", "5.10", "PLC-X20", "SameProj", "SameProj", "USB:MyProject.pro")
	listener := runFakeServer(t, port, response)
	defer listener.Close()

	scanner := getScanner(t, port)
	dialerGroup, err := scanner.GetDialerGroupConfig().GetDefaultDialerGroupFromConfig()
	if err != nil {
		t.Fatalf("failed to get dialer group: %v", err)
	}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: uint(port)}

	status, result, err := scanner.Scan(context.Background(), dialerGroup, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("status = %v, want SCAN_SUCCESS", status)
	}
	info := result.(*DeviceInfo)
	if info.Project != "SameProj" {
		t.Errorf("Project = %q, want %q (deduplicated)", info.Project, "SameProj")
	}
}

func TestScanRejectsGarbage(t *testing.T) {
	const port = 21549
	listener := runFakeServer(t, port, []byte("not proconos"))
	defer listener.Close()

	scanner := getScanner(t, port)
	dialerGroup, err := scanner.GetDialerGroupConfig().GetDefaultDialerGroupFromConfig()
	if err != nil {
		t.Fatalf("failed to get dialer group: %v", err)
	}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: uint(port)}

	status, _, err := scanner.Scan(context.Background(), dialerGroup, target)
	if err == nil {
		t.Fatal("expected an error for a non-ProConOS response, got nil")
	}
	if status != zgrab2.SCAN_PROTOCOL_ERROR {
		t.Errorf("status = %v, want SCAN_PROTOCOL_ERROR", status)
	}
}

func TestParseResponseTable(t *testing.T) {
	valid := buildFakeDeviceInfoResponse("3.90", "5.10", "PLC-X20", "ProjA", "ProjB", "src")
	if _, err := parseResponse(valid); err != nil {
		t.Errorf("parseResponse(valid) failed: %v", err)
	}
	if _, err := parseResponse([]byte("garbage")); err == nil {
		t.Error("expected error for garbage input, got nil")
	}
	if _, err := parseResponse(nil); err == nil {
		t.Error("expected error for empty input, got nil")
	}
}

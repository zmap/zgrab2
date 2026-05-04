package zgrab2

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"
)

// mockScanner implements the Scanner interface for testing.
type mockScanner struct {
	name     string
	trigger  string
	protocol string
	port     uint
	scanFunc func(ctx context.Context, dg *DialerGroup, t *ScanTarget) (ScanStatus, any, error)
}

func (m *mockScanner) Init(flags ScanFlags) error               { return nil }
func (m *mockScanner) InitPerSender(senderID int) error         { return nil }
func (m *mockScanner) GetName() string                          { return m.name }
func (m *mockScanner) GetTrigger() string                       { return m.trigger }
func (m *mockScanner) Protocol() string                         { return m.protocol }
func (m *mockScanner) GetDialerGroupConfig() *DialerGroupConfig { return nil }
func (m *mockScanner) GetScanMetadata() any                     { return nil }
func (m *mockScanner) Scan(ctx context.Context, dg *DialerGroup, t *ScanTarget) (ScanStatus, any, error) {
	if m.scanFunc != nil {
		return m.scanFunc(ctx, dg, t)
	}
	return SCAN_SUCCESS, nil, nil
}

// setupTestScanner registers a mock scanner in the package-level globals and
// returns a cleanup function that restores the previous state.
func setupTestScanner(name string, trigger string, port uint) func() {
	oldScanners := scanners
	oldOrdered := orderedScanners
	oldDGConfig := defaultDialerGroupConfigToScanners
	oldDG := defaultDialerGroupToScanners

	scanners = make(map[string]*Scanner)
	orderedScanners = nil
	defaultDialerGroupConfigToScanners = make(map[string]*DialerGroupConfig)
	defaultDialerGroupToScanners = make(map[string]*DialerGroup)

	var s Scanner = &mockScanner{
		name:     name,
		trigger:  trigger,
		protocol: "test",
		port:     port,
	}
	scanners[name] = &s
	orderedScanners = append(orderedScanners, name)
	defaultDialerGroupConfigToScanners[name] = &DialerGroupConfig{
		BaseFlags: &BaseFlags{
			Port:           port,
			ConnectTimeout: 1 * time.Second,
			TargetTimeout:  5 * time.Second,
		},
	}
	defaultDialerGroupToScanners[name] = &DialerGroup{}

	return func() {
		scanners = oldScanners
		orderedScanners = oldOrdered
		defaultDialerGroupConfigToScanners = oldDGConfig
		defaultDialerGroupToScanners = oldDG
	}
}

// makeTestMonitor creates a Monitor with a buffered channel for testing.
func makeTestMonitor() *Monitor {
	var wg sync.WaitGroup
	return MakeMonitor(100, &wg, orderedScanners)
}

func TestBuildGrabFromInputResponse_PortSet(t *testing.T) {
	target := &ScanTarget{
		IP:   net.ParseIP("10.0.0.1"),
		Port: 8080,
	}
	grab := BuildGrabFromInputResponse(target, nil)
	if grab.Port != 8080 {
		t.Errorf("expected Port=8080, got %d", grab.Port)
	}
}

func TestBuildGrabFromInputResponse_PortZero(t *testing.T) {
	target := &ScanTarget{
		IP: net.ParseIP("10.0.0.1"),
	}
	grab := BuildGrabFromInputResponse(target, nil)
	if grab.Port != 0 {
		t.Errorf("expected Port=0, got %d", grab.Port)
	}
}

func TestGrabTarget_PortFromCLIFlags(t *testing.T) {
	cleanup := setupTestScanner("test-scanner", "", 443)
	defer cleanup()

	mon := makeTestMonitor()
	defer mon.Stop()

	target := ScanTarget{
		IP:   net.ParseIP("10.0.0.1"),
		Port: 0, // no port from CSV — simulates CLI-only port
	}

	grab := grabTarget(context.Background(), target, mon)
	if grab.Port != 443 {
		t.Errorf("expected port 443 from CLI flags, got %d", grab.Port)
	}
}

func TestGrabTarget_PortFromCSV(t *testing.T) {
	cleanup := setupTestScanner("test-scanner", "", 80)
	defer cleanup()

	mon := makeTestMonitor()
	defer mon.Stop()

	target := ScanTarget{
		IP:   net.ParseIP("10.0.0.1"),
		Port: 8443, // port from CSV takes precedence
	}

	grab := grabTarget(context.Background(), target, mon)
	if grab.Port != 8443 {
		t.Errorf("expected port 8443 from CSV, got %d", grab.Port)
	}
}

func TestGrabTarget_PortAppearsInJSON(t *testing.T) {
	cleanup := setupTestScanner("test-scanner", "", 443)
	defer cleanup()

	mon := makeTestMonitor()
	defer mon.Stop()

	target := ScanTarget{
		IP:   net.ParseIP("10.0.0.1"),
		Port: 0,
	}

	grab := grabTarget(context.Background(), target, mon)

	data, err := json.Marshal(grab)
	if err != nil {
		t.Fatalf("failed to marshal grab: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal grab: %v", err)
	}

	portVal, ok := decoded["port"]
	if !ok {
		t.Fatal("port field missing from JSON output when CLI port was set")
	}
	if uint(portVal.(float64)) != 443 {
		t.Errorf("expected port 443 in JSON, got %v", portVal)
	}
}

func TestGrabTarget_PortOmittedWhenZeroAndNoDefault(t *testing.T) {
	// Scanner with port=0 and target with port=0 → port should be 0 and omitted from JSON
	cleanup := setupTestScanner("test-scanner", "", 0)
	defer cleanup()

	mon := makeTestMonitor()
	defer mon.Stop()

	target := ScanTarget{
		IP:   net.ParseIP("10.0.0.1"),
		Port: 0,
	}

	grab := grabTarget(context.Background(), target, mon)

	data, err := json.Marshal(grab)
	if err != nil {
		t.Fatalf("failed to marshal grab: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal grab: %v", err)
	}

	if _, ok := decoded["port"]; ok {
		t.Error("port field should be omitted from JSON when port is 0")
	}
}

func TestGrabTarget_TagFilterMatchesScanner(t *testing.T) {
	cleanup := setupTestScanner("tagged-scanner", "my-tag", 9090)
	defer cleanup()

	mon := makeTestMonitor()
	defer mon.Stop()

	// Target with matching tag should be scanned and port resolved
	target := ScanTarget{
		IP:  net.ParseIP("10.0.0.1"),
		Tag: "my-tag",
	}

	grab := grabTarget(context.Background(), target, mon)
	if grab.Port != 9090 {
		t.Errorf("expected port 9090 for matching tag, got %d", grab.Port)
	}
}

func TestGrabTarget_TagFilterNoMatch(t *testing.T) {
	cleanup := setupTestScanner("tagged-scanner", "my-tag", 9090)
	defer cleanup()

	mon := makeTestMonitor()
	defer mon.Stop()

	// Target with non-matching tag — scanner doesn't run, but port should
	// still be resolved from scanner config for output consistency
	target := ScanTarget{
		IP:  net.ParseIP("10.0.0.1"),
		Tag: "other-tag",
	}

	grab := grabTarget(context.Background(), target, mon)
	if grab.Port != 9090 {
		t.Errorf("expected port 9090 from scanner config even without tag match, got %d", grab.Port)
	}
}

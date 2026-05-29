// Package checkpoint contains the zgrab2 Module implementation for the Checkpoint
// firewall admin protocol, by default on port 264.
// It probes for the service and extracts the firewall hostname from the response.
package checkpoint

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// ScanResults is the output of the scan.
type ScanResults struct {
	// FirewallHost is the CN field from the firewall's DN response (e.g. "fw1.example.com").
	FirewallHost string `json:"firewall_host,omitempty"`
	// Host is the O field from the firewall's DN response (e.g. "example.com").
	Host string `json:"host,omitempty"`
}

type Flags struct {
	zgrab2.BaseFlags
}

type Module struct{}

type Scanner struct {
	config            *Flags
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("checkpoint", "Check Point Firewall-1 topology protocol", module.Description(), 264, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *Module) NewFlags() any {
	return new(Flags)
}

func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "Probe for Check Point Firewall-1 and retrieve the firewall hostname via the topology protocol"
}

func (f *Flags) Validate(_ []string) error {
	return nil
}

func (f *Flags) Help() string {
	return ""
}

func (scanner *Scanner) Protocol() string {
	return "checkpoint"
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

func (scanner *Scanner) GetScanMetadata() any {
	return nil
}

// Init initializes the Scanner instance with the flags from the command line.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// See Metasploit's implementation for spec
// https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/gather/checkpoint_hostname.rb#L59

// probePacket1 is the initial handshake packet sent to identify a Checkpoint service.
var probePacket1 = []byte{0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21}

// probePacket2 requests the topology/hostname information.
var probePacket2 = []byte{0x00, 0x00, 0x00, 0x0b, 's', 'e', 'c', 'u', 'r', 'e', 'r', 'e', 'm', 'o', 't', 'e', 0x00}

// decodeResponse parses a Checkpoint topology response into FirewallHost and Host.
// The wire format is: 4-byte length prefix, then "CN=<host>,O=<domain>", then 8 trailing bytes.
func decodeResponse(answer []byte, results *ScanResults) error {
	// Need at least 4 (header) + 1 (data) + 8 (trailer) = 13 bytes for any content.
	if len(answer) < 13 {
		return fmt.Errorf("response too short (%d bytes)", len(answer))
	}
	payload := string(answer[4 : len(answer)-8])
	parts := strings.SplitN(payload, ",", 2)
	if len(parts) != 2 {
		return fmt.Errorf("unexpected response format: %q", payload)
	}
	cn, o := parts[0], parts[1]
	// Expect "CN=<value>" and "O=<value>"
	if !strings.HasPrefix(cn, "CN=") || !strings.HasPrefix(o, "O=") {
		return fmt.Errorf("unexpected DN fields: %q", payload)
	}
	results.FirewallHost = cn[3:]
	results.Host = o[2:]
	return nil
}

// Scan connects to port 264 and runs the Checkpoint topology probe:
//  1. Send a fixed 8-byte identification packet.
//  2. Verify the response starts with 0x59 ('Y'), indicating a Checkpoint service.
//  3. Send the "securemote" request packet.
//  4. Parse the returned DN to extract the firewall hostname.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error connecting to %s: %w", target.String(), err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	results := &ScanResults{}

	// Step 1: send identification probe.
	if _, err = conn.Write(probePacket1); err != nil {
		return zgrab2.TryGetScanStatus(err), results, fmt.Errorf("error sending probe to %s: %w", target.String(), err)
	}
	resp1, err := zgrab2.ReadAvailable(conn)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), results, fmt.Errorf("error reading probe response from %s: %w", target.String(), err)
	}

	// Step 2: verify this is a Checkpoint service
	const Y = 0x59 // the letter 'Y', which Checkpoint uses to indicate a valid response to the initial probe
	if len(resp1) == 0 || resp1[0] != Y {
		return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("not a Checkpoint service at %s: unexpected response %x", target.String(), resp1)
	}

	// Step 3: request topology/hostname.
	if _, err = conn.Write(probePacket2); err != nil {
		return zgrab2.TryGetScanStatus(err), results, fmt.Errorf("error sending topology request to %s: %w", target.String(), err)
	}
	resp2, err := zgrab2.ReadAvailable(conn)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), results, fmt.Errorf("error reading topology response from %s: %w", target.String(), err)
	}

	// Step 4: parse the DN out of the response.
	if err = decodeResponse(resp2, results); err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("error decoding response from %s: %w", target.String(), err)
	}

	return zgrab2.SCAN_SUCCESS, results, nil
}

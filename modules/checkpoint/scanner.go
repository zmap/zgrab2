// Package checkpoint contains the zgrab2 Module implementation for the Checkpoint
// firewall admin protocol, by default on port 264.
// It probes for the service and extracts the firewall hostname from the response.
package checkpoint

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/zmap/zgrab2"
)

const maxReadSize = 2048

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner](
		"checkpoint",
		"Probe for Checkpoint firewalls",
		"Probe for Checkpoint firewalls, returns whether the host responded with the expected reply to the "+
			"initial probe and the firewall and smartcenter host after a topology request, if received.",
		264,
	)
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

// Init initializes the Scanner with the command-line flags.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.SetBaseFlags(&f.BaseFlags)
	scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

// ScanResults is the output of the scan.
type ScanResults struct {
	CheckpointResponseReceived bool   `json:"initial_response_is_checkpoint"`
	RawTopologyResponse        string `json:"raw_topology_response,omitempty"`
	// FirewallHost is the CN field from the topology DN (e.g. "fw1.example.com").
	FirewallHost string `json:"firewall_host,omitempty"`
	// SmartCenterHost is the management server name from the O= field
	SmartCenterHost string `json:"smart_center_host,omitempty"`
	// ObjectSuffix is the trailing dot-component of the O= field in the topology DN.
	// Its purpose is unknown; it appears stable per management server.
	ObjectSuffix string `json:"object_suffix,omitempty"`
	// SupportedCiphers lists the ciphers advertised in the topology response.
	SupportedCiphers []string `json:"supported_ciphers,omitempty"`
}

type Flags struct {
	zgrab2.BaseFlags
	ReadTimeout time.Duration `long:"read-timeout" description:"How long to wait for full reply from probe" default:"5s"`
	IncludeRaw  bool          `long:"include-raw" description:"Include raw topology response"`
}

var (
	// See Metasploit's implementation for probe spec
	// https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/gather/checkpoint_hostname.rb#L59
	probePacket1                       = []byte{0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21} // inital probe packet
	expectedCheckpointResponseProbeOne = []byte("Y\x00\x00\x00")                                // expected reply to probe 1
	probePacket2                       = []byte("\x00\x00\x00\x0bsecuremote\x00")               // probe packet to request topology
)

// Scan connects to port 264 and runs the Checkpoint topology probe:
//  1. Send a fixed 8-byte identification packet.
//  2. Verify the response is the expected Checkpoint response
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
	resp1, err := zgrab2.ReadAvailableWithOptions(conn, maxReadSize, time.Second*2, 0, maxReadSize)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), results, fmt.Errorf("error reading probe response from %s: %w", target.String(), err)
	}

	// Step 2: verify this is a Checkpoint service
	err = decodeCheckpointProbeResponse(resp1, results)
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("unexpected response to initial Checkpoint probe: %w", err)
	}

	// Step 3: request topology/hostname.
	if _, err = conn.Write(probePacket2); err != nil {
		return zgrab2.TryGetScanStatus(err), results, fmt.Errorf("error sending topology request to %s: %w", target.String(), err)
	}
	resp2, err := zgrab2.ReadAvailableWithOptions(conn, maxReadSize, time.Second*2, 0, maxReadSize)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), results, fmt.Errorf("error reading topology response from %s: %w", target.String(), err)
	}

	// Step 4: parse the DN out of the response.
	if err = decodeTopologyResponse(string(resp2), results, scanner.config.IncludeRaw); err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, results, fmt.Errorf("error decoding topology response from %s: %w", target.String(), err)
	}

	return zgrab2.SCAN_SUCCESS, results, nil
}

// dnRegEx captures the CN and the full O= value up to the first null byte, newline, or comma.
// The O= value includes the trailing SIC suffix (e.g. "host.com.abc123" or "host..abc123"),
// which is split out in decodeTopologyResponse.
var dnRegEx = regexp.MustCompile(`(?i)CN=([^,]+),O=([^,\x00\n]+)`)

// decodeTopologyResponse parses a Checkpoint topology response.
//
// Wire layout (after the 4-byte message-length prefix):
//
//	CN=<gateway>,O=<management>.<suffix>\x00
//	[4-byte big-endian count]
//	( [4-byte len including \x00] <cipher suite>\x00 ) × count
func decodeTopologyResponse(answer string, results *ScanResults, includeRaw bool) error {
	if includeRaw {
		results.RawTopologyResponse = answer
	}

	loc := dnRegEx.FindStringSubmatchIndex(answer)
	if loc == nil {
		return fmt.Errorf("no DN found in response: %q", answer)
	}

	results.FirewallHost = answer[loc[2]:loc[3]]

	oValue := answer[loc[4]:loc[5]]
	if idx := strings.LastIndex(oValue, "."); idx >= 0 {
		results.ObjectSuffix = strings.TrimRight(oValue[idx+1:], ".")
		oValue = strings.TrimRight(oValue[:idx], ".")
	}
	results.SmartCenterHost = oValue

	// Cipher list follows the null terminator that ends the DN field.
	// loc[1] is the end of the regex match, which stops just before the \x00.
	after := answer[loc[1]:]
	if nullIdx := strings.IndexByte(after, 0); nullIdx >= 0 {
		results.SupportedCiphers = parseCipherSuites([]byte(after[nullIdx+1:]))
	}

	return nil
}

// parseCipherSuites decodes the length-prefixed encryption method list from the topology response.
// Each entry is a 4-byte big-endian length (including the null terminator) followed by the name.
func parseCipherSuites(data []byte) []string {
	if len(data) < 4 {
		return nil
	}
	count := binary.BigEndian.Uint32(data[:4])
	data = data[4:]
	if count > 256 {
		return nil
	}
	ciphers := make([]string, 0, count)
	for range count {
		if len(data) < 4 {
			break
		}
		nameLen := int(binary.BigEndian.Uint32(data[:4]))
		data = data[4:]
		if nameLen <= 0 || len(data) < nameLen {
			break
		}
		name := strings.TrimRight(string(data[:nameLen]), "\x00")
		if name != "" {
			ciphers = append(ciphers, name)
		}
		data = data[nameLen:]
	}
	if len(ciphers) == 0 {
		return nil
	}
	return ciphers
}

func decodeCheckpointProbeResponse(answer []byte, res *ScanResults) error {
	if bytes.Equal(answer, expectedCheckpointResponseProbeOne) {
		res.CheckpointResponseReceived = true
		return nil
	}
	return fmt.Errorf("expected: %s, got %s", string(expectedCheckpointResponseProbeOne), string(answer))
}

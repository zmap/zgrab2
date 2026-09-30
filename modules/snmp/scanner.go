// Package snmp provides a zgrab2 module that sends a read-only SNMP GET.
// Default port: 161/udp.
package snmp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/zmap/zgrab2"
)

type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`

	Community string `long:"community" default:"public" description:"SNMP community string to use for the read-only GET request."`
	Version   string `long:"version" default:"auto" choice:"auto" choice:"1" choice:"2c" choice:"3" description:"SNMP probe version to use. auto tries SNMPv3 discovery, then v1/v2c GET."`
}

func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner](
		"snmp",
		"Simple Network Management Protocol (SNMP)",
		"Send a read-only SNMP GET for standard system OIDs.",
		161,
	)
}

type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.SetBaseFlags(&f.BaseFlags)
	scanner.DialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportUDP,
		BaseFlags:                       &f.BaseFlags,
	}
	return nil
}

func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	switch target.Port {
	case 162:
		// Port 162 is normally a trap receiver, but some devices run an SNMP
		// agent on 162. With --version auto, try agent first and only fall
		// back to the trap-receiver probe if the agent scan fails.
		if strings.ToLower(scanner.config.Version) == "auto" {
			if status, result, err := scanner.scanAgent(ctx, dialGroup, target); err == nil {
				return status, result, nil
			}
		}
		return scanner.scanTrapReceiver(ctx, dialGroup, target)
	default:
		return scanner.scanAgent(ctx, dialGroup, target)
	}
}

func (scanner *Scanner) scanAgent(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	version := strings.ToLower(scanner.config.Version)
	switch version {
	case "3":
		return scanner.scanV3(ctx, dialGroup, target)
	case "1", "2c":
		return scanner.scanCommunity(ctx, dialGroup, target, version)
	case "auto":
		v3Status, v3Any, v3Err := scanner.scanV3(ctx, dialGroup, target)
		if v3Err == nil {
			// v3 discovery succeeded — enrich with community GET to populate sys* fields.
			if v3Log, ok := v3Any.(*Log); ok {
				scanner.enrichWithSysInfo(ctx, dialGroup, target, v3Log)
			}
			return v3Status, v3Any, nil
		}
		commStatus, commAny, commErr := scanner.scanCommunity(ctx, dialGroup, target, "2c")
		if commErr == nil {
			return commStatus, commAny, nil
		}
		return zgrab2.TryGetScanStatus(v3Err), nil, fmt.Errorf("SNMPv3 discovery failed: %w; SNMPv2c GET failed: %w", v3Err, commErr)
	default:
		return zgrab2.SCAN_APPLICATION_ERROR, nil, fmt.Errorf("unsupported SNMP version %q", scanner.config.Version)
	}
}

// enrichWithSysInfo attempts a SNMPv2c community GET after v3 discovery so
// that sys_descr, sys_name, sys_contact, sys_location etc. are populated even
// when the primary probe was v3. Failures are silently ignored.
func (scanner *Scanner) enrichWithSysInfo(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget, result *Log) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	request, err := BuildGetRequest("2c", scanner.config.Community, systemOIDs)
	if err != nil {
		return
	}
	if _, err = conn.Write(request); err != nil {
		return
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	cr, err := ParseResponse(buf[:n])
	if err != nil {
		return
	}
	if result.Values == nil {
		result.Values = map[string]string{}
	}
	for k, v := range cr.Values {
		if _, exists := result.Values[k]; !exists {
			result.Values[k] = v
		}
	}
	if cr.SysDescr != "" {
		result.SysDescr = cr.SysDescr
	}
	if cr.SysObjectID != "" {
		result.SysObjectID = cr.SysObjectID
	}
	if cr.SysUpTime != "" {
		result.SysUpTime = cr.SysUpTime
	}
	if cr.SysContact != "" {
		result.SysContact = cr.SysContact
	}
	if cr.SysName != "" {
		result.SysName = cr.SysName
	}
	if cr.SysLocation != "" {
		result.SysLocation = cr.SysLocation
	}
	if cr.SysServices != 0 {
		result.SysServices = cr.SysServices
	}
	result.Community = scanner.config.Community
}

func (scanner *Scanner) scanCommunity(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget, version string) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error dialing SNMP target %v: %w", target.String(), err)
	}
	defer func(conn net.Conn) {
		zgrab2.CloseConnAndHandleError(conn)
	}(conn)

	request, err := BuildGetRequest(version, scanner.config.Community, systemOIDs)
	if err != nil {
		return zgrab2.SCAN_APPLICATION_ERROR, nil, err
	}
	if _, err = conn.Write(request); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error sending SNMP request to target %v: %w", target.String(), err)
	}

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error reading SNMP response from target %v: %w", target.String(), err)
	}

	result, err := ParseResponse(buf[:n])
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("error parsing SNMP response from target %v: %w", target.String(), err)
	}
	result.IsSNMP = true
	result.Port = target.Port
	result.Community = scanner.config.Community
	result.Version = version
	result.Probe = "community-get"
	result.Role = "agent"
	result.RawResponseLength = n
	return zgrab2.SCAN_SUCCESS, result, nil
}

func (scanner *Scanner) scanV3(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error dialing SNMP target %v: %w", target.String(), err)
	}
	defer func(conn net.Conn) {
		zgrab2.CloseConnAndHandleError(conn)
	}(conn)

	if _, err = conn.Write(BuildV3DiscoveryRequest()); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error sending SNMPv3 discovery request to target %v: %w", target.String(), err)
	}

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return zgrab2.SCAN_CONNECTION_CLOSED, nil, fmt.Errorf("SNMPv3 discovery target %v closed without response", target.String())
		}
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error reading SNMPv3 discovery response from target %v: %w", target.String(), err)
	}

	result, err := ParseV3DiscoveryResponse(buf[:n])
	if err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("error parsing SNMPv3 discovery response from target %v: %w", target.String(), err)
	}
	result.IsSNMP = true
	result.Port = target.Port
	result.Version = "3"
	result.Probe = "v3-discovery"
	result.Role = "agent"
	result.RawResponseLength = n
	return zgrab2.SCAN_SUCCESS, result, nil
}

func (scanner *Scanner) scanTrapReceiver(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error dialing SNMP trap receiver %v: %w", target.String(), err)
	}
	defer func(conn net.Conn) {
		zgrab2.CloseConnAndHandleError(conn)
	}(conn)

	if _, err = conn.Write(BuildInformRequest(scanner.config.Community)); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("error sending SNMP Inform to %v: %w", target.String(), err)
	}

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		// No response received — may be a silent trap receiver or firewall.
		// Return an inconclusive result rather than a hard failure so the
		// port is still recorded as having received our probe.
		inconclusiveResult := &Log{
			Values: map[string]string{},
			Port:   target.Port,
			Probe:  "v2-inform",
			Role:   "trap_receiver",
		}
		if errors.Is(err, io.EOF) {
			return zgrab2.SCAN_CONNECTION_CLOSED, inconclusiveResult, nil
		}
		return zgrab2.TryGetScanStatus(err), inconclusiveResult, err
	}

	raw := buf[:n]

	// Try v2c response parse first, then v3 discovery parse.
	if parsed, parseErr := ParseResponse(raw); parseErr == nil {
		parsed.IsSNMP = true
		parsed.Port = target.Port
		parsed.Probe = "v2-inform"
		parsed.Role = "trap_receiver"
		parsed.RawResponseLength = n
		return zgrab2.SCAN_SUCCESS, parsed, nil
	}
	if parsed, parseErr := ParseV3DiscoveryResponse(raw); parseErr == nil {
		parsed.IsSNMP = true
		parsed.Port = target.Port
		parsed.Probe = "v2-inform"
		parsed.Role = "trap_receiver"
		parsed.RawResponseLength = n
		return zgrab2.SCAN_SUCCESS, parsed, nil
	}

	// Full parse failed — fall back to BER fingerprint only.
	if looksLikeSNMP(raw) {
		result := &Log{
			IsSNMP:            true,
			Values:            map[string]string{},
			Port:              target.Port,
			Probe:             "v2-inform",
			Role:              "trap_receiver",
			RawResponseLength: n,
		}
		return zgrab2.SCAN_SUCCESS, result, nil
	}

	return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("no recognizable SNMP response from trap receiver %v", target.String())
}

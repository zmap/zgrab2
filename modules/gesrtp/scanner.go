// Package gesrtp provides a zgrab2 module that scans for GE SRTP (Service
// Request Transport Protocol) devices.
// Default port: 18245 (TCP), used by GE/Emerson PACSystems, Series 90, and
// RX3i PLCs.
//
// To keep traffic minimal while remaining accurate, this module performs a
// short, fixed exchange: an Init handshake (56 zero bytes, acknowledged with
// a fixed magic byte pair), followed by a SCADA Enable request and a Return
// Controller Type request -- both read-only identification probes with no
// memory read/write, program upload/download, or CPU control involved. The
// Init handshake alone is a positive, unambiguous identification; the two
// follow-up requests are enrichment that extracts the PLC's program/model
// name and a device-type indicator, and can be skipped with
// --skip-enrichment to reduce the exchange to a single request/response.
//
// See gesrtp.go for the wire-format details and their sources. Note CVE-2022-30263
// documents that GE SRTP transmits credentials in cleartext -- worth keeping
// in mind when this module identifies a listener during OT recon.
package gesrtp

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the gesrtp scan module.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`

	// SkipEnrichment, if set, stops after the Init handshake, skipping the
	// SCADA Enable / Return Controller Type requests (and so not extracting
	// a PLC name or device indicator). Reduces the exchange to a single
	// request/response.
	SkipEnrichment bool `long:"skip-enrichment" description:"Skip the SCADA Enable / Return Controller Type requests after Init, reducing the probe to a single request/response"`
}

// Results is the output of the gesrtp scan module.
type Results struct {
	// InitBanner is set when the target's Init response didn't match the
	// generic ack byte pattern but did carry a recognizable GE PLC
	// self-identification string directly (observed on real PACSystems
	// hardware; see extractGEBanner). Often more informative than PLCName,
	// since it can include firmware version and serial number.
	InitBanner string `json:"init_banner,omitempty"`
	// SCADAEnabled is true if the target acknowledged the SCADA Enable
	// request with a well-formed Return-type response. Omitted entirely
	// when --skip-enrichment is set.
	SCADAEnabled bool `json:"scada_enabled,omitempty"`
	// PLCName is the program/controller name extracted from the Return
	// Controller Type response, when available.
	PLCName string `json:"plc_name,omitempty"`
	// DeviceIndicator is the raw device-type indicator byte from the Return
	// Controller Type response, when available.
	DeviceIndicator *byte `json:"device_indicator,omitempty"`
	// Raw is the hex-encoded Return Controller Type response, included when
	// --verbose is set.
	Raw string `json:"raw,omitempty"`
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	zgrab2.BaseScanner
	config *Flags
}

// NewModule returns a new gesrtp module.
func NewModule() *zgrab2.TypedModule[Flags, Scanner, *Scanner] {
	return zgrab2.NewTypedModule[Flags, Scanner, *Scanner](
		"gesrtp",
		"Probe for GE SRTP (Service Request Transport Protocol) devices",
		"Perform a GE SRTP Init handshake, then optionally a SCADA Enable and Return Controller Type request, identifying GE/Emerson PACSystems, Series 90, and RX3i PLCs and extracting the PLC name where available",
		18245,
	)
}

// Init initializes the Scanner.
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

// Scan connects to the target (default port 18245) and performs the GE SRTP
// Init handshake, followed by SCADA Enable / Return Controller Type
// enrichment unless --skip-enrichment is set.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	conn, err := dialGroup.Dial(ctx, target)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not dial target %s: %w", target.String(), err)
	}
	defer zgrab2.CloseConnAndHandleError(conn)

	if _, err = conn.Write(buildInitPacket()); err != nil {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not send Init packet to %s: %w", target.String(), err)
	}
	// Read whatever comes back rather than assuming a fixed headerLen reply:
	// some real devices' Init response carries a self-identifying banner
	// directly and isn't exactly headerLen bytes (see extractGEBanner).
	initResp, err := zgrab2.ReadAvailable(conn)
	if err != nil && err != io.EOF {
		return zgrab2.TryGetScanStatus(err), nil, fmt.Errorf("could not read Init response from %s: %w", target.String(), err)
	}

	results := &Results{}
	if !validateInitResponse(initResp) {
		banner, ok := extractGEBanner(initResp)
		if !ok {
			return zgrab2.SCAN_PROTOCOL_ERROR, nil, fmt.Errorf("response from %s was not a valid GE SRTP Init acknowledgment", target.String())
		}
		results.InitBanner = banner
	}

	if scanner.config.SkipEnrichment {
		return zgrab2.SCAN_SUCCESS, results, nil
	}

	// SCADA Enable: enrichment only -- Init alone already positively
	// identified the target, so any failure past this point is reported as
	// a successful (if less detailed) scan rather than an error.
	if _, err = conn.Write(scadaEnablePacket); err != nil {
		return zgrab2.SCAN_SUCCESS, results, nil
	}
	scadaResp := make([]byte, headerLen)
	if _, err = io.ReadFull(conn, scadaResp); err != nil {
		return zgrab2.SCAN_SUCCESS, results, nil
	}
	results.SCADAEnabled = validateScadaEnableResponse(scadaResp)
	if !results.SCADAEnabled {
		return zgrab2.SCAN_SUCCESS, results, nil
	}

	// Return Controller Type: further enrichment, same graceful-failure
	// handling.
	if _, err = conn.Write(returnControllerTypePacket); err != nil {
		return zgrab2.SCAN_SUCCESS, results, nil
	}
	ctrlHeader := make([]byte, headerLen)
	if _, err = io.ReadFull(conn, ctrlHeader); err != nil {
		return zgrab2.SCAN_SUCCESS, results, nil
	}
	payloadLen, err := controllerTypePayloadLen(ctrlHeader)
	if err != nil {
		return zgrab2.SCAN_SUCCESS, results, nil
	}
	full := ctrlHeader
	if payloadLen > 0 {
		payload := make([]byte, payloadLen)
		if _, err = io.ReadFull(conn, payload); err != nil {
			return zgrab2.SCAN_SUCCESS, results, nil
		}
		full = append(full, payload...)
	}

	if info, ok := parseControllerTypeResponse(full); ok {
		results.PLCName = info.PLCName
		if info.HasDevice {
			d := info.DeviceIndicator
			results.DeviceIndicator = &d
		}
	}
	if scanner.config.Verbose {
		results.Raw = hex.EncodeToString(full)
	}

	return zgrab2.SCAN_SUCCESS, results, nil
}

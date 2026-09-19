// Package gesrtp implements the wire format of GE SRTP (Service Request
// Transport Protocol), the proprietary protocol spoken by GE/Emerson
// PACSystems, Series 90, and RX3i PLCs on TCP port 18245.
//
// GE does not publish a protocol specification. The byte layouts and
// validation logic here are derived from three independently-produced
// public sources that agree with each other:
//
//   - The original reverse-engineering research: "Leveraging the SRTP
//     Protocol for Over-the-Network Memory Acquisition of a GE Fanuc
//     Series 90-30" (DFRWS, 2017).
//   - github.com/TheMadHatt3r/ge-ethernet-SRTP, an MIT-licensed Python
//     client built from that research and Wireshark captures.
//   - github.com/praetorian-inc/nerva's gesrtp plugin, an Apache-2.0
//     licensed Go network-identification scanner, which is the primary
//     source for the exact request/response byte layouts used below.
//
// This file implements only the read-only identification exchange used by
// nerva: an Init handshake (56 zero bytes), followed by a SCADA Enable
// request and a Return Controller Type request, both fixed-content
// requests requiring no knowledge of any specific PLC's state. No memory
// read/write, program upload/download, or CPU control commands are
// implemented.
package gesrtp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	// headerLen is the fixed size of every GE SRTP message header.
	headerLen = 56

	// packetTypeTransmit and packetTypeReturn are the values found at
	// header byte 0, distinguishing a request ("Transmit") from a
	// response ("Return").
	packetTypeReturn = 0x03

	// initAckByte is the value a genuine GE SRTP listener returns at byte 0
	// of its response to the 56-byte all-zero Init packet.
	initAckByte = 0x01
	// protocolIDByte is the value at byte 8 of a valid Init response.
	protocolIDByte = 0x0f

	// textLengthOffset is the 16-bit little-endian length, within a
	// response header, of any payload trailing the fixed 56-byte header.
	textLengthOffset = 4

	svcSCADAEnable          = 0x4F
	svcReturnControllerType = 0x43

	// Return Controller Type payload offsets, counted from the start of
	// the payload that trails the 56-byte header (i.e. absolute offset
	// headerLen+N).
	ctrlPayloadMaxLen         = 40
	ctrlSvcEchoOffset         = 8
	ctrlDeviceIndicatorOffset = 9
	ctrlPLCNameOffset         = 12
	ctrlPLCNameLen            = 8
)

// scadaEnablePacket is the fixed 56-byte SCADA Enable request (service code
// 0x4F). GE SRTP has several special-cased message formats depending on the
// service being invoked; this is reproduced byte-for-byte from the nerva
// reference implementation rather than reconstructed from the more general
// (and, for this request type, less certain) field-by-field template used
// for memory-read requests.
var scadaEnablePacket = []byte{
	0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc0,
	0x00, 0x00, 0x00, 0x00, 0x10, 0x0e, 0x00, 0x00,
	0x01, 0x01, svcSCADAEnable, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// returnControllerTypePacket is the fixed 56-byte Return Controller Type
// request (service code 0x43), reproduced byte-for-byte from the nerva
// reference implementation. Its response carries the PLC's program/model
// name and a device-type indicator byte.
var returnControllerTypePacket = []byte{
	0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xc0,
	0x00, 0x00, 0x00, 0x00, 0x10, 0x0e, 0x00, 0x00,
	0x01, 0x01, svcReturnControllerType, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// buildInitPacket returns the 56-byte all-zero Init packet every GE SRTP
// session must begin with.
func buildInitPacket() []byte {
	return make([]byte, headerLen)
}

// validateInitResponse checks a response to the Init packet: it must be at
// least headerLen bytes, with byte 0 acknowledging the init (initAckByte)
// and byte 8 carrying the protocol identifier (protocolIDByte).
func validateInitResponse(resp []byte) bool {
	return len(resp) >= headerLen && resp[0] == initAckByte && resp[8] == protocolIDByte
}

// knownGEIdentifiers are distinctive substrings observed in the
// self-identifying banner that some real GE PACSystems devices return
// directly in their Init response, instead of the generic ack byte pattern
// validateInitResponse checks for. Confirmed against a live, internet-facing
// PACSystems RX7i (IC698CPE020) during accuracy validation of this module:
// its Init response was "\x06\x00\x00\x00\x001PACSystems RX7i IC698CPE020
// FW:9.50 SN:GE9706AF73\x06\x00\x00\x00\x00" -- an ack byte of 0x06 (not
// 0x01) followed directly by a plaintext model/firmware/serial string.
var knownGEIdentifiers = []string{
	"PACSystems",
	"GE Fanuc",
	"Series 90-30",
	"Series 90-70",
	"VersaMax",
}

// extractGEBanner scans resp for a recognizable GE PLC self-identification
// string and, if found, returns the trimmed, printable-ASCII text of the
// response (control bytes collapsed to spaces) as a human-readable banner.
// This is a fallback for devices whose Init response carries this banner
// directly rather than (or in addition to) the generic ack byte pattern.
func extractGEBanner(resp []byte) (string, bool) {
	printable := make([]byte, len(resp))
	for i, b := range resp {
		if b >= 0x20 && b < 0x7f {
			printable[i] = b
		} else {
			printable[i] = ' '
		}
	}
	text := strings.Join(strings.Fields(string(printable)), " ")
	for _, marker := range knownGEIdentifiers {
		if strings.Contains(text, marker) {
			return text, true
		}
	}
	return "", false
}

// validateScadaEnableResponse checks that a SCADA Enable response is a
// well-formed "Return" packet.
func validateScadaEnableResponse(resp []byte) bool {
	return len(resp) > 0 && resp[0] == packetTypeReturn
}

// controllerTypeInfo holds the fields extracted from a Return Controller
// Type response.
type controllerTypeInfo struct {
	PLCName         string
	DeviceIndicator byte
	HasDevice       bool
}

// controllerTypePayloadLen inspects a Return Controller Type response's
// header and reports how many additional payload bytes (if any) must still
// be read from the connection, per the textLength field at byte 4. It
// returns an error if the declared length violates the protocol's known
// maximum for this response type.
func controllerTypePayloadLen(header []byte) (int, error) {
	if len(header) < headerLen {
		return 0, fmt.Errorf("header is %d bytes, want %d", len(header), headerLen)
	}
	textLength := binary.LittleEndian.Uint16(header[textLengthOffset : textLengthOffset+2])
	if textLength > ctrlPayloadMaxLen {
		return 0, fmt.Errorf("declared payload length %d exceeds the %d-byte maximum for this response", textLength, ctrlPayloadMaxLen)
	}
	return int(textLength), nil
}

// parseControllerTypeResponse extracts the PLC name and device indicator
// from a full Return Controller Type response (56-byte header plus its
// trailing payload, already concatenated). Returns ok=false if the response
// doesn't carry a usable payload (e.g. the service echo doesn't match) --
// this is not treated as a hard error, since a bare Return Controller Type
// acknowledgment without enrichment data is still a legitimate response.
func parseControllerTypeResponse(full []byte) (info controllerTypeInfo, ok bool) {
	if len(full) < headerLen+ctrlSvcEchoOffset+1 {
		return info, false
	}
	payload := full[headerLen:]
	if payload[ctrlSvcEchoOffset] != svcReturnControllerType {
		return info, false
	}

	if len(payload) > ctrlDeviceIndicatorOffset {
		info.DeviceIndicator = payload[ctrlDeviceIndicatorOffset]
		info.HasDevice = true
	}
	if len(payload) >= ctrlPLCNameOffset+ctrlPLCNameLen {
		info.PLCName = nullTerminatedASCII(payload[ctrlPLCNameOffset : ctrlPLCNameOffset+ctrlPLCNameLen])
	}
	return info, true
}

// nullTerminatedASCII returns the portion of b before its first NUL byte,
// or all of b if there is none.
func nullTerminatedASCII(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

package pcworx

import (
	"bytes"
	"errors"
	"strings"
)

// The Phoenix Contact PC WorX protocol runs over TCP, usually on port 1962.
// A session starts with a fixed "init comms" handshake; the device echoes
// back a fixed-shape response containing a one-byte session id (byte 17)
// that must be threaded through two more requests to pull PLC identity
// info out of a third response. Byte layout is taken from the
// nmap-service-probes "pcworx" match rule.

// initComms is the initial handshake request.
var initComms = []byte{
	0x01, 0x01, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00,
	0x78, 0x80, 0x00, 0x03, 0x00, 0x0c,
	'I', 'B', 'E', 'T', 'H', '0', '1', 'N', '0', '_', 'M', 0x00,
}

// handshakePrefix is everything up to the session id byte (index 17) in a
// valid handshake response; the two bytes after the session id must also be 0x00.
var handshakePrefix = []byte{
	0x81, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
}

const sessionIDOffset = 17

// ErrNotPCWorx is returned when the handshake response doesn't match the
// expected PC WorX signature.
var ErrNotPCWorx = errors.New("no valid PC WorX response")

// DeviceInfo is the JSON-serializable result of a PC WorX scan. Only the
// handshake is required for a confirmed detection; the identity fields are
// filled in on a best-effort basis since not every device answers the
// follow-up info request.
type DeviceInfo struct {
	PLCType         string `json:"plc_type,omitempty"`
	ModelNumber     string `json:"model_number,omitempty"`
	FirmwareVersion string `json:"firmware_version,omitempty"`
	FirmwareDate    string `json:"firmware_date,omitempty"`
	FirmwareTime    string `json:"firmware_time,omitempty"`
}

// matchesHandshake reports whether resp is a valid PC WorX handshake reply.
func matchesHandshake(resp []byte) bool {
	if len(resp) < 20 {
		return false
	}
	if !bytes.Equal(resp[:sessionIDOffset], handshakePrefix) {
		return false
	}
	return resp[sessionIDOffset+1] == 0x00 && resp[sessionIDOffset+2] == 0x00
}

// buildSetSessionRequest builds the second-stage request that activates the session id.
func buildSetSessionRequest(sid byte) []byte {
	req := []byte{0x01, 0x05, 0x00, 0x16, 0x00, 0x01, 0x00, 0x00, 0x78, 0x80, 0x00}
	req = append(req, sid)
	req = append(req, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x02, 0x95, 0x00, 0x00)
	return req
}

// buildInfoRequest builds the third-stage request that asks for PLC identity info.
func buildInfoRequest(sid byte) []byte {
	req := []byte{0x01, 0x06, 0x00, 0x0e, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00}
	req = append(req, sid)
	req = append(req, 0x04, 0x00)
	return req
}

// cstrAt reads a NUL-terminated (or buffer-end-terminated) string at an
// absolute byte offset.
func cstrAt(data []byte, offset int) string {
	if offset < 0 || offset >= len(data) {
		return ""
	}
	end := bytes.IndexByte(data[offset:], 0x00)
	if end < 0 {
		end = len(data) - offset
	}
	return strings.TrimSpace(string(data[offset : offset+end]))
}

// parseInfoResponse extracts PLC identity fields from a third-stage info
// response. Field offsets come from the nmap PC WorX probe.
func parseInfoResponse(resp []byte) *DeviceInfo {
	if len(resp) == 0 || resp[0] != 0x81 {
		return nil
	}
	info := &DeviceInfo{
		PLCType:         cstrAt(resp, 30),
		ModelNumber:     cstrAt(resp, 152),
		FirmwareVersion: cstrAt(resp, 66),
		FirmwareDate:    cstrAt(resp, 79),
		FirmwareTime:    cstrAt(resp, 91),
	}
	return info
}

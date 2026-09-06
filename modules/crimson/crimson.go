package crimson

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net"
	"strings"
)

// Based on nmap's cr3-fingerprint.nse script and the CR3 fingerprinting
// probes used against it: the client sends a small fixed "get property"
// request for a numeric property ID (0x2b for manufacturer, 0x2a for model)
// and the device replies with a 6-byte header followed by a NUL-terminated
// ASCII string.
// Protocol runs over TCP, usually on port 789.
const (
	probeManufacturerHex = "0004012b1b00"
	probeModelHex        = "0004012a1a00"

	// headerSize is the length of the fixed CR3 response header that
	// precedes the NUL-terminated string payload.
	headerSize  = 6
	readBufSize = 4096
)

var (
	probeManufacturer []byte
	probeModel        []byte
)

func init() {
	var err error
	probeManufacturer, err = hex.DecodeString(probeManufacturerHex)
	if err != nil {
		panic("could not decode Crimson manufacturer probe")
	}
	probeModel, err = hex.DecodeString(probeModelHex)
	if err != nil {
		panic("could not decode Crimson model probe")
	}
}

// ErrNotCrimson is returned when neither probe yields a recognizable CR3 string.
var ErrNotCrimson = errors.New("no valid Crimson/Red Lion CR3 response")

// DeviceInfo is the JSON-serializable result of a Crimson scan.
type DeviceInfo struct {
	// Manufacturer is the vendor string returned for property 0x2b (typically "Red Lion Controls").
	Manufacturer string `json:"manufacturer,omitempty"`
	// Model is the device/model string returned for property 0x2a.
	Model string `json:"model,omitempty"`
}

// exchange writes probe to conn and returns whatever response comes back.
func exchange(conn net.Conn, probe []byte) ([]byte, error) {
	if _, err := conn.Write(probe); err != nil {
		return nil, err
	}
	buf := make([]byte, readBufSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// parseCR3String extracts the NUL-terminated ASCII payload from a CR3
// response, skipping the fixed 6-byte header. It returns "" if the response
// is too short or doesn't contain any alphanumeric text, since devices that
// don't understand the probe often echo back empty or garbage data.
func parseCR3String(resp []byte) string {
	if len(resp) <= headerSize {
		return ""
	}
	body := bytes.TrimSuffix(resp[headerSize:], []byte{0})
	if i := bytes.IndexByte(body, 0); i >= 0 {
		body = body[:i]
	}
	text := strings.TrimSpace(string(body))
	for _, r := range text {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return text
		}
	}
	return ""
}

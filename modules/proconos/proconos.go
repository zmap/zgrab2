package proconos

import (
	"bytes"
	"errors"
)

// probe elicits a device-info response from a ProConOS (Phoenix Contact /
// KW-Software) PLC runtime. The response layout is:
//
//	0xcc 0x01 <3 bytes> 0x02 0x92 0x00 'V' <os version> "ProConOS V" <version>
//	" " <3-letter month> <spaces> <day> " " <year>   (build date, ignored)
//	<NUL run> <PLC name> \x00 <project A> \x00 <project B> \x00 <source> \x00
//
// Runs over TCP, usually on port 20547.
var probe = []byte{0xcc, 0x01, 0x00, 0x0b, 0x40, 0x02, 0x00, 0x00, 0x47, 0xee}

const readBufSize = 4096

// ErrNotProConOS is returned when the response doesn't match the expected
// ProConOS signature.
var ErrNotProConOS = errors.New("no valid ProConOS response")

// DeviceInfo is the JSON-serializable result of a ProConOS scan.
type DeviceInfo struct {
	// OSVersion is the runtime OS version reported before the "ProConOS V" marker.
	OSVersion string `json:"os_version,omitempty"`
	// Version is the ProConOS runtime version.
	Version string `json:"version,omitempty"`
	// PLC is the PLC/hardware model name.
	PLC string `json:"plc,omitempty"`
	// Project is the loaded project name (or "A/B" if two distinct names are reported).
	Project string `json:"project,omitempty"`
	// Source is the source path/identifier reported by the device.
	Source string `json:"source,omitempty"`
}

func isDigitOrDot(b byte) bool {
	return (b >= '0' && b <= '9') || b == '.'
}

// readDigitsOrDots consumes a run of ASCII digits/dots starting at pos.
func readDigitsOrDots(resp []byte, pos int) (string, int) {
	start := pos
	for pos < len(resp) && isDigitOrDot(resp[pos]) {
		pos++
	}
	return string(resp[start:pos]), pos
}

// skipNulls advances pos past a run of one or more NUL bytes.
func skipNulls(resp []byte, pos int) (int, bool) {
	start := pos
	for pos < len(resp) && resp[pos] == 0x00 {
		pos++
	}
	return pos, pos > start
}

// readUntilNull reads bytes up to (not including) the next NUL byte.
func readUntilNull(resp []byte, pos int) (string, int, bool) {
	idx := bytes.IndexByte(resp[pos:], 0x00)
	if idx < 0 {
		return "", pos, false
	}
	return string(resp[pos : pos+idx]), pos + idx, true
}

// parseResponse validates the fixed ProConOS signature bytes and extracts
// the runtime version, PLC name, project name(s), and source path from the
// NUL-delimited string table that follows.
func parseResponse(resp []byte) (*DeviceInfo, error) {
	const magicLen = 9 // 0xcc 0x01 + 3 arbitrary bytes + 0x02 0x92 0x00 + 'V'
	if len(resp) < magicLen ||
		resp[0] != 0xcc || resp[1] != 0x01 ||
		resp[5] != 0x02 || resp[6] != 0x92 || resp[7] != 0x00 ||
		resp[8] != 'V' {
		return nil, ErrNotProConOS
	}

	pos := magicLen
	var osVersion, version, plc, projectA, projectB, source string
	var ok bool

	osVersion, pos = readDigitsOrDots(resp, pos)
	if osVersion == "" {
		return nil, ErrNotProConOS
	}

	const marker = "ProConOS V"
	if pos+len(marker) > len(resp) || string(resp[pos:pos+len(marker)]) != marker {
		return nil, ErrNotProConOS
	}
	pos += len(marker)

	version, pos = readDigitsOrDots(resp, pos)
	if version == "" {
		return nil, ErrNotProConOS
	}

	// Skip the build-date stamp (e.g. " Jan  1 2024") up to the NUL padding
	// that separates it from the string table.
	dateEnd := bytes.IndexByte(resp[pos:], 0x00)
	if dateEnd < 0 {
		return nil, ErrNotProConOS
	}
	pos += dateEnd

	if pos, ok = skipNulls(resp, pos); !ok {
		return nil, ErrNotProConOS
	}
	if plc, pos, ok = readUntilNull(resp, pos); !ok {
		return nil, ErrNotProConOS
	}
	pos, _ = skipNulls(resp, pos)
	if projectA, pos, ok = readUntilNull(resp, pos); !ok {
		return nil, ErrNotProConOS
	}
	pos, _ = skipNulls(resp, pos)
	if projectB, pos, ok = readUntilNull(resp, pos); !ok {
		return nil, ErrNotProConOS
	}
	pos, _ = skipNulls(resp, pos)
	if source, _, ok = readUntilNull(resp, pos); !ok {
		return nil, ErrNotProConOS
	}

	project := projectA
	if projectB != "" && projectB != projectA {
		project = projectA + "/" + projectB
	}

	return &DeviceInfo{
		OSVersion: osVersion,
		Version:   version,
		PLC:       plc,
		Project:   project,
		Source:    source,
	}, nil
}

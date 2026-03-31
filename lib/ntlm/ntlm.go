// Package ntlm provides shared types and helpers for extracting fingerprint
// information from NTLMSSP Challenge messages. It is protocol-agnostic and
// can be used by any module that obtains an NTLM challenge (RDP, SMB, HTTP, etc.).
package ntlm

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Info holds the fingerprint data extracted from an NTLM Challenge message.
type Info struct {
	// Version is the OS version string from the NTLM Version field (e.g. "10.0.17763").
	OSVersion string `json:"os_version,omitempty"`
	// TargetName is the server's target name from the challenge.
	TargetName string `json:"target_name,omitempty"`
	// NetBIOSComputerName from AvPair MsvAvNbComputerName.
	NetBIOSComputerName string `json:"netbios_computer_name,omitempty"`
	// NetBIOSDomainName from AvPair MsvAvNbDomainName.
	NetBIOSDomainName string `json:"netbios_domain_name,omitempty"`
	// DNSComputerName (FQDN) from AvPair MsvAvDnsComputerName.
	DNSComputerName string `json:"dns_computer_name,omitempty"`
	// DNSDomainName from AvPair MsvAvDnsDomainName.
	DNSDomainName string `json:"dns_domain_name,omitempty"`
	// ForestName from AvPair MsvAvDnsTreeName.
	ForestName string `json:"forest_name,omitempty"`
}

// AvPair IDs as defined in MS-NLMP §2.2.2.1.
const (
	AvIDMsvAvEOL             uint16 = 0
	AvIDMsvAvNbComputerName  uint16 = 1
	AvIDMsvAvNbDomainName    uint16 = 2
	AvIDMsvAvDnsComputerName uint16 = 3
	AvIDMsvAvDnsDomainName   uint16 = 4
	AvIDMsvAvDnsTreeName     uint16 = 5
)

// VersionFromUint64 decodes the 8-byte NTLM Version structure packed as a
// uint64 (little-endian) into an "Major.Minor.Build" string.
// Returns empty string if the version structure marker (0x0F) is not present.
func VersionFromUint64(v uint64) string {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	// b[0] = major, b[1] = minor, b[2:4] = build (LE), b[4:7] = reserved, b[7] = revision (0x0F)
	if b[7] != 0x0F {
		return ""
	}
	major := b[0]
	minor := b[1]
	build := binary.LittleEndian.Uint16(b[2:4])
	return fmt.Sprintf("%d.%d.%d", major, minor, build)
}

// VersionFromBytes decodes an 8-byte NTLM Version structure into an
// "Major.Minor.Build" string. Returns empty string on invalid input.
func VersionFromBytes(b []byte) string {
	if len(b) < 8 || b[7] != 0x0F {
		return ""
	}
	major := b[0]
	minor := b[1]
	build := binary.LittleEndian.Uint16(b[2:4])
	return fmt.Sprintf("%d.%d.%d", major, minor, build)
}

// cleanString strips null bytes from a UTF-16LE encoded string.
func cleanString(b []byte) string {
	return strings.ReplaceAll(string(b), "\x00", "")
}

// InfoFromAvPairs populates an Info struct from a slice of (id, value) pairs
// as found in the NTLM Challenge TargetInfo field. The pairs parameter is a
// slice of structs with AvID (uint16) and Value ([]byte) fields — matching
// the AvPairSlice type used by lib/smb/ntlmssp.
//
// This function accepts an interface to avoid importing the smb package. Each
// element must have exported AvID uint16 and Value []byte fields accessible
// via the AvPairEntry interface.
func InfoFromAvPairs(info *Info, pairs []AvPairEntry) {
	for _, pair := range pairs {
		id, val := pair.GetAvID(), pair.GetValue()
		value := cleanString(val)
		switch id {
		case AvIDMsvAvNbComputerName:
			info.NetBIOSComputerName = value
		case AvIDMsvAvNbDomainName:
			info.NetBIOSDomainName = value
		case AvIDMsvAvDnsComputerName:
			info.DNSComputerName = value
		case AvIDMsvAvDnsDomainName:
			info.DNSDomainName = value
		case AvIDMsvAvDnsTreeName:
			info.ForestName = value
		}
	}
}

// AvPairEntry is a minimal interface for accessing NTLM AV_PAIR fields.
type AvPairEntry interface {
	GetAvID() uint16
	GetValue() []byte
}

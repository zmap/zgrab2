package rdp

import "github.com/zmap/zgrab2"

/*
 * Adapted from https://github.com/nmap/nmap/blob/136e1c6ed771119d3d0aa2629efc5dbc783f946d/scripts/rdp-ntlm-info.nse#L79
 */

var NTLM_NEGOTIATE_BLOB = []byte{
	0x30, 0x37, 0xA0, 0x03, 0x02, 0x01, 0x60, 0xA1, 0x30, 0x30, 0x2E, 0x30, 0x2C, 0xA0, 0x2A, 0x04, 0x28,
	0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, // Identifer, NTLMSSP
	0x01, 0x00, 0x00, 0x00, //NTLM Negotiate (01)
	// Negotiate Flags
	0xB7, 0x82, 0x08, 0xE2, //Flags (NEGOTIATE_SIGN_ALWAYS | NEGOTIATE_NTLM | NEGOTIATE_SIGN | REQUEST_TARGET | NEGOTIATE_UNICODE)
	// Domain Name Fields
	0x00, 0x00, // DomainNameLen
	0x00, 0x00, // DomainNameMaxLen
	0x00, 0x00, 0x00, 0x00, // DomainNameBufferOffset
	0x00, 0x00, // WorkstationLen
	0x00, 0x00, // WorkstationMaxLen
	0x00, 0x00, 0x00, 0x00, // WorkstationBufferOffset
	// Version
	0x0A,       // Major Version
	0x00,       // Minor Version
	0x63, 0x45, // Build #
	0x00, 0x00, 0x00, // Reserved
	0x0F, //NTLMRevision = 5 = NTLMSSP_REVISION_W2K3
}

var NTLM_PREFIX = []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}

var NTLM_AV_ID_VALUES = map[uint16]string{
	1:  "netbios_computer_name",
	2:  "netbios_domain_name",
	3:  "fqdn",
	4:  "dns_domain_name",
	5:  "dns_forest_name",
	6:  "flags",
	7:  "timestamp",
	8:  "restrictions",
	9:  "target_ame",
	10: "channel_bindings",
}

const NTLM_RESPONSE_LENGTH = 56

type NTLMSecurityBlob struct {
	Signature              [8]byte
	MessageType            uint32
	DomainNameLen          uint16
	DomainNameMaxLen       uint16
	DomainNameBufferOffset uint32
	NegotiateFlags         uint32
	ServerChallenge        uint64
	Reserved               uint64
	TargetInfoLen          uint16
	TargetInfoMaxLen       uint16
	TargetInfoBufferOffset uint32
	Version                [8]byte
}

type OSVersion struct {
	MajorVersion byte
	MinorVersion byte
	BuildNumber  uint16
}

type RDPResult struct {
	OSVersion           string         `json:"os_version,omitempty"`
	TargetName          string         `json:"target_name,omitempty"`
	NetBIOSComputerName string         `json:"netbios_computer_name,omitempty"`
	NetBIOSDomainName   string         `json:"netbios_domain_name,omitempty"`
	DNSComputerName     string         `json:"dns_computer_name,omitempty"`
	DNSDomainName       string         `json:"dns_domain_name,omitempty"`
	ForestName          string         `json:"forest_name,omitempty"`
	TLSLog              *zgrab2.TLSLog `json:"tls,omitempty"`
}

const AV_ITEM_LENGTH = 4

const AV_EOL = 0

type AVItem struct {
	Id     uint16
	Length uint16
}

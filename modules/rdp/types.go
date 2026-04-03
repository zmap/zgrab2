package rdp

import (
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/ntlm"
)

// -----------------------------------------------------------------------
// X.224 / RDP Negotiation constants and types (MS-RDPBCGR §2.2.1)
// -----------------------------------------------------------------------

const (
	x224TPDUConnectionRequest = 0xE0
	x224TPDUConnectionConfirm = 0xD0
)

const (
	typeRDPNegReq     = 0x01
	typeRDPNegRsp     = 0x02
	typeRDPNegFailure = 0x03
)

// Requested/selected protocol bitmask values.
// See [MS-RDPBCGR] §2.2.1.1.1 RDP Negotiation Request and §2.2.1.2.1 RDP Negotiation Response:
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3
const (
	protocolRDP      = 0x00000000 // PROTOCOL_RDP: Standard RDP Security
	protocolSSL      = 0x00000001 // PROTOCOL_SSL: TLS 1.x
	protocolHybrid   = 0x00000002 // PROTOCOL_HYBRID: CredSSP (TLS + NTLM/Kerberos), i.e. NLA
	protocolRDSTLS   = 0x00000004 // PROTOCOL_RDSTLS
	protocolHybridEx = 0x00000008 // PROTOCOL_HYBRID_EX: CredSSP with Early User Authorization
)

var selectedProtocolNames = map[uint32]string{
	protocolRDP:      "standard_rdp",
	protocolSSL:      "ssl",
	protocolHybrid:   "hybrid",
	protocolRDSTLS:   "rdstls",
	protocolHybridEx: "hybrid_ex",
}

var failureCodeNames = map[uint32]string{
	0x01: "ssl_required_by_server",
	0x02: "ssl_not_allowed_by_server",
	0x03: "ssl_cert_not_on_server",
	0x04: "inconsistent_flags",
	0x05: "hybrid_required_by_server",
	0x06: "ssl_with_user_auth_required",
}

// RDP negotiation response flags.
// See [MS-RDPBCGR] §2.2.1.2.1 RDP Negotiation Response (RDP_NEG_RSP):
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2975bdc-6d56-49ee-9c57-f2ff3a0b6817
const (
	negRspFlagExtendedClientData = 0x01
	negRspFlagDynvcGfx           = 0x02
	negRspFlagRestrictedAdmin    = 0x08
	negRspFlagRedirectedAuth     = 0x10
)

// NegotiationFlags is the decoded RDP_NEG_RSP flags field.
// See [MS-RDPBCGR] §2.2.1.2.1 RDP Negotiation Response (RDP_NEG_RSP):
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2975bdc-6d56-49ee-9c57-f2ff3a0b6817
type NegotiationFlags struct {
	// Server supports Extended Client Data Blocks in the GCC Conference Create Request.
	ExtendedClientDataSupported bool `json:"extended_client_data_supported"`
	// Server supports the Graphics Pipeline Extension Protocol (MS-RDPEGFX).
	DynvcGfxProtocolSupported bool `json:"dynvc_gfx_protocol_supported"`
	// Server supports restricted admin mode — credential-less logon over CredSSP.
	RestrictedAdminModeSupported bool `json:"restricted_admin_mode_supported"`
	// Server supports Remote Credential Guard — redirected credential authentication.
	RedirectedAuthModeSupported bool `json:"redirected_authentication_mode_supported"`
}

func decodeNegotiationFlags(raw uint8) *NegotiationFlags {
	return &NegotiationFlags{
		ExtendedClientDataSupported:  raw&negRspFlagExtendedClientData != 0,
		DynvcGfxProtocolSupported:    raw&negRspFlagDynvcGfx != 0,
		RestrictedAdminModeSupported: raw&negRspFlagRestrictedAdmin != 0,
		RedirectedAuthModeSupported:  raw&negRspFlagRedirectedAuth != 0,
	}
}

// x224Cookie is sent inside the Connection Request as a routing token.
var x224Cookie = []byte("Cookie: mstshash=zgrab\r\n")

// -----------------------------------------------------------------------
// NTLM constants and types (unchanged, adapted from nmap rdp-ntlm-info)
// -----------------------------------------------------------------------

var NTLM_NEGOTIATE_BLOB = []byte{
	0x30, 0x37, 0xA0, 0x03, 0x02, 0x01, 0x60, 0xA1, 0x30, 0x30, 0x2E, 0x30, 0x2C, 0xA0, 0x2A, 0x04, 0x28,
	0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, // Identifier, NTLMSSP
	0x01, 0x00, 0x00, 0x00, // NTLM Negotiate (01)
	// Negotiate Flags
	0xB7, 0x82, 0x08, 0xE2, // Flags (NEGOTIATE_SIGN_ALWAYS | NEGOTIATE_NTLM | NEGOTIATE_SIGN | REQUEST_TARGET | NEGOTIATE_UNICODE)
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
	0x0F, // NTLMRevision = 5 = NTLMSSP_REVISION_W2K3
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
	9:  "target_name",
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

// -----------------------------------------------------------------------
// Result types
// -----------------------------------------------------------------------

// RDPResult is the output of the RDP scan.
type RDPResult struct {
	// X.224 negotiation results (populated for all RDP servers)
	SelectedProtocol string            `json:"selected_protocol,omitempty"`
	NegotiationFlags *NegotiationFlags `json:"negotiation_flags,omitempty"`
	FailureCode      string            `json:"failure_code,omitempty"`

	// NTLM results (populated only for Microsoft RDP with CredSSP/NLA)
	NTLM   *ntlm.Info     `json:"ntlm,omitempty"`
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

const AV_ITEM_LENGTH = 4

const AV_EOL = 0

type AVItem struct {
	Id     uint16
	Length uint16
}

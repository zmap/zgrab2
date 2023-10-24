package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

type FirstAnswer struct {
	IsRDP         bool
	CanPerformTLS bool
	ProtocolFlags []string
}

func newFirstAnswer(msg []byte) FirstAnswer {
	if len(msg) != 19 {
		return FirstAnswer{}
	}

	answer := FirstAnswer{}

	answer.IsRDP = bytes.Equal(msg[0:10], rdpIndicator)
	answer.CanPerformTLS = msg[11] == 0x02
	answer.ProtocolFlags = newProtocolFlags(msg[12])

	return answer
}

func newProtocolFlags(b byte) []string {
	return getFlags(map[string]uint32{
		"EXTENDED_CLIENT_DATA_SUPPORTED":           1 << 0,
		"DYNVC_GFX_PROTOCOL_SUPPORTED":             1 << 1,
		"RESTRICTED_ADMIN_MODE_SUPPORTED":          1 << 3,
		"REDIRECTED_AUTHENTICATION_MODE_SUPPORTED": 1 << 4,
	}, uint32(b))
}

type NTLMInfo struct {
	Raw            []byte     `json:"raw,omitempty"`
	TargetName     string     `json:"target_name,omitempty"`
	Os             Os         `json:"os,omitempty"`
	TargetInfo     TargetInfo `json:"target_info,omitempty"`
	NegotiateFlags []string   `json:"negotiate_flags,omitempty"`
}

func newNTLMInfo(ntlmBytes []byte) NTLMInfo {
	info := NTLMInfo{
		Raw: ntlmBytes,
	}

	ntlmInfoIndex := bytes.IndexAny(ntlmBytes, "NTLMSSP")
	if ntlmInfoIndex == -1 {
		return info
	}

	ntlmInfoBytes := ntlmBytes[ntlmInfoIndex:]

	targetNameLen := binary.LittleEndian.Uint16(ntlmInfoBytes[12:14])
	targetNameOffset := binary.LittleEndian.Uint32(ntlmInfoBytes[16:20])
	info.TargetName = decodeString(ntlmInfoBytes[targetNameOffset : targetNameOffset+uint32(targetNameLen)])

	info.NegotiateFlags = parseNegotiateFlags(binary.LittleEndian.Uint32(ntlmInfoBytes[20:24]))

	info.Os = newOS(ntlmInfoBytes[48:56])

	targetInfoLen := binary.LittleEndian.Uint16(ntlmInfoBytes[40:42])
	targetInfoOffset := binary.LittleEndian.Uint32(ntlmInfoBytes[44:48])
	targetInfoBytes := ntlmInfoBytes[targetInfoOffset : targetInfoOffset+uint32(targetInfoLen)]

	info.TargetInfo = newTargetInfo(targetInfoBytes)

	return info
}

type Os struct {
	Name  string `json:"name,omitempty"`
	Build string `json:"build,omitempty"`
}

func newOS(osBytes []byte) Os {
	majorVersion := osBytes[0]
	minorVersion := osBytes[1]
	build := binary.LittleEndian.Uint16(osBytes[2:4])

	name := "Unknown"
	switch majorVersion {
	case 5:
		switch minorVersion {
		case 1:
			name = "Windows XP (SP2)"
		case 2:
			name = "Windows Server 2003"
		}
	case 6:
		switch minorVersion {
		case 0:
			name = "Windows Server 2008 / Windows Vista"
		case 1:
			name = "Windows Server 2008 R2 / Windows 7"
		case 2:
			name = "Windows Server 2012 / Windows 8"
		case 3:
			name = "Windows Server 2012 R2 / Windows 8.1"
		}
	case 10:
		switch minorVersion {
		case 0:
			name = "Windows Server 2016 or 2019 / Windows 10"
		}
	}

	return Os{
		Name:  name,
		Build: fmt.Sprintf("%d.%d.%d", majorVersion, minorVersion, build),
	}
}

type TargetInfo struct {
	NetbiosDomainName    string `json:"netbios_domain_name,omitempty"`
	NetbiosComputerName  string `json:"netbios_computer_name,omitempty"`
	Fqdn                 string `json:"fqdn,omitempty"`
	DnsDomainName        string `json:"dns_domain_name,omitempty"`
	MsvAvDnsTreeName     string `json:"msv_av_dns_tree_name,omitempty"`
	MsvAvTimestamp       string `json:"msv_av_timestamp,omitempty"`
	MsvAvSingleHost      string `json:"msv_av_single_host,omitempty"`
	MsvAvTargetName      string `json:"msv_av_target_name,omitempty"`
	MsvAvChannelBindings string `json:"msv_av_channel_bindings,omitempty"`
}

func newTargetInfo(targetInfoBytes []byte) TargetInfo {
	const (
		MsvAvEOL             = 0x0000
		MsvAvNbComputerName  = 0x0001
		MsvAvNbDomainName    = 0x0002
		MsvAvDnsComputerName = 0x0003
		MsvAvDnsDomainName   = 0x0004
		MsvAvDnsTreeName     = 0x0005
		MsvAvFlags           = 0x0006
		MsvAvTimestamp       = 0x0007
		MsvAvSingleHost      = 0x0008
		MsvAvTargetName      = 0x0009
		MsvAvChannelBindings = 0x000A

		unixAndWindowsFileTimeStartDifference = 116444736000000000
		secondAnd100nsDifference              = 10000000
	)

	info := TargetInfo{}

	for offset := 0; offset < len(targetInfoBytes); {
		avID := binary.LittleEndian.Uint16(targetInfoBytes[offset : offset+2])
		avLen := binary.LittleEndian.Uint16(targetInfoBytes[offset+2 : offset+4])
		avValue := targetInfoBytes[offset+4 : offset+4+int(avLen)]

		offset = offset + 4 + int(avLen)

		switch avID {
		case MsvAvEOL, MsvAvFlags:
			continue
		case MsvAvNbComputerName:
			info.NetbiosComputerName = decodeString(avValue)
		case MsvAvNbDomainName:
			info.NetbiosDomainName = decodeString(avValue)
		case MsvAvDnsComputerName:
			info.Fqdn = decodeString(avValue)
		case MsvAvDnsDomainName:
			info.DnsDomainName = decodeString(avValue)
		case MsvAvDnsTreeName:
			info.MsvAvDnsTreeName = decodeString(avValue)
		case MsvAvTimestamp:
			// windows filetime recorded in 100ns and starts from 01-01-1601
			// the difference between windows filetime start and unix timestamp start is 116444736000000000 counting in 100ns
			// the difference between 100ns and second is 10^7
			// now using time.Duration and time.Add because of int64 overflow
			info.MsvAvTimestamp = time.Unix(
				int64((binary.LittleEndian.Uint64(avValue)-unixAndWindowsFileTimeStartDifference)/secondAnd100nsDifference),
				0,
			).Format(time.RFC3339)
		case MsvAvSingleHost:
			info.MsvAvSingleHost = decodeString(avValue)
		case MsvAvTargetName:
			info.MsvAvTargetName = decodeString(avValue)
		case MsvAvChannelBindings:
			info.MsvAvChannelBindings = decodeString(avValue)
		}
	}

	return info
}

func parseNegotiateFlags(flags uint32) []string {
	return getFlags(map[string]uint32{
		"NTLMSSP_NEGOTIATE_UNICODE":                  1 << 0,
		"NTLM_NEGOTIATE_OEM":                         1 << 1,
		"NTLMSSP_REQUEST_TARGET":                     1 << 2,
		"NTLMSSP_NEGOTIATE_SIGN":                     1 << 4,
		"NTLMSSP_NEGOTIATE_SEAL":                     1 << 5,
		"NTLMSSP_NEGOTIATE_DATAGRAM":                 1 << 6,
		"NTLMSSP_NEGOTIATE_LM_KEY":                   1 << 7,
		"NTLMSSP_NEGOTIATE_NTLM":                     1 << 9,
		"NTLMSSP_ANONYMOUS":                          1 << 11,
		"NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED":      1 << 12,
		"NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED": 1 << 13,
		"NTLMSSP_NEGOTIATE_ALWAYS_SIGN":              1 << 15,
		"NTLMSSP_TARGET_TYPE_DOMAIN":                 1 << 16,
		"NTLMSSP_TARGET_TYPE_SERVER":                 1 << 17,
		"NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY": 1 << 19,
		"NTLMSSP_NEGOTIATE_IDENTIFY":                 1 << 20,
		"NTLMSSP_REQUEST_NON_NT_SESSION_KEY":         1 << 22,
		"NTLMSSP_NEGOTIATE_TARGET_INFO":              1 << 23,
		"NTLMSSP_NEGOTIATE_VERSION":                  1 << 25,
		"NTLMSSP_NEGOTIATE_128":                      1 << 29,
		"NTLMSSP_NEGOTIATE_KEY_EXCH":                 1 << 30,
		"NTLMSSP_NEGOTIATE_56":                       1 << 31,
	}, flags)
}

func decodeString(input []byte) string {
	return string(bytes.ReplaceAll(input, []byte{0x00}, []byte{}))
}

func getFlags(allFlagsMap map[string]uint32, inputFlags uint32) []string {
	var resFlags []string
	for flagName, flagValue := range allFlagsMap {
		if inputFlags&flagValue == flagValue {
			resFlags = append(resFlags, flagName)
		}
	}

	return resFlags
}

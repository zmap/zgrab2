package smb

import (
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	"unicode/utf16"

	"github.com/zmap/zgrab2/lib/smb/gss"
	"github.com/zmap/zgrab2/lib/smb/ntlmssp"
	"github.com/zmap/zgrab2/lib/smb/smb/encoder"
)

// HeaderLog contains the relevant parts of the header that is included with
// each packet.
type HeaderLog struct {
	// ProtocolID identifies the SMB protocol version (e.g. ProtocolSmb ==
	// "\xFFSMB")
	ProtocolID []byte `json:"protocol_id"`

	// Status is the server's status; e.g. NTSTATUS
	// (https://msdn.microsoft.com/en-us/library/cc704588.aspx).
	Status uint32 `json:"status"`

	// Command is the command identifier.
	Command uint16 `json:"command"`

	// Credits is the number of credits granted to the client.
	Credits uint16 `json:"credits"`

	// Flags is the flags for the request (see
	// https://msdn.microsoft.com/en-us/library/cc246529.aspx)
	Flags uint32 `json:"flags"`
}

// NegotiationLog contains the relevant parts of the negotiation response
// packet.  See https://msdn.microsoft.com/en-us/library/cc246561.aspx.
type NegotiationLog struct {
	HeaderLog

	// SecurityMode is the server's security mode (e.g. signing
	// enabled/required).
	SecurityMode uint16 `json:"security_mode"`

	// DialectRevision is the SMB2 dialect number; 0x2FF is the wildcard.
	DialectRevision uint16 `json:"dialect_revision"`

	// ServerGuid is the server's globally unique identifier.
	ServerGuid []byte `json:"server_guid"`

	// Capabilities specifies protocol capabilities for the server.
	Capabilities uint32 `json:"capabilities"`

	// SystemTime is the time (in seconds since Unix epoch) the server received
	// the negotiation request.
	SystemTime uint32 `json:"system_time"`

	// ServerStartTime is the time (in seconds since the Unix epoch) the server started.
	ServerStartTime uint32 `json:"server_start_time"`

	// AuthenticationTypes is a list of OBJECT IDENTIFIERs (in dotted-decimal
	// format) identifying authentication modes that the server supports.
	AuthenticationTypes []string `json:"authentication_types,omitempty"`
}

// SessionSetupLog contains the relevant parts of the first session setup
// response packet.  See https://msdn.microsoft.com/en-us/library/cc246564.aspx
type SessionSetupLog struct {
	HeaderLog

	// SetupFlags is the gives additional information on the session.
	SetupFlags uint16 `json:"setup_flags"`

	// TargetName is the target name from the challenge packet
	TargetName string `json:"target_name"`

	// NegotiateFlags are the flags from the challenge packet
	NegotiateFlags uint32 `json:"negotiate_flags"`
}

// Parse the SMB version and dialect; version string
// will be of the form: Major.Minor.Revision.
//
// 'Revisions' are set to 0 if not specified (e.g. 2.1 is 2.1.0)
// The following versions/dialects are known:
// SMB 1.0.0
// SMB 2.0.2
// SMB 2.1.0
// SMB 3.0.0
// SMB 3.0.2
// SMB 3.1.1
type SMBVersions struct {
	Major     uint8  `json:"major"`
	Minor     uint8  `json:"minor"`
	Revision  uint8  `json:"revision"`
	VerString string `json:"version_string"`
}

// See [MS-SMB2] Sect. 2.2.4
// These are the flags for the Capabilties field, and are use
// for determining the SMBCapabilties booleans (below).
const (
	SMB2_CAP_DFS                = 0x00000001 // Distributed Filesystem
	SMB2_CAP_LEASING            = 0x00000002 // Leasing Support
	SMB2_CAP_LARGE_MTU          = 0x00000004 // Muti-credit support
	SMB2_CAP_MULTI_CHANNEL      = 0x00000008 // Multi-channel support
	SMB2_CAP_PERSISTENT_HANDLES = 0x00000010 // Persistent handles
	SMB2_CAP_DIRECTORY_LEASING  = 0x00000020 // Directory leasing
	SMB2_CAP_ENCRYPTION         = 0x00000040 // Encryption support
)

type SMBCapabilities struct {
	DFSSupport bool `json:"smb_dfs_support"`
	Leasing    bool `json:"smb_leasing_support,omitempty"`           // Valid for >2.0.2
	LargeMTU   bool `json:"smb_multicredit_support,omitempty"`       // Valid for >2.0.2
	MultiChan  bool `json:"smb_multichan_support,omitempty"`         // Valid for >2.1
	Persist    bool `json:"smb_persistent_handle_support,omitempty"` // Valid for >2.1
	DirLeasing bool `json:"smb_directory_leasing_support,omitempty"` // Valid for >2.1
	Encryption bool `json:"smb_encryption_support,omitempty"`        // Only for 3.0, 3.0.2
}

// SMBLog logs the relevant information about the session.
type SMBLog struct {
	// SupportV1 is true if the server's protocol ID indicates support for
	// version 1.
	SupportV1 bool `json:"smbv1_support"`

	Version *SMBVersions `json:"smb_version,omitempty"`

	// If present, represent the NativeOS, NTLM, and GroupName fields of SMBv1 Session Setup Negotiation
	// An empty string for these values indicate the data was not available
	NativeOs  string `json:"native_os"`
	NTLM      string `json:"ntlm"`
	GroupName string `json:"group_name"`

	// While the NegotiationLogs and SessionSetupLog each have their own
	// Capabilties field, we are ignoring the SessionsSetupLog capability
	// when decoding, and only representing the server capabilties based
	// on what is present in the NegotiationLog capability bitmask field,
	// which is why this capability decode is presented at this level
	// in the results.
	//
	// This is based on Sect. 2.2.4 from the [MS-SMB2] document, which states:
	// "The Capabilities field specifies protocol capabilities for the server."
	Capabilities *SMBCapabilities `json:"smb_capabilities,omitempty"`

	// HasNTLM is true if the server supports the NTLM authentication method.
	HasNTLM bool `json:"has_ntlm"`

	// NegotiationLog, if present, contains the server's response to the
	// negotiation request.
	NegotiationLog *NegotiationLog `json:"negotiation_log,omitempty"`

	// SessionSetupLog, if present, contains the server's response to the
	// session setup request.
	SessionSetupLog *SessionSetupLog `json:"session_setup_log,omitempty"`
}

// LoggedSession wraps the Session struct, and holds a Log struct alongside it
// to track its progress.
type LoggedSession struct {
	Session
	Log *SMBLog
}

// zschema doesn't support uint64, so convert this into a standard 32-bit
// timestamp
func getTime(time uint64) uint32 {
	// SMB timestamps are tenths of a millisecond since 1/1/1601.
	// Between Jan 1, 1601 and Jan 1, 1970, you have 369 complete years, of
	// which 89 are leap years (1700, 1800, and 1900 were not leap years). That
	// gives you a total of 134774 days or 11644473600 seconds
	const offset uint64 = 11644473600
	return uint32(time/1e7 - offset)
}

func getHeaderLog(src *Header) HeaderLog {
	return *fillHeaderLog(src, nil)
}

func fillHeaderLog(src *Header, dest *HeaderLog) *HeaderLog {
	if dest == nil {
		dest = new(HeaderLog)
	}
	dest.ProtocolID = append(make([]byte, len(src.ProtocolID)), src.ProtocolID...)
	dest.Status = src.Status
	dest.Command = src.Command
	dest.Credits = src.Credits
	dest.Flags = src.Flags
	return dest
}

// GetSMBLog() determines the Protocol version and dialect, and optionally
// negotiates a session.
func GetSMBLog(conn net.Conn, session bool, v1 bool, debug bool) (smbLog *SMBLog, err error) {
	opt := Options{}

	s := &LoggedSession{
		Session: Session{
			IsSigningRequired: false,
			IsAuthenticated:   false,
			debug:             debug,
			securityMode:      0,
			messageID:         0,
			sessionID:         0,
			dialect:           0,
			conn:              conn,
			options:           opt,
			trees:             make(map[string]uint32),
		},
	}

	if v1 {
		err := s.LoggedNegotiateProtocolv1(session)
		if err == nil && session {
			s.LoggedSessionSetupV1()
		}
	} else {
		err = s.LoggedNegotiateProtocol(session)
	}
	return s.Log, err
}

func wstring(input []byte) string {
	u16 := make([]uint16, len(input)/2)

	for i := 0; i < len(u16); i++ {
		u16[i] = uint16(input[i*2]) | (uint16(input[i*2+1]) << 8)
	}

	return string(utf16.Decode(u16))
}

// Temporary placeholder to detect SMB v1 by sending a simple v1
// header with an invalid command; the response with be an error
// code, but with a v1 ProtocolID
// TODO: Parse the unmarshaled results.
func (ls *LoggedSession) LoggedNegotiateProtocolv1(setup bool) error {
	s := &ls.Session

	negReq := s.NewNegotiateReqV1()
	s.Debug("Sending LoggedNegotiateProtocolV1 request", nil)
	buf, err := s.send(negReq)
	if err != nil {
		s.Debug("", err)
		return err
	}

	logStruct := new(SMBLog)
	ls.Log = logStruct

	// s.send() will return error if buf size is < 4.
	// Check the for the protocol identifier here, so that we at least
	// log that this is an SMB1 server even if the full unmarshal fails.
	if string(buf[0:4]) == ProtocolSmb {
		ls.Log.SupportV1 = true
		ls.Log.Version = &SMBVersions{Major: 1,
			Minor:     0,
			Revision:  0,
			VerString: "SMB 1.0"}
	} else {
		return fmt.Errorf("Invalid v1 Protocol ID\n")
	}

	negRes := NegotiateResV1{}
	// TODO: Unmarshal struct depends on the CIF dialect response field.
	if err := encoder.Unmarshal(buf, &negRes); err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		// Not returning error here, because the NegotiationResV1 is
		// only valid for the extended NT LM 0.12 dialect of SMB1.
	}

	// TODO: Parse capabilities and return those results

	return nil
}

func (ls *LoggedSession) LoggedSessionSetupV1() (err error) {
	s := &ls.Session
	var buf []byte

	req := s.NewSessionSetupV1Req()
	s.Debug("Sending LoggedSessionSetupV1 Request", nil)
	buf, err = s.send(req)
	if err != nil {
		s.Debug("No response to SMBv1 cleartext SessionSetup", nil)
		return nil
	}

	// Safely trim down everything except the payload
	if len(buf) < SmbHeaderV1Length {
		return nil
	}
	// When using unicode, a padding byte will exist after the header
	paddingLength := int((buf[11] >> 7) & 1)
	// Skip header
	buf = buf[SmbHeaderV1Length:]
	// The byte after the header holds the number of words remaining in uint16s
	// words + 3 bytes for wordlength & bytecount + potential unicode padding
	claimedRemainingSize := int(buf[0])*2 + 3 + paddingLength
	if len(buf) < claimedRemainingSize {
		return nil
	}
	buf = buf[claimedRemainingSize:]

	var decoded string
	if paddingLength == 1 {
		// Unicode string
		decoded, err = encoder.FromSmbString(buf)
		if err != nil {
			s.Debug("Error encountered while decoding SMB string", err)
			return nil
		}
	} else {
		// ASCII string
		decoded = string(buf)
	}

	// We expect 3 null-terminated strings in this order;
	// These fields are technically all optional, but guaranteed to be in this order
	fields := strings.Split(decoded, "\000")
	if len(fields) > 0 {
		ls.Log.NativeOs = fields[0]
	}
	if len(fields) > 1 {
		ls.Log.NTLM = fields[1]
	}
	if len(fields) > 2 {
		ls.Log.GroupName = fields[2]
	}

	return nil
}

// LoggedNegotiateProtocol performs the same operations as
// Session.NegotiateProtocol() up to the point where user credentials would be
// required, and logs the server's responses.
// If setup is false, stop after reading the response to Negotiate.
// If setup is true, send a SessionSetup1 request.
//
// Note: This supports SMB2 only.
func (ls *LoggedSession) LoggedNegotiateProtocol(setup bool) error {
	s := &ls.Session
	negReq := s.NewNegotiateReq()
	s.Debug("Sending LoggedNegotiateProtocol request", nil)
	buf, err := s.send(negReq)
	if err != nil {
		s.Debug("", err)
		return err
	}

	negRes := NewNegotiateRes()
	s.Debug("Unmarshalling NegotiateProtocol response", nil)
	if err := encoder.Unmarshal(buf, &negRes); err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}
	logStruct := new(SMBLog)

	ls.Log = logStruct

	switch string(negRes.Header.ProtocolID) {
	case ProtocolSmb:
		ls.Log.SupportV1 = true
		ls.Log.Version = &SMBVersions{Major: 1,
			Minor:     0,
			Revision:  0,
			VerString: "SMB 1.0"}
	case ProtocolSmb2:
		major := uint8(0x0f & (negRes.DialectRevision >> 8))
		minor := uint8(0x0f & (negRes.DialectRevision >> 4))
		revision := uint8(0x0f & negRes.DialectRevision)
		caps := negRes.Capabilities
		ls.Log.Version = &SMBVersions{}
		// Intentional cascading fallthroughs on the dialect revision, to match
		// the description in [MS-SMB2] Sect. 2.2.4. The Capabilites flags are
		// masked based on what capabilities are valid to infer based on the
		// server version.
		switch negRes.DialectRevision {
		case 0x0202:
			caps &= 0x01
			fallthrough
		case 0x0210:
			caps &= 0x07
			fallthrough
		// Version 3.1.1 supporting fewer flags than 3.0.0 and 3.0.2 is
		// intentional, based on the chart from [MS-SMB2] Sect 2.2.4,
		// "Capabilities", which states (in reference to the  Encryption flag):
		// "This flag is valid for the SMB 3.0 and 3.0.2 dialects", explicitly
		// excluding 3.1.1
		case 0x311:
			caps &= 0x3f
			fallthrough
		case 0x300, 0x0302:
			caps &= 0x7f
			// At this point, the capabilities flags are properly masked, so we
			// can decode them for all versions.  We also node the computed
			// major/minor/revision numbers are valid, and match the explicitly
			// defined versions in [MS-SMB2].
			var verString string

			// To be pedantic, to match the MS documents in reference to SMB
			// versions, we will not include revision values of '0' in the
			// version string.  E.g., SMB 2.1 instead of SMB 2.1.0
			if revision > 0 {
				verString = fmt.Sprintf("SMB %d.%d.%d", major, minor, revision)
			} else {
				verString = fmt.Sprintf("SMB %d.%d", major, minor)
			}
			ls.Log.Version = &SMBVersions{
				Major:     major,
				Minor:     minor,
				Revision:  revision,
				VerString: verString,
			}
			ls.Log.Capabilities = &SMBCapabilities{
				DFSSupport: caps&SMB2_CAP_DFS != 0,
				Leasing:    caps&SMB2_CAP_LEASING != 0,
				LargeMTU:   caps&SMB2_CAP_LARGE_MTU != 0,
				MultiChan:  caps&SMB2_CAP_MULTI_CHANNEL != 0,
				Persist:    caps&SMB2_CAP_PERSISTENT_HANDLES != 0,
				DirLeasing: caps&SMB2_CAP_DIRECTORY_LEASING != 0,
				Encryption: caps&SMB2_CAP_ENCRYPTION != 0,
			}
		default:
		}
	}

	logStruct.NegotiationLog = &NegotiationLog{
		HeaderLog:       getHeaderLog(&negRes.Header),
		SecurityMode:    negRes.SecurityMode,
		DialectRevision: negRes.DialectRevision,
		ServerGuid:      append(make([]byte, len(negRes.ServerGuid)), negRes.ServerGuid...),
		Capabilities:    negRes.Capabilities,
		SystemTime:      getTime(negRes.SystemTime),
		ServerStartTime: getTime(negRes.ServerStartTime),
	}
	if negRes.Header.Status != StatusOk {
		return errors.New(fmt.Sprintf("NT Status Error: %d\n", negRes.Header.Status))
	}

	// Check SPNEGO security blob
	spnegoOID, err := gss.ObjectIDStrToInt(gss.SpnegoOid)
	if err != nil {
		return err
	}
	oid := negRes.SecurityBlob.OID
	if !oid.Equal(asn1.ObjectIdentifier(spnegoOID)) {
		return errors.New(fmt.Sprintf(
			"Unknown security type OID [expecting %s]: %s\n",
			gss.SpnegoOid,
			negRes.SecurityBlob.OID))
	}

	// Check for NTLMSSP support
	ntlmsspOID, err := gss.ObjectIDStrToInt(gss.NtLmSSPMechTypeOid)
	if err != nil {
		s.Debug("", err)
		return err
	}
	logStruct.NegotiationLog.AuthenticationTypes = make([]string, len(negRes.SecurityBlob.Data.MechTypes))
	logStruct.HasNTLM = false
	for i, mechType := range negRes.SecurityBlob.Data.MechTypes {
		logStruct.NegotiationLog.AuthenticationTypes[i] = mechType.String()
		if mechType.Equal(asn1.ObjectIdentifier(ntlmsspOID)) {
			logStruct.HasNTLM = true
		}
	}

	if !setup {
		return nil
	}

	s.securityMode = negRes.SecurityMode
	s.dialect = negRes.DialectRevision

	// Determine whether signing is required
	mode := uint16(s.securityMode)
	if mode&SecurityModeSigningEnabled > 0 {
		if mode&SecurityModeSigningRequired > 0 {
			s.IsSigningRequired = true
		} else {
			s.IsSigningRequired = false
		}
	} else {
		s.IsSigningRequired = false
	}

	s.Debug("Sending SessionSetup1 request", nil)
	ssreq, err := s.NewSessionSetup1Req()
	if err != nil {
		s.Debug("", err)
		return err
	}
	ssres, err := NewSessionSetup1Res()
	if err != nil {
		s.Debug("", err)
		return err
	}
	buf, err = encoder.Marshal(ssreq)
	if err != nil {
		s.Debug("", err)
		return err
	}

	buf, err = s.send(ssreq)
	if err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}

	s.Debug("Unmarshalling SessionSetup1 response", nil)
	if err := encoder.Unmarshal(buf, &ssres); err != nil {
		s.Debug("", err)
		return err
	}
	logStruct.SessionSetupLog = &SessionSetupLog{
		HeaderLog:  getHeaderLog(&ssres.Header),
		SetupFlags: ssres.Flags,
	}
	challenge := ntlmssp.NewChallenge()
	resp := ssres.SecurityBlob
	if err := encoder.Unmarshal(resp.ResponseToken, &challenge); err != nil {
		s.Debug("", err)
		return err
	}

	if ssres.Header.Status != StatusMoreProcessingRequired {
		status, _ := StatusMap[negRes.Header.Status]
		return errors.New(fmt.Sprintf("NT Status Error: %s\n", status))
	}
	logStruct.SessionSetupLog.TargetName = wstring(challenge.TargetName)
	logStruct.SessionSetupLog.NegotiateFlags = challenge.NegotiateFlags

	return nil
}

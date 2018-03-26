package smb

import (
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"unicode/utf16"

	"github.com/zmap/zgrab2/lib/smb/gss"
	"github.com/zmap/zgrab2/lib/smb/ntlmssp"
	"github.com/zmap/zgrab2/lib/smb/smb/encoder"
)

// HeaderLog contains the relevant parts of the header that is included with each packet.
type HeaderLog struct {
	// ProtocolID identifies the SMB protocol version (e.g. ProtocolSmb == "\xFFSMB")
	ProtocolID []byte `json:"protocol_id"`

	// Status is the server's status; e.g. NTSTATUS (https://msdn.microsoft.com/en-us/library/cc704588.aspx).
	Status uint32 `json:"status"`

	// Command is the command identifier.
	Command uint16 `json:"command"`

	// Credits is the number of credits granted to the client.
	Credits uint16 `json:"credits"`

	// Flags is the flags for the request (see https://msdn.microsoft.com/en-us/library/cc246529.aspx)
	Flags uint32 `json:"flags"`
}

// NegotiationLog contains the relevant parts of the negotiation response packet.
// See https://msdn.microsoft.com/en-us/library/cc246561.aspx.
type NegotiationLog struct {
	HeaderLog

	// SecurityMode is the server's security mode (e.g. signing enabled/required).
	SecurityMode uint16 `json:"security_mode"`

	// DialectRevision is the SMB2 dialect number; 0x2FF is the wildcard.
	DialectRevision uint16 `json:"dialect_revision"`

	// ServerGuid is the server's globally unique identifier.
	ServerGuid []byte `json:"server_guid"`

	// Capabilities specifies protocol capabilities for the server.
	Capabilities uint32 `json:"capabilities"`

	// SystemTime is the time (in seconds since Unix epoch) the server received the negotiation request.
	SystemTime uint32 `json:"system_time"`

	// ServerStartTime is the time (in seconds since the Unix epoch) the server started.
	ServerStartTime uint32 `json:"server_start_time"`

	// AuthenticationTypes is a list of OBJECT IDENTIFIERs (in dotted-decimal format) identifying authentication modes
	// // that the server supports.
	AuthenticationTypes []string `json:"authentication_types,omitempty"`
}

// SessionSetupLog contains the relevant parts of the first session setup response packet.
// See https://msdn.microsoft.com/en-us/library/cc246564.aspx
type SessionSetupLog struct {
	HeaderLog

	// SetupFlags is the gives additional information on the session.
	SetupFlags uint16 `json:"setup_flags"`

	// TargetName is the target name from the challenge packet
	TargetName string `json:"target_name"`

	// NegotiateFlags are the flags from the challenge packet
	NegotiateFlags uint32 `json:"negotiate_flags"`
}

// SMBLog logs the relevant information about the session.
type SMBLog struct {
	// SupportV1 is true if the server's protocol ID indicates support for version 1.
	SupportV1 bool `json:"smbv1_support"`

	// HasNTLM is true if the server supports the NTLM authentication method.
	HasNTLM bool `json:"has_ntlm"`

	// NegotiationLog, if present, contains the server's response to the negotiation request.
	NegotiationLog *NegotiationLog `json:"negotiation_log"`

	// SessionSetupLog, if present, contains the server's response to the session setup request.
	SessionSetupLog *SessionSetupLog `json:"session_setup_log"`
}

// LoggedSession wraps the Session struct, and holds a Log struct alongside it to track its progress.
type LoggedSession struct {
	Session
	Log *SMBLog
}

// zschema doesn't support uint64, so convert this into a standard 32-bit timestamp
func getTime(time uint64) uint32 {
	// SMB timestamps are tenths of a millisecond since 1/1/1601.
	// Between Jan 1, 1601 and Jan 1, 1970, you have 369 complete years, of which 89 are leap years (1700, 1800, and 1900 were not leap years). That gives you a total of 134774 days or 11644473600 seconds
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

// GetSMBLog attempts to negotiate a SMB session on the given connection.
func GetSMBLog(conn net.Conn, debug bool) (*SMBLog, error) {
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

	err := s.LoggedNegotiateProtocol(true)
	return s.Log, err
}

// GetSMBBanner sends a single negotiate packet to the server to perform a scan equivalent to the original ZGrab.
func GetSMBBanner(conn net.Conn, debug bool) (*SMBLog, error) {
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

	err := s.LoggedNegotiateProtocol(false)
	return s.Log, err
}

func wstring(input []byte) string {
	u16 := make([]uint16, len(input)/2)

	for i := 0; i < len(u16); i++ {
		u16[i] = uint16(input[i*2]) | (uint16(input[i*2+1]) << 8)
	}

	return string(utf16.Decode(u16))
}

// LoggedNegotiateProtocol performs the same operations as Session.NegotiateProtocol() up to the point where user
// credentials would be required, and logs the server's responses.
// If setup is false, stop after reading the response to Negotiate.
// If setup is true, send a SessionSetup1 request.
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
	ls.Log.SupportV1 = string(negRes.Header.ProtocolID) == ProtocolSmb
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

package smb

import (
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"github.com/zmap/zgrab2/lib/smb/gss"
	"github.com/zmap/zgrab2/lib/smb/ntlmssp"
	"github.com/zmap/zgrab2/lib/smb/smb/encoder"
	"unicode/utf16"
)

type HeaderLog struct {
	ProtocolID []byte `json:"protocol_id"`
	Status uint32 `json:"status"`
	Command uint16 `json:"command"`
	Credits uint16 `json:"credits"`
	Flags uint32 `json:"flags"`
	NextCommand uint32 `json:"next_command"`
	TreeID uint32 `json:"tree_id"`
}

type NegotiationLog struct {
	HeaderLog

	SecurityMode uint16 `json:"security_mode"`
	DialectRevision uint16 `json:"dialect_revision"`
	ServerGuid []byte `json:"server_guid"`
	Capabilities uint32 `json:"capabilities"`
	SystemTime uint64 `json:"system_time"`
	ServerStartTime uint64 `json:"server_start_time"`
	AuthenticationTypes []string `json:"authentication_types,omitempty"`
}

type SessionSetupLog struct {
	HeaderLog
	SetupFlags uint16 `json:"setup_flags"`
	TargetName string `json:"target_name"`
	NegotiateFlags uint32 `json:"negotiate_flags"`
}

type SMBLog struct {
	SupportV1 bool `json:"smbv1_support"`
	NegotiationLog *NegotiationLog `json:"negotiation_log"`
	SessionSetupLog *SessionSetupLog `json:"session_setup_log"`
}

type LoggedSession struct {
	Session
	Log *SMBLog
}

func getHeaderLog(src *Header) HeaderLog {
	return *fillHeaderLog(src, nil)
}

func fillHeaderLog(src *Header, dest *HeaderLog) *HeaderLog {
	if dest == nil {
		dest = new(HeaderLog)
	}
	dest.ProtocolID = append(make([]byte, len(src.ProtocolID)), src.ProtocolID...)
	dest.Status =  src.Status
	dest.Command =  src.Command
	dest.Credits =  src.Credits
	dest.Flags = src.Flags
	dest.NextCommand = src.NextCommand
	dest.TreeID =  src.TreeID
	return dest
}

func GetSMBLog(conn net.Conn) (*SMBLog, error) {
	opt := Options{}

	s := &LoggedSession{
		Session: Session{
			IsSigningRequired: false,
			IsAuthenticated:   false,
			debug:             true,
			securityMode:      0,
			messageID:         0,
			sessionID:         0,
			dialect:           0,
			conn:              conn,
			options:           opt,
			trees:             make(map[string]uint32),
		},
	}

	err := s.LoggedNegotiateProtocol()
	return s.Log, err
}

func wstring(input []byte) string {
	u16 := make([]uint16, len(input) / 2)

	for i := 0; i < len(u16); i++ {
		u16[i] = uint16(input[i * 2]) | (uint16(input[i * 2 + 1]) << 8)
	}

	return string(utf16.Decode(u16))
}

func (ls *LoggedSession) LoggedNegotiateProtocol() error {
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
		HeaderLog: getHeaderLog(&negRes.Header),
		SecurityMode: negRes.SecurityMode,
		DialectRevision: negRes.DialectRevision,
		ServerGuid: append(make([]byte, len(negRes.ServerGuid)), negRes.ServerGuid...),
		Capabilities: negRes.Capabilities,
		SystemTime: negRes.SystemTime,
		ServerStartTime: negRes.ServerStartTime,
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
	hasNTLMSSP := false
	for i, mechType := range negRes.SecurityBlob.Data.MechTypes {
		logStruct.NegotiationLog.AuthenticationTypes[i] = mechType.String()
		if mechType.Equal(asn1.ObjectIdentifier(ntlmsspOID)) {
			hasNTLMSSP = true
		}
	}
	if !hasNTLMSSP {
		return errors.New("Server does not support NTLMSSP")
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
		HeaderLog: getHeaderLog(&ssres.Header),
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

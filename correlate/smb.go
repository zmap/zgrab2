package correlate

import (
	"encoding/json"
	"fmt"

	"github.com/zmap/zgrab2/lib/attribution"
	smblog "github.com/zmap/zgrab2/lib/smb/smb"
)

func extractSMB(raw json.RawMessage) (*smblog.SMBLog, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var res smblog.SMBLog
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("decoding smb result: %w", err)
	}
	return &res, nil
}

// smbNTLMOSVersion returns the NTLM-derived OS version string, if any --
// requires the smb module to have been run with --setup-session so it
// negotiates far enough to receive an NTLM Challenge. This is the one
// reliable version signal SMB alone can provide.
func smbNTLMOSVersion(res *smblog.SMBLog) string {
	if res == nil || res.SessionSetupLog == nil || res.SessionSetupLog.NTLMInfo == nil {
		return ""
	}
	return res.SessionSetupLog.NTLMInfo.OSVersion
}

// smbSignalFrom grades an SMB negotiation response. SMB alone doesn't prove
// Windows -- Samba speaks the same wire protocol on Linux/BSD -- so
// standalone confidence is low unless NTLM version evidence is present.
func smbSignalFrom(res *smblog.SMBLog) protocolSignal {
	if res == nil {
		return protocolSignal{}
	}
	sig := protocolSignal{
		windowsFamilyConfidence: attribution.ConfidenceLow,
		evidence: []Evidence{{
			Source:     "smb",
			Signal:     "smb_negotiation_response",
			Confidence: attribution.ConfidenceLow,
		}},
	}
	if v := smbNTLMOSVersion(res); v != "" {
		sig.windowsFamilyConfidence = attribution.ConfidenceHigh
		sig.evidence = append(sig.evidence, Evidence{
			Source:     "smb",
			Signal:     "ntlm_os_version_observed:" + v,
			Confidence: attribution.ConfidenceHigh,
		})
	}
	return sig
}

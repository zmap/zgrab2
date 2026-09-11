package correlate

import (
	"encoding/json"
	"fmt"

	"github.com/zmap/zgrab2/lib/attribution"
	"github.com/zmap/zgrab2/modules/rdp"
)

func extractRDP(raw json.RawMessage) (*rdp.RDPResult, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var res rdp.RDPResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("decoding rdp result: %w", err)
	}
	return &res, nil
}

// rdpSignalFrom grades an RDP X.224 Connection Confirm. RDP alone doesn't
// prove Windows -- xrdp/FreeRDP exist -- so standalone confidence is low
// unless NTLM version evidence is present (real Microsoft RDP negotiating
// CredSSP/NLA, a pre-auth NTLM Negotiate/Challenge exchange with no
// credentials sent).
func rdpSignalFrom(res *rdp.RDPResult) protocolSignal {
	if res == nil {
		return protocolSignal{}
	}
	sig := protocolSignal{
		windowsFamilyConfidence: attribution.ConfidenceLow,
		evidence: []Evidence{{
			Source:     "rdp",
			Signal:     "rdp_connection_confirm",
			Confidence: attribution.ConfidenceLow,
		}},
	}
	if res.NTLM != nil && res.NTLM.OSVersion != "" {
		sig.windowsFamilyConfidence = attribution.ConfidenceHigh
		sig.evidence = append(sig.evidence, Evidence{
			Source:     "rdp",
			Signal:     "ntlm_os_version_observed:" + res.NTLM.OSVersion,
			Confidence: attribution.ConfidenceHigh,
		})
	}
	return sig
}

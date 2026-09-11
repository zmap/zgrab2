package correlate

import (
	"encoding/json"
	"fmt"

	"github.com/zmap/zgrab2/lib/attribution"
	"github.com/zmap/zgrab2/modules/msmq"
)

func extractMSMQ(raw json.RawMessage) (*msmq.Results, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var res msmq.Results
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("decoding msmq result: %w", err)
	}
	return &res, nil
}

// msmqSignalFrom turns a decoded msmq.Results into this host's Windows-family
// signal and vulnerability candidate. Genuine MS-MQQB is Windows-exclusive
// (unlike RDP/SMB, which have real non-Windows implementations), so even a
// medium-confidence (anomalous) detection is standalone Windows-family
// evidence -- see modules/msmq/assessment.go's assessConfidence for how that
// confidence was derived from the wire response.
func msmqSignalFrom(res *msmq.Results) (protocolSignal, *attribution.VulnerabilityAssessment) {
	if res == nil {
		return protocolSignal{}, nil
	}
	sig := protocolSignal{}
	switch res.Detection.Confidence {
	case attribution.ConfidenceHigh:
		sig.windowsFamilyConfidence = attribution.ConfidenceHigh
		sig.evidence = append(sig.evidence, Evidence{Source: "msmq", Signal: "spec_compliant_ms_mqqb_response", Confidence: attribution.ConfidenceHigh})
	case attribution.ConfidenceMedium:
		sig.windowsFamilyConfidence = attribution.ConfidenceMedium
		sig.evidence = append(sig.evidence, Evidence{Source: "msmq", Signal: "anomalous_ms_mqqb_response", Confidence: attribution.ConfidenceMedium})
	}
	if res.Detection.Accepted {
		sig.evidence = append(sig.evidence, Evidence{Source: "msmq", Signal: "anonymous_connection_accepted", Confidence: attribution.ConfidenceHigh})
	}
	vuln := res.VulnerabilityAssessment
	return sig, &vuln
}

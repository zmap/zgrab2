package correlate

import "github.com/zmap/zgrab2/lib/attribution"

// protocolSignal is one protocol's contribution to the host-level OS-family
// assessment: how confident that protocol's own evidence makes us that the
// target is Windows, plus the raw evidence backing it. An empty
// windowsFamilyConfidence means this protocol contributed no OS-family
// signal at all (as opposed to actively suggesting non-Windows, which no
// signal here does -- these modules only ever add positive evidence).
type protocolSignal struct {
	windowsFamilyConfidence attribution.Confidence
	evidence                []Evidence
}

// confidenceRank orders Confidence values so signals can be compared/
// maximized; unknown/empty ranks lowest.
func confidenceRank(c attribution.Confidence) int {
	switch c {
	case attribution.ConfidenceHigh:
		return 3
	case attribution.ConfidenceMedium:
		return 2
	case attribution.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

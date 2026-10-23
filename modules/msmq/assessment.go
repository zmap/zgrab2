package msmq

import "github.com/zmap/zgrab2/lib/attribution"

// assessConfidence is the single source of truth for how confident this
// module is that a response came from a genuine, spec-compliant MS-MQQB
// acceptor (as opposed to something else merely echoing/relaying bytes on
// port 1801, like the anomalous host observed in real-world scanning: zero
// ServerGuid, padding that doesn't match the mandated 0x5A pattern). High
// confidence requires the padding pattern to match -- the one thing a
// non-compliant relay is unlikely to replicate correctly, since [MS-MQQB]
// mandates it only for genuine server responses. It feeds Detection.
// Confidence, MSMQIdentification.{Confidence,Evidence}, and
// assessVulnerability, so the three never disagree with each other.
func assessConfidence(parsed *establishConnectionResponse, serverGUIDZero bool) (attribution.Confidence, []attribution.Evidence) {
	evidence := []attribution.Evidence{
		EvidenceSignatureValid,
		EvidencePacketTypeValid,
	}
	if parsed.PaddingMatchesResponse {
		evidence = append(evidence, EvidencePaddingValid)
	} else {
		evidence = append(evidence, EvidencePaddingInvalid)
	}
	if serverGUIDZero {
		evidence = append(evidence, EvidenceServerGuidZero)
	} else {
		evidence = append(evidence, EvidenceServerGuidNonzero)
	}

	if parsed.PaddingMatchesResponse {
		return attribution.ConfidenceHigh, evidence
	}
	return attribution.ConfidenceMedium, evidence
}

// buildOSEvidence returns raw OS/QS-bit facts only -- never a Family/Version
// conclusion. This is the entire reason Results.OSIdentification stays null:
// these bits describe the acceptor's self-reported OS-class/QoS-support
// flags ([MS-MQQB] 2.2.3.1, fields B and C), not a Windows version, and a
// single module must never promote them into one.
func buildOSEvidence(parsed *establishConnectionResponse) []attribution.Evidence {
	serverOSBit := EvidenceOSBitUnset
	if parsed.IsServerOS {
		serverOSBit = EvidenceOSBitSet
	}
	gqosBit := EvidenceQoSBitUnset
	if parsed.SupportsGQoS {
		gqosBit = EvidenceQoSBitSet
	}
	return []attribution.Evidence{serverOSBit, gqosBit}
}

// assessVulnerability grades exposure risk from what this single exchange
// can actually prove: whether an anonymous request was accepted (Level 1 of
// the graduated anonymous-access model -- see SecurityAssessment), and how
// confident we are the responder is genuine MS-MQQB. VulnConfirmed and
// VulnLikely are structurally unreachable here -- a single EstablishConnection
// exchange never carries version/patch evidence, so this module can never
// honestly claim more than VulnNotConfirmed: an accepted, spec-compliant
// handshake is a necessary precondition for further access, but this probe
// never attempts queue, message, or administrative access (Levels 2/3), so
// it can never confirm a vulnerability, only report that Level 1 was
// observed. Confirmed/likely/potential all require evidence beyond a single
// handshake (that's a correlation-layer concern, or a future active-probe
// module explicitly authorized to test Levels 2/3).
func assessVulnerability(accepted bool, confidence attribution.Confidence) attribution.VulnerabilityAssessment {
	switch {
	case accepted && confidence == attribution.ConfidenceHigh:
		return attribution.VulnerabilityAssessment{
			Status: attribution.VulnNotConfirmed,
			Rationale: "An anonymous MS-MQQB EstablishConnection handshake (Level 1) was accepted by a " +
				"responder that matches the mandated protocol response pattern. This probe does not " +
				"attempt queue, message, or administrative access, so unauthorized protocol/resource " +
				"access (Levels 2/3) was not established and no specific vulnerability is confirmed.",
			// The observed condition backing this status is named by its
			// finding code, not a free-text "issue class" label -- avoids
			// any reading of this as a confirmed vulnerability taxonomy.
			KnownIssueClasses: []string{"MSMQ_ANONYMOUS_HANDSHAKE"},
		}
	case accepted:
		return attribution.VulnerabilityAssessment{
			Status: attribution.VulnInsufficientEvidence,
			Rationale: "The acceptor's response deviates from the mandated MS-MQQB response pattern; " +
				"too anomalous to trust as a genuine MSMQ implementation for vulnerability assessment.",
		}
	case confidence == attribution.ConfidenceHigh:
		return attribution.VulnerabilityAssessment{
			Status: attribution.VulnUnknown,
			Rationale: "A genuine MS-MQQB listener was identified, but the anonymous handshake (Level 1) " +
				"was refused; no access-level conclusion can be drawn from a refusal alone.",
		}
	default:
		return attribution.VulnerabilityAssessment{
			Status: attribution.VulnInsufficientEvidence,
			Rationale: "The response deviates from the mandated MS-MQQB response pattern; too " +
				"anomalous to trust as a genuine MSMQ implementation.",
		}
	}
}

// anonymousHandshakeEvidence lists the evidence codes backing
// AnonymousHandshakeInfo.Detected. EvidencePaddingValid/Invalid are shared
// with assessConfidence's evidence -- the same underlying fact, one code.
func anonymousHandshakeEvidence(accepted bool, parsed *establishConnectionResponse) []attribution.Evidence {
	evidence := make([]attribution.Evidence, 0, 3)
	if accepted {
		evidence = append(evidence, EvidenceEstablishAccepted)
	} else {
		evidence = append(evidence, EvidenceEstablishRefused)
	}
	evidence = append(evidence, EvidenceResponseValid)
	if parsed.PaddingMatchesResponse {
		evidence = append(evidence, EvidencePaddingValid)
	} else {
		evidence = append(evidence, EvidencePaddingInvalid)
	}
	return evidence
}

// buildAnonymousHandshakeInfo populates Level 1 of the graduated
// anonymous-access model from this exchange's own outcome. Detected mirrors
// Accepted (a raw fact: did the acceptor let the anonymous request through),
// while Confidence mirrors assessConfidence's judgment of whether this is a
// genuine MS-MQQB responder at all.
func buildAnonymousHandshakeInfo(accepted bool, confidence attribution.Confidence, parsed *establishConnectionResponse) AnonymousHandshakeInfo {
	return AnonymousHandshakeInfo{
		Detected:   accepted,
		Confidence: confidence,
		Scope:      anonymousHandshakeScope,
		Evidence:   anonymousHandshakeEvidence(accepted, parsed),
	}
}

// buildSecurityAssessment grades all three levels of the graduated
// anonymous-access model. Levels 2/3 are always untestedAccessAssessment --
// this module performs no queue/message/credential operations, ever.
//
// Status is a 3-way value that factors in BOTH Accepted and confidence --
// security confidence must never exceed the confidence of the underlying
// protocol evidence. "confirmed" requires confidence == high (a genuine,
// spec-compliant acceptor); an accepted handshake from a lower-confidence
// (anomalous/non-compliant) responder is "observed", not "confirmed" -- the
// bit was literally set, but the responder isn't trustworthy enough to
// treat that as a confirmed finding.
func buildSecurityAssessment(accepted bool, confidence attribution.Confidence) SecurityAssessment {
	status := "not_confirmed"
	impact := "The externally reachable MSMQ endpoint did not accept the anonymous protocol handshake " +
		"in this exchange; the connection request was refused."
	switch {
	case accepted && confidence == attribution.ConfidenceHigh:
		status = "confirmed"
		impact = "The externally reachable MSMQ endpoint accepts an unauthenticated protocol handshake."
	case accepted:
		status = "observed"
		impact = "An unauthenticated protocol handshake was accepted, but the response deviates from the " +
			"mandated MS-MQQB pattern; too anomalous to confirm as genuine MSMQ behavior."
	}
	return SecurityAssessment{
		AnonymousHandshake: AnonymousHandshakeAssessment{
			Status:     status,
			Severity:   "informational",
			Confidence: confidence,
			Impact:     impact,
			Limitation: "The probe does not establish anonymous queue, message, or administrative access.",
		},
		AnonymousProtocolAccess: untestedAccessAssessment,
		AnonymousResourceAccess: untestedAccessAssessment,
	}
}

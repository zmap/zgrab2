// Package attribution provides a shared vocabulary for turning raw,
// per-protocol wire-level facts into graded identification claims (OS
// family/version, product version, vulnerability likelihood) without
// overstating certainty.
//
// The central rule this package encodes: a single protocol module observes
// facts (Evidence) about one exchange. It may grade its own confidence in
// those facts (Confidence), but it must never promote a fact into an OS
// family/version or vulnerability conclusion on its own -- that requires
// corroborating evidence from other protocols/modules, which is a
// correlation step built on top of these types, not inside any one module.
// A module that has no version field in its wire format (e.g. MSMQ's
// EstablishConnection exchange) must report VersionNotAvailablePreAuth
// rather than infer a version from a value that merely looks like one.
package attribution

// Confidence grades how certain an identification claim is.
type Confidence string

const (
	ConfidenceHigh    Confidence = "high"
	ConfidenceMedium  Confidence = "medium"
	ConfidenceLow     Confidence = "low"
	ConfidenceUnknown Confidence = "unknown"
)

// Evidence is a single factual, uninterpreted wire-level observation (e.g.
// "padding_matches_mandated_server_pattern"). Evidence is a fact, never a
// conclusion -- only a correlation step with cross-protocol context is
// allowed to turn Evidence into a Family/Version/Vulnerability conclusion.
type Evidence string

// VersionStatus describes whether/why version information is available.
type VersionStatus string

const (
	// VersionNotAvailablePreAuth means the protocol exchange performed has no
	// version field at all -- a permanent fact about the exchange, not a gap
	// that a future scan could close without authenticating or using a
	// different protocol.
	VersionNotAvailablePreAuth VersionStatus = "not_available_pre_auth"
	// VersionNotObserved means a version field could exist in this protocol
	// but wasn't captured in this particular run.
	VersionNotObserved VersionStatus = "not_observed"
	// VersionAvailable means Version/Build below are populated from real
	// protocol-native evidence.
	VersionAvailable VersionStatus = "available"
)

// VersionIdentification reports whether exact version/build information is
// available, and if not, why.
type VersionIdentification struct {
	Status  VersionStatus `json:"status"`
	Version *string       `json:"version"`
	Build   *string       `json:"build"`
}

// OSIdentification is what a single module (or, with richer evidence, a
// correlation step) can responsibly claim about the target's OS. Family/
// Version/Build must stay nil, and Confidence/FamilyConfidence must stay
// ConfidenceUnknown, unless there is genuinely sufficient protocol-native
// evidence -- a single module observing one protocol must never assert OS
// family/version on its own.
type OSIdentification struct {
	Family           *string    `json:"family"`
	FamilyConfidence Confidence `json:"family_confidence"`
	Version          *string    `json:"version"`
	Build            *string    `json:"build"`
	Confidence       Confidence `json:"confidence"`
	Evidence         []Evidence `json:"evidence,omitempty"`
}

// Detection summarizes whether the protocol was detected and how the
// exchange concluded.
type Detection struct {
	Detected   bool       `json:"detected"`
	Accepted   bool       `json:"accepted"`
	Confidence Confidence `json:"confidence"`
}

// Finding is a single security-relevant observation about a target, derived
// from protocol-level evidence. Finding carries no human-readable title or
// description -- those live in a module-local descriptions map (e.g.
// msmq.FindingDescriptions), so a UI/API presentation layer resolves ID to
// text rather than every scanned record repeating the same prose.
type Finding struct {
	ID         string     `json:"id"`
	Severity   string     `json:"severity"`
	Confidence Confidence `json:"confidence"`
}

// VulnAssessmentStatus grades how strongly evidence supports a vulnerability
// concern, without ever asserting a specific CVE applies unless the
// evidence (exact version/build) actually supports it.
type VulnAssessmentStatus string

const (
	VulnConfirmed VulnAssessmentStatus = "confirmed"
	VulnLikely    VulnAssessmentStatus = "likely"
	VulnPotential VulnAssessmentStatus = "potential"
	// VulnNotConfirmed means a security-relevant behavior was positively
	// observed (e.g. an unauthenticated protocol handshake was accepted),
	// but nothing beyond that was tested/established -- it is a graded step
	// below VulnPotential: not "maybe vulnerable," but "one necessary
	// precondition was observed and nothing further was attempted."
	VulnNotConfirmed         VulnAssessmentStatus = "not_confirmed"
	VulnUnknown              VulnAssessmentStatus = "unknown"
	VulnInsufficientEvidence VulnAssessmentStatus = "insufficient_evidence"
)

// VulnerabilityAssessment separates a graded status and its rationale from
// any specific CVE/issue-class labels, so a status can never be produced
// without an accompanying explanation of what evidence (or lack of it)
// justifies it.
type VulnerabilityAssessment struct {
	Status VulnAssessmentStatus `json:"status"`
	// Rationale explains, in plain language, what evidence (or lack of it)
	// justifies Status.
	Rationale string `json:"rationale"`
	// KnownIssueClasses lists the specific observed security conditions
	// (e.g. finding/evidence codes like "MSMQ_ANONYMOUS_HANDSHAKE") backing
	// Status -- never a free-text "issue class" label, and never a CVE ID.
	// The JSON key is "observed_security_conditions", deliberately not
	// "known_issue_classes": pairing an open-ended taxonomy label with a
	// Status like "not_confirmed" risks a downstream consumer reading the
	// pairing as a confirmed vulnerability classification. The Go field
	// name is kept for backward compatibility with existing Go callers
	// (e.g. correlate/correlate.go's combineVulnerability); only the wire
	// representation changed.
	KnownIssueClasses []string `json:"observed_security_conditions,omitempty"`
}

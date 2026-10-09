package msmq

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/zmap/zgrab2/lib/attribution"
)

// msmqProductName is the constant Identification.Product value in compact
// output -- this module only ever speaks MS-MQQB, so there is nothing to
// vary per host.
const msmqProductName = "Microsoft Message Queuing"

// rawPreviewBytes caps how many leading bytes of the raw response are
// included as RawEvidenceInfo.Preview -- a strict, fixed maximum, never a
// truncation of the canonical raw evidence itself (which is represented by
// SHA256/Length, not by this preview).
const rawPreviewBytes = 32

// RawEvidenceInfo reports whether/how the raw protocol response is
// available, without requiring every record to carry the full inline blob.
// The canonical raw evidence is SHA256+Length; Preview is a small, strictly
// bounded, optional convenience slice, never a truncated substitute for it.
//
// Available=false is the ONLY state in which Inline/SHA256/Length/Preview
// are meaningful to ask about at all -- MarshalJSON below enforces this,
// producing exactly:
//   - unavailable:        {"available": false}
//   - available, inline:  {"available": true, "inline": true, "sha256": "...", "length": ...}
//   - available, external:{"available": true, "inline": false, "sha256": "...", "length": ...}
//
// never the contradictory {"available": false, "inline": true} debug mode
// used to produce.
type RawEvidenceInfo struct {
	Available bool
	SHA256    string
	Length    int
	// Inline is true when the full raw bytes are also present elsewhere in
	// the same record (debug mode's Raw field); false when the bytes must
	// be fetched out-of-band by SHA256 (standard mode).
	Inline bool
	// Preview is the hex-encoded first rawPreviewBytes bytes of the
	// response, when available -- a bounded convenience sample, not a
	// truncated version of the canonical evidence above.
	Preview string
}

// rawEvidenceWire is RawEvidenceInfo's JSON shape. Inline is a *bool (not a
// plain bool) so it can be omitted entirely when Available is false, while
// still rendering explicit "inline": false when Available is true but the
// bytes live externally -- a plain bool+omitempty can't distinguish
// "absent" from "false".
type rawEvidenceWire struct {
	Available bool   `json:"available"`
	Inline    *bool  `json:"inline,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Length    int    `json:"length,omitempty"`
	Preview   string `json:"raw_preview,omitempty"`
}

// MarshalJSON enforces that Inline/SHA256/Length/Preview only ever appear
// when Available is true -- see the type doc for the exact three shapes
// this produces.
func (r RawEvidenceInfo) MarshalJSON() ([]byte, error) {
	if !r.Available {
		return json.Marshal(rawEvidenceWire{Available: false})
	}
	inline := r.Inline
	return json.Marshal(rawEvidenceWire{
		Available: true,
		Inline:    &inline,
		SHA256:    r.SHA256,
		Length:    r.Length,
		Preview:   r.Preview,
	})
}

// rawEvidence builds a RawEvidenceInfo from the hex-encoded raw response
// (empty if --verbose wasn't set, in which case Available is false).
func rawEvidence(rawHex string, inline bool) RawEvidenceInfo {
	if rawHex == "" {
		return RawEvidenceInfo{Available: false}
	}
	raw, err := hex.DecodeString(rawHex)
	if err != nil {
		return RawEvidenceInfo{Available: false}
	}
	sum := sha256.Sum256(raw)
	info := RawEvidenceInfo{
		Available: true,
		SHA256:    hex.EncodeToString(sum[:]),
		Length:    len(raw),
		Inline:    inline,
	}
	if n := min(len(raw), rawPreviewBytes); n > 0 {
		info.Preview = hex.EncodeToString(raw[:n])
	}
	return info
}

// fingerprintSchemaVersion namespaces fingerprintCanonicalString's format.
// Bump this (msmq-fingerprint-v2, ...) if the set/meaning of fields in the
// canonical string ever changes, so old and new fingerprint IDs are never
// silently conflated.
const fingerprintSchemaVersion = "msmq-fingerprint-v1"

// fingerprintCanonicalString builds the explicitly versioned, delimited
// input fingerprintID hashes. Only STABLE fingerprint characteristics go in
// -- deliberately excluding the actual server_guid/client_guid values, IP,
// and time_stamp, which are genuinely per-host or always-constant for this
// module's fixed probe. client_guid_zero/server_guid_zero (booleans, not
// the GUID values themselves) are protocol-compliance characteristics, not
// per-host identity, so they belong here.
func fingerprintCanonicalString(r *Results) string {
	return fmt.Sprintf(
		"%s|os_field=%d|session_mode=%t|padding_valid=%t|client_guid_zero=%t|server_guid_zero=%t",
		fingerprintSchemaVersion,
		r.Fingerprint.OperatingSystemRaw,
		r.Fingerprint.SessionMode,
		r.Fingerprint.PaddingMatchesServerPattern,
		r.Fingerprint.ClientGuidZero,
		r.Fingerprint.ServerGuidZero,
	)
}

// fingerprintID is a deterministic content-hash of fingerprintCanonicalString.
// Two hosts with identical characteristics get the identical ID with zero
// runtime state: no registry, no cross-goroutine coordination, independently
// recomputable by any downstream consumer holding the same fields.
func fingerprintID(r *Results) string {
	sum := sha256.Sum256([]byte(fingerprintCanonicalString(r)))
	return "msmq-fp-" + hex.EncodeToString(sum[:])[:12]
}

// StandardFinding is a finding without its human-readable title -- resolve
// ID against FindingDescriptions for text.
type StandardFinding struct {
	ID         string                 `json:"id"`
	Severity   string                 `json:"severity"`
	Confidence attribution.Confidence `json:"confidence"`
}

// StandardVulnerability is a code-only vulnerability view -- no free-text
// rationale (debug mode's attribution.VulnerabilityAssessment.Rationale is
// left untouched there since the correlate tool depends on it; standard
// mode uses this separate, leaner type instead of that shared one).
type StandardVulnerability struct {
	Status attribution.VulnAssessmentStatus `json:"status"`
	// ObservedSecurityConditions names the specific finding/evidence codes
	// backing Status (e.g. "MSMQ_ANONYMOUS_HANDSHAKE") -- never a free-text
	// "issue class" label, to avoid a downstream consumer reading this as
	// a confirmed vulnerability classification when Status is not_confirmed.
	ObservedSecurityConditions []string `json:"observed_security_conditions,omitempty"`
}

// StandardResults is the full structured API representation: every semantic
// field debug mode has, minus the duplication debug mode carries for
// backward compatibility (no top-level Accepted/OperatingSystem/
// IsSessionMode/PaddingMatchesServerPattern -- those live in Detection/
// Fingerprint only), minus embedded prose (findings/vulnerability carry
// codes, not titles/rationale), and with the raw response represented by
// hash+metadata rather than inline bytes.
type StandardResults struct {
	Protocol      string `json:"protocol"`
	FingerprintID string `json:"fingerprint_id"`

	Detection  attribution.Detection `json:"detection"`
	ClientGuid string                `json:"client_guid,omitempty"`
	ServerGuid string                `json:"server_guid,omitempty"`
	TimeStamp  uint32                `json:"time_stamp"`

	Fingerprint FingerprintInfo `json:"fingerprint"`

	OSIdentification      attribution.OSIdentification      `json:"os_identification"`
	MSMQIdentification    MSMQIdentification                `json:"msmq_identification"`
	VersionIdentification attribution.VersionIdentification `json:"version_identification"`

	Security           SecurityInfo       `json:"security"`
	SecurityAssessment SecurityAssessment `json:"security_assessment"`
	SecurityPosture    SecurityPosture    `json:"security_posture"`

	Vulnerability StandardVulnerability `json:"vulnerability_assessment"`

	Findings []StandardFinding `json:"findings,omitempty"`

	RawEvidence RawEvidenceInfo `json:"raw_evidence"`
}

// newStandardResults derives a StandardResults from an already fully
// computed Results -- pure representation change, no new computation.
func newStandardResults(r *Results) *StandardResults {
	findings := make([]StandardFinding, len(r.Findings))
	for i, f := range r.Findings {
		findings[i] = StandardFinding{ID: f.ID, Severity: f.Severity, Confidence: f.Confidence}
	}
	rawEv := r.RawEvidence
	rawEv.Inline = false // standard mode never carries the bytes inline

	return &StandardResults{
		Protocol:      r.Protocol,
		FingerprintID: fingerprintID(r),

		Detection:  r.Detection,
		ClientGuid: r.ClientGuid,
		ServerGuid: r.ServerGuid,
		TimeStamp:  r.TimeStamp,

		Fingerprint: r.Fingerprint,

		OSIdentification:      r.OSIdentification,
		MSMQIdentification:    r.MSMQIdentification,
		VersionIdentification: r.VersionIdentification,

		Security:           r.Security,
		SecurityAssessment: r.SecurityAssessment,
		SecurityPosture:    r.SecurityPosture,

		Vulnerability: StandardVulnerability{
			Status:                     r.VulnerabilityAssessment.Status,
			ObservedSecurityConditions: r.VulnerabilityAssessment.KnownIssueClasses,
		},

		Findings: findings,

		RawEvidence: rawEv,
	}
}

// CompactResults is the default enterprise-production representation:
// target <=1KB/asset. Every field here is load-bearing per the user's
// explicit "must still retain" list -- nothing here is discretionary
// polish.
type CompactResults struct {
	Service struct {
		Protocol   string                 `json:"protocol"`
		Status     string                 `json:"status"` // always "open": Scan() only returns a result on success
		Confidence attribution.Confidence `json:"confidence"`
	} `json:"service"`

	Fingerprint struct {
		FingerprintID string `json:"fingerprint_id"`
		OSField       uint16 `json:"os_field"`
		OSFieldHex    string `json:"os_field_hex"`
		ServerGuid    string `json:"server_guid,omitempty"`
		SessionMode   bool   `json:"session_mode"`
		PaddingValid  bool   `json:"padding_valid"`
	} `json:"fingerprint"`

	Identification struct {
		Product    string                 `json:"product"`
		OSFamily   *string                `json:"os_family"`
		OSVersion  *string                `json:"os_version"`
		Build      *string                `json:"build"`
		Confidence attribution.Confidence `json:"confidence"`
	} `json:"identification"`

	Security struct {
		AnonymousHandshake struct {
			Status     string                 `json:"status"`
			Confidence attribution.Confidence `json:"confidence"`
		} `json:"anonymous_handshake"`
		AnonymousProtocolAccess string `json:"anonymous_protocol_access"`
		AnonymousResourceAccess string `json:"anonymous_resource_access"`
	} `json:"security"`

	Assessment struct {
		Vulnerability attribution.VulnAssessmentStatus `json:"vulnerability"`
	} `json:"assessment"`

	Findings []string `json:"findings,omitempty"`

	Evidence struct {
		Codes        []attribution.Evidence `json:"codes,omitempty"`
		RawAvailable bool                   `json:"raw_available"`
		RawSHA256    string                 `json:"raw_sha256,omitempty"`
		// CaptureSize is the raw response length in bytes, when available --
		// never the bytes themselves. Named to match the byte count of what
		// RawSHA256 was computed over, distinct from RawEvidenceInfo.Length
		// (debug/standard's field name for the same concept).
		CaptureSize int `json:"capture_size,omitempty"`
	} `json:"evidence"`
}

// newCompactResults derives a CompactResults from an already fully computed
// Results -- pure representation change, no new computation. Deliberately
// omitted vs. debug: client_guid/time_stamp (always zero/constant for this
// module's fixed anonymous probe -- no signal), free-text rationale/titles
// (resolve IDs against FindingDescriptions/EvidenceDescriptions instead),
// inline raw bytes (hash only).
func newCompactResults(r *Results) *CompactResults {
	c := &CompactResults{}

	c.Service.Protocol = "msmq"
	c.Service.Status = "open"
	c.Service.Confidence = r.Detection.Confidence

	c.Fingerprint.FingerprintID = fingerprintID(r)
	c.Fingerprint.OSField = r.Fingerprint.OperatingSystemRaw
	c.Fingerprint.OSFieldHex = r.Fingerprint.OperatingSystemHex
	c.Fingerprint.ServerGuid = r.ServerGuid
	c.Fingerprint.SessionMode = r.Fingerprint.SessionMode
	c.Fingerprint.PaddingValid = r.Fingerprint.PaddingMatchesServerPattern

	c.Identification.Product = msmqProductName
	c.Identification.OSFamily = r.OSIdentification.Family
	c.Identification.OSVersion = r.OSIdentification.Version
	c.Identification.Build = r.OSIdentification.Build
	c.Identification.Confidence = r.OSIdentification.Confidence

	c.Security.AnonymousHandshake.Status = r.SecurityAssessment.AnonymousHandshake.Status
	c.Security.AnonymousHandshake.Confidence = r.SecurityAssessment.AnonymousHandshake.Confidence
	c.Security.AnonymousProtocolAccess = r.SecurityAssessment.AnonymousProtocolAccess.Status
	c.Security.AnonymousResourceAccess = r.SecurityAssessment.AnonymousResourceAccess.Status

	c.Assessment.Vulnerability = r.VulnerabilityAssessment.Status

	for _, f := range r.Findings {
		c.Findings = append(c.Findings, f.ID)
	}

	codes := make([]attribution.Evidence, 0, len(r.MSMQIdentification.Evidence)+len(r.Security.AnonymousHandshake.Evidence))
	codes = append(codes, r.MSMQIdentification.Evidence...)
	codes = append(codes, r.Security.AnonymousHandshake.Evidence...)
	c.Evidence.Codes = dedupeEvidence(codes)
	c.Evidence.RawAvailable = r.RawEvidence.Available
	c.Evidence.RawSHA256 = r.RawEvidence.SHA256
	c.Evidence.CaptureSize = r.RawEvidence.Length

	return c
}

// dedupeEvidence removes duplicate codes while preserving first-seen order
// (e.g. EvidencePaddingValid is shared by both MSMQIdentification.Evidence
// and Security.AnonymousHandshake.Evidence today).
func dedupeEvidence(codes []attribution.Evidence) []attribution.Evidence {
	seen := make(map[attribution.Evidence]bool, len(codes))
	out := make([]attribution.Evidence, 0, len(codes))
	for _, c := range codes {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

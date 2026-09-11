package msmq

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/attribution"
)

func TestFingerprintIDDeterminism(t *testing.T) {
	base := &Results{Fingerprint: FingerprintInfo{OperatingSystemRaw: 16, SessionMode: false, PaddingMatchesServerPattern: true}}
	same := &Results{Fingerprint: FingerprintInfo{OperatingSystemRaw: 16, SessionMode: false, PaddingMatchesServerPattern: true}}
	differentOS := &Results{Fingerprint: FingerprintInfo{OperatingSystemRaw: 528, SessionMode: false, PaddingMatchesServerPattern: true}}
	differentSession := &Results{Fingerprint: FingerprintInfo{OperatingSystemRaw: 16, SessionMode: true, PaddingMatchesServerPattern: true}}
	differentPadding := &Results{Fingerprint: FingerprintInfo{OperatingSystemRaw: 16, SessionMode: false, PaddingMatchesServerPattern: false}}

	if fingerprintID(base) != fingerprintID(same) {
		t.Error("identical fingerprint fields produced different fingerprint IDs")
	}
	for name, other := range map[string]*Results{"os": differentOS, "session_mode": differentSession, "padding": differentPadding} {
		if fingerprintID(base) == fingerprintID(other) {
			t.Errorf("differing %s produced the same fingerprint ID as base", name)
		}
	}

	// server_guid must NOT affect the fingerprint ID -- it's genuinely
	// per-host, not a "fingerprint" characteristic to dedupe by.
	withGUIDA := &Results{ServerGuid: "aaaaaaaa-0000-0000-0000-000000000000", Fingerprint: FingerprintInfo{OperatingSystemRaw: 16, PaddingMatchesServerPattern: true}}
	withGUIDB := &Results{ServerGuid: "bbbbbbbb-0000-0000-0000-000000000000", Fingerprint: FingerprintInfo{OperatingSystemRaw: 16, PaddingMatchesServerPattern: true}}
	if fingerprintID(withGUIDA) != fingerprintID(withGUIDB) {
		t.Error("differing ServerGuid alone changed the fingerprint ID, but ServerGuid must be excluded from it")
	}
}

// TestFingerprintCanonicalStringVersioned checks the exact, explicitly
// versioned canonical string format fingerprintID hashes, and confirms
// client_guid_zero/server_guid_zero (protocol-compliance booleans, not the
// GUID values themselves) participate in the hash, while excludes remain
// excluded (server_guid VALUE, IP, time_stamp).
func TestFingerprintCanonicalStringVersioned(t *testing.T) {
	r := &Results{
		ServerGuid: "413383a6-4642-4b06-a5be-d2227ac718af", // must NOT affect the canonical string
		TimeStamp:  12345,                                  // must NOT affect the canonical string
		Fingerprint: FingerprintInfo{
			OperatingSystemRaw:          16,
			SessionMode:                 false,
			PaddingMatchesServerPattern: true,
			ClientGuidZero:              true,
			ServerGuidZero:              false,
		},
	}
	want := "msmq-fingerprint-v1|os_field=16|session_mode=false|padding_valid=true|client_guid_zero=true|server_guid_zero=false"
	if got := fingerprintCanonicalString(r); got != want {
		t.Errorf("fingerprintCanonicalString = %q, want %q", got, want)
	}

	// client_guid_zero/server_guid_zero must change the ID -- they didn't
	// before this canonicalization, and the user explicitly required them.
	flippedServerGUIDZero := *r
	flippedServerGUIDZero.Fingerprint.ServerGuidZero = true
	if fingerprintID(r) == fingerprintID(&flippedServerGUIDZero) {
		t.Error("differing server_guid_zero produced the same fingerprint ID")
	}
	flippedClientGUIDZero := *r
	flippedClientGUIDZero.Fingerprint.ClientGuidZero = false
	if fingerprintID(r) == fingerprintID(&flippedClientGUIDZero) {
		t.Error("differing client_guid_zero produced the same fingerprint ID")
	}

	// Actual ServerGuid VALUE and TimeStamp must still be excluded.
	differentGUIDValue := *r
	differentGUIDValue.ServerGuid = "00000000-0000-0000-0000-000000000000"
	differentGUIDValue.TimeStamp = 999
	if fingerprintID(r) != fingerprintID(&differentGUIDValue) {
		t.Error("differing ServerGuid/TimeStamp values changed the fingerprint ID, but those are per-host and must be excluded")
	}
}

func TestRawEvidence(t *testing.T) {
	notCaptured := rawEvidence("", true)
	if notCaptured.Available {
		t.Error("Available = true for empty raw hex, want false")
	}

	hexBytes := "1052"
	got := rawEvidence(hexBytes, true)
	if !got.Available {
		t.Error("Available = false, want true")
	}
	if got.Length != 2 {
		t.Errorf("Length = %d, want 2", got.Length)
	}
	if got.SHA256 == "" {
		t.Error("SHA256 is empty, want a hash")
	}
	if !got.Inline {
		t.Error("Inline = false, want true (as passed)")
	}
	if got.Preview != hexBytes {
		t.Errorf("Preview = %q, want %q (shorter than the preview cap)", got.Preview, hexBytes)
	}
}

// TestRawEvidenceJSONShapes is the direct regression test for the
// contradictory {"available": false, "inline": true} shape debug mode used
// to produce: asserts the exact three JSON shapes RawEvidenceInfo must
// render.
func TestRawEvidenceJSONShapes(t *testing.T) {
	cases := []struct {
		name     string
		info     RawEvidenceInfo
		wantJSON string
	}{
		{"unavailable", rawEvidence("", true), `{"available":false}`},
		{
			"available inline",
			rawEvidence("1052ff00", true),
			`{"available":true,"inline":true,"sha256":"32c395afb26602893e151e6e559042157644e1a89e09059264089f0196b0ec13","length":4,"raw_preview":"1052ff00"}`,
		},
		{
			"available external",
			rawEvidence("1052ff00", false),
			`{"available":true,"inline":false,"sha256":"32c395afb26602893e151e6e559042157644e1a89e09059264089f0196b0ec13","length":4,"raw_preview":"1052ff00"}`,
		},
	}
	for _, c := range cases {
		raw, err := json.Marshal(c.info)
		if err != nil {
			t.Fatalf("%s: json.Marshal: %v", c.name, err)
		}
		if string(raw) != c.wantJSON {
			t.Errorf("%s: got %s, want %s", c.name, raw, c.wantJSON)
		}
		// The specific contradiction this test guards against: unavailable
		// must never carry an "inline" key of any value.
		if !c.info.Available && bytes.Contains(raw, []byte(`"inline"`)) {
			t.Errorf("%s: unavailable RawEvidenceInfo rendered an \"inline\" key: %s", c.name, raw)
		}
	}
}

func compliantFixture() *Results {
	var clientGUID [16]byte
	pkt := buildResponse(clientGUID, compliantServerGUID, false, responsePaddingByte, 16)
	parsed, err := parseEstablishConnection(pkt)
	if err != nil {
		panic(err)
	}
	accepted := !parsed.Refused
	clientGUIDZero := parsed.ClientGUID == [16]byte{}
	serverGUIDZero := parsed.ServerGUID == [16]byte{}
	confidence, msmqEvidence := assessConfidence(parsed, serverGUIDZero)
	anonymousHandshake := buildAnonymousHandshakeInfo(accepted, confidence, parsed)
	securityAssessment := buildSecurityAssessment(accepted, confidence)

	r := &Results{
		Protocol:                    "MSMQ",
		Detection:                   attribution.Detection{Detected: true, Accepted: accepted, Confidence: confidence},
		Accepted:                    accepted,
		ClientGuid:                  formatGUID(parsed.ClientGUID),
		ServerGuid:                  formatGUID(parsed.ServerGUID),
		TimeStamp:                   parsed.TimeStamp,
		OperatingSystem:             parsed.OperatingSystem,
		IsSessionMode:               parsed.OperatingSystem&ecOSFlagSE != 0,
		PaddingMatchesServerPattern: parsed.PaddingMatchesResponse,
		Security: SecurityInfo{
			AuthenticationObserved: false,
			EncryptionObserved:     false,
			AnonymousHandshake:     anonymousHandshake,
		},
		Fingerprint: FingerprintInfo{
			OperatingSystem:             parsed.OperatingSystem,
			OperatingSystemRaw:          parsed.OperatingSystem,
			OperatingSystemHex:          "0x0010",
			TimeStamp:                   parsed.TimeStamp,
			SessionMode:                 parsed.OperatingSystem&ecOSFlagSE != 0,
			PaddingMatchesServerPattern: parsed.PaddingMatchesResponse,
			ClientGuidZero:              clientGUIDZero,
			ServerGuidZero:              serverGUIDZero,
			AcceptorIsServerOS:          parsed.IsServerOS,
			AcceptorSupportsGQoS:        parsed.SupportsGQoS,
		},
		OSIdentification: attribution.OSIdentification{
			FamilyConfidence: attribution.ConfidenceUnknown,
			Confidence:       attribution.ConfidenceUnknown,
			Evidence:         buildOSEvidence(parsed),
		},
		MSMQIdentification: MSMQIdentification{
			Confidence: confidence,
			Evidence:   msmqEvidence,
		},
		VersionIdentification:   attribution.VersionIdentification{Status: attribution.VersionNotAvailablePreAuth},
		VulnerabilityAssessment: assessVulnerability(accepted, confidence),
		SecurityAssessment:      securityAssessment,
		SecurityPosture: SecurityPosture{
			AnonymousHandshake:      securityAssessment.AnonymousHandshake.Status,
			AnonymousProtocolAccess: securityAssessment.AnonymousProtocolAccess.Status,
			AnonymousResourceAccess: securityAssessment.AnonymousResourceAccess.Status,
		},
		Findings: []attribution.Finding{{ID: "MSMQ_EXPOSED", Severity: "medium", Confidence: attribution.ConfidenceHigh}},
	}
	if accepted {
		r.Findings = append(r.Findings, attribution.Finding{ID: "MSMQ_ANONYMOUS_HANDSHAKE", Severity: "informational", Confidence: confidence})
	}
	r.RawEvidence = rawEvidence(r.Raw, true)
	return r
}

func TestNewCompactResultsDerivation(t *testing.T) {
	r := compliantFixture()
	c := newCompactResults(r)

	if c.Service.Protocol != "msmq" || c.Service.Status != "open" {
		t.Errorf("Service = %+v, want protocol=msmq status=open", c.Service)
	}
	if c.Service.Confidence != r.Detection.Confidence {
		t.Errorf("Service.Confidence = %s, want %s", c.Service.Confidence, r.Detection.Confidence)
	}
	if c.Fingerprint.FingerprintID != fingerprintID(r) {
		t.Errorf("Fingerprint.FingerprintID = %q, want %q", c.Fingerprint.FingerprintID, fingerprintID(r))
	}
	if c.Fingerprint.ServerGuid != r.ServerGuid {
		t.Errorf("Fingerprint.ServerGuid = %q, want %q (must not sacrifice per-host values)", c.Fingerprint.ServerGuid, r.ServerGuid)
	}
	if c.Identification.Product != msmqProductName {
		t.Errorf("Identification.Product = %q, want %q", c.Identification.Product, msmqProductName)
	}
	if c.Identification.OSFamily != nil {
		t.Error("Identification.OSFamily != nil -- a single module must never assert OS family")
	}
	if c.Security.AnonymousHandshake.Status != r.SecurityAssessment.AnonymousHandshake.Status {
		t.Errorf("Security.AnonymousHandshake.Status = %q, want %q", c.Security.AnonymousHandshake.Status, r.SecurityAssessment.AnonymousHandshake.Status)
	}
	if c.Security.AnonymousProtocolAccess != "not_tested" || c.Security.AnonymousResourceAccess != "not_tested" {
		t.Errorf("Security levels 2/3 = %q/%q, want not_tested/not_tested", c.Security.AnonymousProtocolAccess, c.Security.AnonymousResourceAccess)
	}
	if c.Assessment.Vulnerability != r.VulnerabilityAssessment.Status {
		t.Errorf("Assessment.Vulnerability = %s, want %s", c.Assessment.Vulnerability, r.VulnerabilityAssessment.Status)
	}
	if len(c.Findings) != len(r.Findings) {
		t.Errorf("Findings = %v, want %d bare IDs", c.Findings, len(r.Findings))
	}
	for _, id := range c.Findings {
		if _, ok := FindingDescriptions[id]; !ok {
			t.Errorf("finding ID %q has no entry in FindingDescriptions", id)
		}
	}
	if !c.Evidence.RawAvailable && r.RawEvidence.Available {
		t.Error("Evidence.RawAvailable mismatch")
	}

	// A separate case with a captured raw response: compact must expose
	// capture_size (byte count) alongside the hash, without ever including
	// the raw bytes themselves.
	withRaw := compliantFixture()
	withRaw.Raw = "1052ff00"
	withRaw.RawEvidence = rawEvidence(withRaw.Raw, true)
	cWithRaw := newCompactResults(withRaw)
	if cWithRaw.Evidence.CaptureSize != 4 {
		t.Errorf("Evidence.CaptureSize = %d, want 4", cWithRaw.Evidence.CaptureSize)
	}
	if cWithRaw.Evidence.RawSHA256 == "" {
		t.Error("Evidence.RawSHA256 is empty, want a hash")
	}
	rawJSON, _ := json.Marshal(cWithRaw)
	if bytes.Contains(rawJSON, []byte("1052ff00")) {
		t.Error("compact output contains the raw bytes inline -- must only expose hash/size/availability")
	}

	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if len(raw) > 1024 {
		t.Errorf("compact JSON size = %d bytes, want <= 1024 for a representative compliant host", len(raw))
	}
}

func TestNewStandardResultsDerivation(t *testing.T) {
	r := compliantFixture()
	s := newStandardResults(r)

	if s.Protocol != r.Protocol {
		t.Errorf("Protocol = %q, want %q", s.Protocol, r.Protocol)
	}
	if s.FingerprintID != fingerprintID(r) {
		t.Errorf("FingerprintID = %q, want %q", s.FingerprintID, fingerprintID(r))
	}
	if s.Detection != r.Detection {
		t.Errorf("Detection = %+v, want %+v", s.Detection, r.Detection)
	}
	if s.Vulnerability.Status != r.VulnerabilityAssessment.Status {
		t.Errorf("Vulnerability.Status = %s, want %s", s.Vulnerability.Status, r.VulnerabilityAssessment.Status)
	}
	if len(s.Findings) != len(r.Findings) {
		t.Fatalf("Findings length = %d, want %d", len(s.Findings), len(r.Findings))
	}
	for i, f := range s.Findings {
		if f.ID != r.Findings[i].ID || f.Severity != r.Findings[i].Severity || f.Confidence != r.Findings[i].Confidence {
			t.Errorf("Findings[%d] = %+v, want id/severity/confidence to match %+v", i, f, r.Findings[i])
		}
	}
	if s.RawEvidence.Inline {
		t.Error("RawEvidence.Inline = true, want false in standard mode")
	}
	if len(s.Vulnerability.ObservedSecurityConditions) != len(r.VulnerabilityAssessment.KnownIssueClasses) {
		t.Errorf("Vulnerability.ObservedSecurityConditions = %v, want %v", s.Vulnerability.ObservedSecurityConditions, r.VulnerabilityAssessment.KnownIssueClasses)
	}

	// Standard must not carry the top-level duplicate fields debug keeps
	// for backward compatibility.
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	for _, key := range []string{"accepted", "operating_system", "is_session_mode", "padding_matches_server_pattern"} {
		if _, ok := m[key]; ok {
			t.Errorf("standard output has top-level key %q, which duplicates a value already inside detection/fingerprint", key)
		}
	}

	// The ambiguous "known_issue_classes" key must never appear anywhere in
	// standard output; "observed_security_conditions" must appear with a
	// finding/evidence code (not a free-text issue-class label) for this
	// accepted-and-compliant fixture.
	if bytes.Contains(raw, []byte("known_issue_classes")) {
		t.Error("standard output contains the retired key \"known_issue_classes\"")
	}
	vuln, ok := m["vulnerability_assessment"].(map[string]any)
	if !ok {
		t.Fatalf("vulnerability_assessment is not an object: %#v", m["vulnerability_assessment"])
	}
	conditions, ok := vuln["observed_security_conditions"].([]any)
	if !ok || len(conditions) == 0 {
		t.Fatalf("vulnerability_assessment.observed_security_conditions = %#v, want a non-empty array", vuln["observed_security_conditions"])
	}
	if conditions[0] != "MSMQ_ANONYMOUS_HANDSHAKE" {
		t.Errorf("observed_security_conditions[0] = %v, want the finding code MSMQ_ANONYMOUS_HANDSHAKE, not an issue-class label", conditions[0])
	}
}

// TestScanOutputModeSelection confirms Scan() returns the right Go type for
// each --output-mode value, with detection logic (accepted, confidence,
// findings) unaffected by the mode.
func TestScanOutputModeSelection(t *testing.T) {
	for _, mode := range []string{"debug", "standard", "compact", ""} {
		var clientGUID [16]byte
		pkt := buildResponse(clientGUID, compliantServerGUID, false, responsePaddingByte, 16)
		target := startFakeAcceptor(t, pkt)

		m := NewModule()
		s := m.NewScanner()
		flags := m.NewFlags().(*Flags)
		if mode != "" {
			flags.OutputMode = mode
		}
		if err := s.Init(flags); err != nil {
			t.Fatalf("mode=%q: Init: %v", mode, err)
		}
		scanner := s.(*Scanner)
		dialerGroup, err := scanner.GetDialerGroupConfig().GetDefaultDialerGroupFromConfig()
		if err != nil {
			t.Fatalf("mode=%q: GetDefaultDialerGroupFromConfig: %v", mode, err)
		}
		status, raw, err := scanner.Scan(context.Background(), dialerGroup, target)
		if status != zgrab2.SCAN_SUCCESS {
			t.Fatalf("mode=%q: status = %s, err = %v", mode, status, err)
		}

		switch mode {
		case "standard":
			if _, ok := raw.(*StandardResults); !ok {
				t.Errorf("mode=%q: Scan returned %T, want *StandardResults", mode, raw)
			}
		case "compact":
			if _, ok := raw.(*CompactResults); !ok {
				t.Errorf("mode=%q: Scan returned %T, want *CompactResults", mode, raw)
			}
		default: // "debug" or unset (defaults to debug)
			if _, ok := raw.(*Results); !ok {
				t.Errorf("mode=%q: Scan returned %T, want *Results", mode, raw)
			}
		}
	}
}

func TestFlagsValidateOutputMode(t *testing.T) {
	for _, mode := range []string{"compact", "standard", "debug"} {
		if err := (Flags{OutputMode: mode}).Validate(nil); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", mode, err)
		}
	}
	if err := (Flags{OutputMode: "verbose"}).Validate(nil); err == nil {
		t.Error("Validate(\"verbose\") = nil, want an error for an invalid mode")
	}
}

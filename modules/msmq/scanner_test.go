package msmq

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"testing"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/attribution"
)

// osFieldOffset is the byte offset of EstablishConnectionHeader.OperatingSystem
// within a full EstablishConnection packet: BaseHeader + InternalHeader +
// ClientGuid + ServerGuid + TimeStamp.
const osFieldOffset = baseHeaderLen + internalHeaderLen + 16 + 16 + 4

// setOperatingSystem overwrites the OperatingSystem field of a packet built
// by makeEstablishConnectionResponse (which always leaves it zeroed), so
// tests can exercise specific raw values (e.g. 4224, the value named
// explicitly in the user's regression request).
func setOperatingSystem(pkt []byte, raw uint16) {
	binary.LittleEndian.PutUint16(pkt[osFieldOffset:osFieldOffset+2], raw)
}

// startFakeAcceptor listens on an OS-assigned loopback port, accepts exactly
// one connection, reads (and discards) the request, writes the given raw
// response bytes, then closes -- mirroring a real MS-MQQB acceptor for a
// single EstablishConnection exchange. Returns a ScanTarget pointed at it.
func startFakeAcceptor(t *testing.T, response []byte) *zgrab2.ScanTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req := make([]byte, establishConnectionPacketLen)
		_, _ = io.ReadFull(conn, req) // best-effort; response is what the test actually checks
		if response != nil {
			_, _ = conn.Write(response)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	addr := ln.Addr().(*net.TCPAddr)
	return &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: uint(addr.Port)}
}

// newTestScanner builds an initialized Scanner and a matching DialerGroup,
// the same way the CLI framework would.
func newTestScanner(t *testing.T) (*Scanner, *zgrab2.DialerGroup) {
	t.Helper()
	m := NewModule()
	s := m.NewScanner()
	flags := m.NewFlags().(*Flags)
	if err := s.Init(flags); err != nil {
		t.Fatalf("Init: %v", err)
	}
	scanner := s.(*Scanner)
	dialerGroup, err := scanner.GetDialerGroupConfig().GetDefaultDialerGroupFromConfig()
	if err != nil {
		t.Fatalf("GetDefaultDialerGroupFromConfig: %v", err)
	}
	return scanner, dialerGroup
}

// runScan spins up a fake acceptor serving the given response bytes, then
// runs a real Scanner.Scan against it.
func runScan(t *testing.T, response []byte) (zgrab2.ScanStatus, *Results, error) {
	t.Helper()
	target := startFakeAcceptor(t, response)
	scanner, dialerGroup := newTestScanner(t)
	status, raw, err := scanner.Scan(context.Background(), dialerGroup, target)
	if raw == nil {
		return status, nil, err
	}
	results, ok := raw.(*Results)
	if !ok {
		t.Fatalf("Scan returned unexpected result type %T", raw)
	}
	return status, results, err
}

// buildResponse is a small helper wrapping makeEstablishConnectionResponse
// (defined in msmq_test.go) plus an OperatingSystem override.
func buildResponse(clientGUID, serverGUID [16]byte, refused bool, paddingByte byte, osRaw uint16) []byte {
	pkt := makeEstablishConnectionResponse(clientGUID, serverGUID, 0, refused, paddingByte)
	setOperatingSystem(pkt, osRaw)
	return pkt
}

// compliantServerGUID is a non-zero GUID, as a spec-compliant acceptor
// handling a direct-format-name request MUST return.
var compliantServerGUID = [16]byte{0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa}

func TestScanMalformedResponse(t *testing.T) {
	var clientGUID, serverGUID [16]byte
	pkt := makeEstablishConnectionResponse(clientGUID, serverGUID, 0, false, responsePaddingByte)
	// Corrupt the signature so parseEstablishConnection rejects it, mirroring
	// TestParseEstablishConnectionErrors but exercised through Scan().
	binary.LittleEndian.PutUint32(pkt[4:8], 0xDEADBEEF)

	status, results, err := runScan(t, pkt)
	if status != zgrab2.SCAN_PROTOCOL_ERROR {
		t.Errorf("status = %s, want %s", status, zgrab2.SCAN_PROTOCOL_ERROR)
	}
	if results != nil {
		t.Errorf("results = %+v, want nil", results)
	}
	if err == nil {
		t.Error("err = nil, want non-nil")
	}
}

func TestScanZeroGUIDsCompliantPadding(t *testing.T) {
	var clientGUID, serverGUID [16]byte // both zero
	pkt := buildResponse(clientGUID, serverGUID, false, responsePaddingByte, 16)

	status, results, err := runScan(t, pkt)
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("status = %s, err = %v", status, err)
	}
	if !results.Fingerprint.ServerGuidZero {
		t.Error("Fingerprint.ServerGuidZero = false, want true")
	}
	if !containsEvidence(results.MSMQIdentification.Evidence, EvidenceServerGuidZero) {
		t.Errorf("MSMQIdentification.Evidence = %v, want to contain %q", results.MSMQIdentification.Evidence, EvidenceServerGuidZero)
	}
	// A zero ServerGuid alone must not demote confidence -- only a padding
	// mismatch does.
	if results.Detection.Confidence != attribution.ConfidenceHigh {
		t.Errorf("Detection.Confidence = %s, want %s", results.Detection.Confidence, attribution.ConfidenceHigh)
	}
}

// TestScanOperatingSystem4224 is the regression test named explicitly by the
// user: operating_system=4224 (0x1080) must never be interpreted as a
// Windows version, or any version at all.
func TestScanOperatingSystem4224(t *testing.T) {
	var clientGUID [16]byte
	pkt := buildResponse(clientGUID, compliantServerGUID, false, responsePaddingByte, 4224)

	status, results, err := runScan(t, pkt)
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("status = %s, err = %v", status, err)
	}
	if results.Fingerprint.OperatingSystemRaw != 4224 {
		t.Errorf("Fingerprint.OperatingSystemRaw = %d, want 4224", results.Fingerprint.OperatingSystemRaw)
	}
	if results.Fingerprint.OperatingSystemHex != "0x1080" {
		t.Errorf("Fingerprint.OperatingSystemHex = %q, want %q", results.Fingerprint.OperatingSystemHex, "0x1080")
	}
	if results.OSIdentification.Family != nil {
		t.Errorf("OSIdentification.Family = %v, want nil", *results.OSIdentification.Family)
	}
	if results.OSIdentification.Version != nil {
		t.Errorf("OSIdentification.Version = %v, want nil", *results.OSIdentification.Version)
	}
	if results.MSMQIdentification.Version != nil {
		t.Errorf("MSMQIdentification.Version = %v, want nil", *results.MSMQIdentification.Version)
	}
	if results.VersionIdentification.Status != attribution.VersionNotAvailablePreAuth {
		t.Errorf("VersionIdentification.Status = %s, want %s", results.VersionIdentification.Status, attribution.VersionNotAvailablePreAuth)
	}
}

func TestScanAcceptedCompliant(t *testing.T) {
	var clientGUID [16]byte
	pkt := buildResponse(clientGUID, compliantServerGUID, false, responsePaddingByte, 16)

	status, results, err := runScan(t, pkt)
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("status = %s, err = %v", status, err)
	}
	if results.Detection.Confidence != attribution.ConfidenceHigh {
		t.Errorf("Detection.Confidence = %s, want %s", results.Detection.Confidence, attribution.ConfidenceHigh)
	}
	if results.VulnerabilityAssessment.Status != attribution.VulnNotConfirmed {
		t.Errorf("VulnerabilityAssessment.Status = %s, want %s", results.VulnerabilityAssessment.Status, attribution.VulnNotConfirmed)
	}
	if !containsFindingID(results.Findings, "MSMQ_EXPOSED") || !containsFindingID(results.Findings, "MSMQ_ANONYMOUS_HANDSHAKE") {
		t.Errorf("Findings = %+v, want both MSMQ_EXPOSED and MSMQ_ANONYMOUS_HANDSHAKE", results.Findings)
	}

	// Level 1 (handshake) is a first-class security posture signal, and must
	// never be conflated with Levels 2/3 (protocol/resource access), which
	// this module never tests.
	if !results.Security.AnonymousHandshake.Detected {
		t.Error("Security.AnonymousHandshake.Detected = false, want true")
	}
	if results.Security.AnonymousHandshake.Scope != "protocol_handshake_only" {
		t.Errorf("Security.AnonymousHandshake.Scope = %q, want %q", results.Security.AnonymousHandshake.Scope, "protocol_handshake_only")
	}
	if results.SecurityAssessment.AnonymousHandshake.Status != "confirmed" {
		t.Errorf("SecurityAssessment.AnonymousHandshake.Status = %q, want %q", results.SecurityAssessment.AnonymousHandshake.Status, "confirmed")
	}
	if results.SecurityAssessment.AnonymousHandshake.Severity != "informational" {
		t.Errorf("SecurityAssessment.AnonymousHandshake.Severity = %q, want %q", results.SecurityAssessment.AnonymousHandshake.Severity, "informational")
	}
	if results.SecurityAssessment.AnonymousProtocolAccess.Status != "not_tested" || results.SecurityAssessment.AnonymousProtocolAccess.Confidence != "none" {
		t.Errorf("SecurityAssessment.AnonymousProtocolAccess = %+v, want not_tested/none", results.SecurityAssessment.AnonymousProtocolAccess)
	}
	if results.SecurityAssessment.AnonymousResourceAccess.Status != "not_tested" || results.SecurityAssessment.AnonymousResourceAccess.Confidence != "none" {
		t.Errorf("SecurityAssessment.AnonymousResourceAccess = %+v, want not_tested/none", results.SecurityAssessment.AnonymousResourceAccess)
	}
	if results.SecurityPosture != (SecurityPosture{
		AnonymousHandshake:      "confirmed",
		AnonymousProtocolAccess: "not_tested",
		AnonymousResourceAccess: "not_tested",
	}) {
		t.Errorf("SecurityPosture = %+v, want confirmed/not_tested/not_tested", results.SecurityPosture)
	}
}

func TestScanRefusedCompliant(t *testing.T) {
	var clientGUID [16]byte
	pkt := buildResponse(clientGUID, compliantServerGUID, true, responsePaddingByte, 16)

	status, results, err := runScan(t, pkt)
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("status = %s, err = %v", status, err)
	}
	if results.VulnerabilityAssessment.Status != attribution.VulnUnknown {
		t.Errorf("VulnerabilityAssessment.Status = %s, want %s", results.VulnerabilityAssessment.Status, attribution.VulnUnknown)
	}
	if containsFindingID(results.Findings, "MSMQ_ANONYMOUS_HANDSHAKE") {
		t.Error("Findings contains MSMQ_ANONYMOUS_HANDSHAKE for a refused connection")
	}
	if !containsFindingID(results.Findings, "MSMQ_EXPOSED") {
		t.Error("Findings missing MSMQ_EXPOSED")
	}

	// A refused handshake means Level 1 is explicitly not_confirmed --
	// never silently defaulted or omitted.
	if results.Security.AnonymousHandshake.Detected {
		t.Error("Security.AnonymousHandshake.Detected = true, want false for a refused connection")
	}
	if results.SecurityAssessment.AnonymousHandshake.Status != "not_confirmed" {
		t.Errorf("SecurityAssessment.AnonymousHandshake.Status = %q, want %q", results.SecurityAssessment.AnonymousHandshake.Status, "not_confirmed")
	}
	if results.SecurityPosture.AnonymousHandshake != "not_confirmed" {
		t.Errorf("SecurityPosture.AnonymousHandshake = %q, want %q", results.SecurityPosture.AnonymousHandshake, "not_confirmed")
	}
}

// TestScanAnomalousResponder mirrors the real-world anomaly found while
// scanning live hosts this session: padding that doesn't match the mandated
// 0x5A pattern, a zero ServerGuid despite echoing our own OperatingSystem
// bits back (raw=32784=0x8010) -- a sign of something echoing bytes on port
// 1801 rather than a genuine MS-MQQB implementation.
func TestScanAnomalousResponder(t *testing.T) {
	for _, refused := range []bool{false, true} {
		var clientGUID, serverGUID [16]byte // zero, unlike a compliant acceptor
		pkt := buildResponse(clientGUID, serverGUID, refused, 0x00, 32784)

		status, results, err := runScan(t, pkt)
		if status != zgrab2.SCAN_SUCCESS {
			t.Fatalf("refused=%v: status = %s, err = %v", refused, status, err)
		}
		if results.Detection.Confidence != attribution.ConfidenceMedium {
			t.Errorf("refused=%v: Detection.Confidence = %s, want %s", refused, results.Detection.Confidence, attribution.ConfidenceMedium)
		}
		if results.VulnerabilityAssessment.Status != attribution.VulnInsufficientEvidence {
			t.Errorf("refused=%v: VulnerabilityAssessment.Status = %s, want %s", refused, results.VulnerabilityAssessment.Status, attribution.VulnInsufficientEvidence)
		}

		// Accepted="Level 1 happened" is a raw fact independent of how much
		// we trust the responder's identity; SecurityAssessment.Confidence
		// (not Status) is where that distrust shows up.
		wantDetected := !refused
		if results.Security.AnonymousHandshake.Detected != wantDetected {
			t.Errorf("refused=%v: Security.AnonymousHandshake.Detected = %v, want %v", refused, results.Security.AnonymousHandshake.Detected, wantDetected)
		}
		if results.Security.AnonymousHandshake.Confidence != attribution.ConfidenceMedium {
			t.Errorf("refused=%v: Security.AnonymousHandshake.Confidence = %s, want %s", refused, results.Security.AnonymousHandshake.Confidence, attribution.ConfidenceMedium)
		}
		// Detection.Confidence is medium here (anomalous/non-compliant
		// responder), so an accepted handshake must read "observed", never
		// "confirmed" -- security confidence must never exceed the
		// confidence of the underlying protocol evidence.
		wantStatus := "not_confirmed"
		if !refused {
			wantStatus = "observed"
		}
		if results.SecurityAssessment.AnonymousHandshake.Status != wantStatus {
			t.Errorf("refused=%v: SecurityAssessment.AnonymousHandshake.Status = %q, want %q", refused, results.SecurityAssessment.AnonymousHandshake.Status, wantStatus)
		}
		if results.SecurityAssessment.AnonymousHandshake.Confidence != attribution.ConfidenceMedium {
			t.Errorf("refused=%v: SecurityAssessment.AnonymousHandshake.Confidence = %s, want %s", refused, results.SecurityAssessment.AnonymousHandshake.Confidence, attribution.ConfidenceMedium)
		}
	}
}

// TestSecurityConfidenceNeverExceedsProtocolConfidence is the direct
// regression test for the bug found this session: an accepted-but-anomalous
// response (padding invalid, zero server GUID -- Detection.Confidence ==
// medium) must never report security_assessment.anonymous_handshake as
// "confirmed"/high, since that would claim more certainty than the
// underlying protocol evidence actually supports.
func TestSecurityConfidenceNeverExceedsProtocolConfidence(t *testing.T) {
	var clientGUID, serverGUID [16]byte // zero server GUID -- anomalous
	pkt := buildResponse(clientGUID, serverGUID, false, 0x00, 32784)

	status, results, err := runScan(t, pkt)
	if status != zgrab2.SCAN_SUCCESS {
		t.Fatalf("status = %s, err = %v", status, err)
	}
	if results.Detection.Confidence != attribution.ConfidenceMedium {
		t.Fatalf("Detection.Confidence = %s, want %s (test fixture assumption violated)", results.Detection.Confidence, attribution.ConfidenceMedium)
	}
	if results.SecurityAssessment.AnonymousHandshake.Status == "confirmed" {
		t.Error(`SecurityAssessment.AnonymousHandshake.Status = "confirmed", want "observed" -- must never exceed the underlying medium-confidence protocol evidence`)
	}
	if results.SecurityAssessment.AnonymousHandshake.Confidence == attribution.ConfidenceHigh {
		t.Error("SecurityAssessment.AnonymousHandshake.Confidence = high, want medium -- must mirror Detection.Confidence, never overclaim")
	}
	if results.Security.AnonymousHandshake.Confidence == attribution.ConfidenceHigh {
		t.Error("Security.AnonymousHandshake.Confidence = high, want medium")
	}
}

// TestScanInvariants is a table-driven sweep over many OS/GUID/padding/accept
// combinations, asserting the properties that must hold for every response a
// real acceptor could plausibly send: no version is ever inferred, and
// vulnerability status never exceeds what a single exchange can prove.
func TestScanInvariants(t *testing.T) {
	osValues := []uint16{0, 16, 528, 4224, 32784, 0xFFFF}
	guidValues := [][16]byte{{}, compliantServerGUID}
	paddingValues := []byte{responsePaddingByte, 0x00, 0x41}

	for _, osRaw := range osValues {
		for _, serverGUID := range guidValues {
			for _, padding := range paddingValues {
				for _, refused := range []bool{false, true} {
					var clientGUID [16]byte
					pkt := buildResponse(clientGUID, serverGUID, refused, padding, osRaw)

					status, results, err := runScan(t, pkt)
					if status != zgrab2.SCAN_SUCCESS {
						t.Fatalf("os=%d guid=%x padding=%x refused=%v: status = %s, err = %v", osRaw, serverGUID, padding, refused, status, err)
					}

					if results.VulnerabilityAssessment.Status == attribution.VulnConfirmed || results.VulnerabilityAssessment.Status == attribution.VulnLikely {
						t.Errorf("os=%d guid=%x padding=%x refused=%v: VulnerabilityAssessment.Status = %s, must never be confirmed/likely from a single exchange",
							osRaw, serverGUID, padding, refused, results.VulnerabilityAssessment.Status)
					}
					if results.OSIdentification.Family != nil || results.OSIdentification.Version != nil || results.OSIdentification.Build != nil {
						t.Errorf("os=%d guid=%x padding=%x refused=%v: OSIdentification = %+v, want Family/Version/Build all nil",
							osRaw, serverGUID, padding, refused, results.OSIdentification)
					}
					if results.MSMQIdentification.Version != nil {
						t.Errorf("os=%d guid=%x padding=%x refused=%v: MSMQIdentification.Version = %v, want nil",
							osRaw, serverGUID, padding, refused, *results.MSMQIdentification.Version)
					}
					want := attribution.VersionIdentification{Status: attribution.VersionNotAvailablePreAuth}
					if results.VersionIdentification != want {
						t.Errorf("os=%d guid=%x padding=%x refused=%v: VersionIdentification = %+v, want %+v",
							osRaw, serverGUID, padding, refused, results.VersionIdentification, want)
					}

					// Graduated anonymous-access model invariants: Level 1's
					// Detected must always mirror Accepted; Levels 2/3 are
					// always not_tested/none, no matter what the wire data
					// looks like, because this module never attempts them.
					accepted := !refused
					if results.Security.AnonymousHandshake.Detected != accepted {
						t.Errorf("os=%d guid=%x padding=%x refused=%v: Security.AnonymousHandshake.Detected = %v, want %v",
							osRaw, serverGUID, padding, refused, results.Security.AnonymousHandshake.Detected, accepted)
					}
					if results.Security.AnonymousHandshake.Scope != "protocol_handshake_only" {
						t.Errorf("os=%d guid=%x padding=%x refused=%v: Security.AnonymousHandshake.Scope = %q, want protocol_handshake_only",
							osRaw, serverGUID, padding, refused, results.Security.AnonymousHandshake.Scope)
					}
					// Security confidence must never exceed the confidence of
					// the underlying protocol evidence: "confirmed" is only
					// reachable when Detection.Confidence == high; an
					// accepted-but-anomalous response is "observed", never
					// "confirmed".
					wantHandshakeStatus := "not_confirmed"
					switch {
					case accepted && results.Detection.Confidence == attribution.ConfidenceHigh:
						wantHandshakeStatus = "confirmed"
					case accepted:
						wantHandshakeStatus = "observed"
					}
					if results.SecurityAssessment.AnonymousHandshake.Status != wantHandshakeStatus {
						t.Errorf("os=%d guid=%x padding=%x refused=%v: SecurityAssessment.AnonymousHandshake.Status = %q, want %q",
							osRaw, serverGUID, padding, refused, results.SecurityAssessment.AnonymousHandshake.Status, wantHandshakeStatus)
					}
					if results.SecurityAssessment.AnonymousHandshake.Status == "confirmed" && results.Detection.Confidence != attribution.ConfidenceHigh {
						t.Errorf("os=%d guid=%x padding=%x refused=%v: status=confirmed but Detection.Confidence=%s -- security confidence exceeded protocol evidence confidence",
							osRaw, serverGUID, padding, refused, results.Detection.Confidence)
					}
					// Severity must never escalate beyond informational from
					// a single handshake, no matter how the wire data looks.
					if results.SecurityAssessment.AnonymousHandshake.Severity != "informational" {
						t.Errorf("os=%d guid=%x padding=%x refused=%v: SecurityAssessment.AnonymousHandshake.Severity = %q, must always be informational",
							osRaw, serverGUID, padding, refused, results.SecurityAssessment.AnonymousHandshake.Severity)
					}
					if results.SecurityAssessment.AnonymousProtocolAccess != (UntestedAccessAssessment{Status: "not_tested", Confidence: "none"}) {
						t.Errorf("os=%d guid=%x padding=%x refused=%v: SecurityAssessment.AnonymousProtocolAccess = %+v, want not_tested/none",
							osRaw, serverGUID, padding, refused, results.SecurityAssessment.AnonymousProtocolAccess)
					}
					if results.SecurityAssessment.AnonymousResourceAccess != (UntestedAccessAssessment{Status: "not_tested", Confidence: "none"}) {
						t.Errorf("os=%d guid=%x padding=%x refused=%v: SecurityAssessment.AnonymousResourceAccess = %+v, want not_tested/none",
							osRaw, serverGUID, padding, refused, results.SecurityAssessment.AnonymousResourceAccess)
					}
					// No high-severity anonymous-access finding may ever be
					// produced from a single handshake.
					for _, f := range results.Findings {
						if f.ID == "MSMQ-ANONYMOUS-ACCEPTED" {
							t.Errorf("os=%d guid=%x padding=%x refused=%v: retired finding MSMQ-ANONYMOUS-ACCEPTED must not be produced",
								osRaw, serverGUID, padding, refused)
						}
						if f.Severity == "high" || f.Severity == "critical" {
							t.Errorf("os=%d guid=%x padding=%x refused=%v: finding %s has severity %q, must never exceed informational/medium from a single handshake",
								osRaw, serverGUID, padding, refused, f.ID, f.Severity)
						}
					}
					// SecurityPosture must mirror SecurityAssessment exactly,
					// so a correlation engine reading only the flat summary
					// never disagrees with the richer structure.
					wantPosture := SecurityPosture{
						AnonymousHandshake:      results.SecurityAssessment.AnonymousHandshake.Status,
						AnonymousProtocolAccess: "not_tested",
						AnonymousResourceAccess: "not_tested",
					}
					if results.SecurityPosture != wantPosture {
						t.Errorf("os=%d guid=%x padding=%x refused=%v: SecurityPosture = %+v, want %+v",
							osRaw, serverGUID, padding, refused, results.SecurityPosture, wantPosture)
					}
				}
			}
		}
	}
}

// TestResultsBackwardCompatibleJSON guards against ever removing or renaming
// a field that existed before this schema extension.
func TestResultsBackwardCompatibleJSON(t *testing.T) {
	var clientGUID [16]byte
	// SE bit set (0x8010) so the pre-existing "is_session_mode" key (tagged
	// omitempty) actually renders, letting this test check for its presence.
	pkt := buildResponse(clientGUID, compliantServerGUID, false, responsePaddingByte, 0x8010)

	_, results, err := runScan(t, pkt)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}

	raw, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	for _, key := range []string{
		"accepted", "client_guid", "server_guid", "time_stamp", "operating_system",
		"is_session_mode", "padding_matches_server_pattern", "security", "fingerprint", "findings",
	} {
		if _, ok := m[key]; !ok {
			t.Errorf("marshaled Results is missing pre-existing key %q", key)
		}
	}

	// security.anonymous_handshake upgraded from a bool to an object this
	// session -- confirm it marshaled as the new first-class object shape,
	// not silently reverted to a bool.
	security, ok := m["security"].(map[string]any)
	if !ok {
		t.Fatalf("security is not an object: %#v", m["security"])
	}
	anonHandshake, ok := security["anonymous_handshake"].(map[string]any)
	if !ok {
		t.Fatalf("security.anonymous_handshake is not an object (want detected/confidence/scope/evidence): %#v", security["anonymous_handshake"])
	}
	for _, key := range []string{"detected", "confidence", "scope", "evidence"} {
		if _, ok := anonHandshake[key]; !ok {
			t.Errorf("security.anonymous_handshake is missing key %q", key)
		}
	}

	for _, key := range []string{"security_assessment", "security_posture"} {
		if _, ok := m[key]; !ok {
			t.Errorf("marshaled Results is missing new key %q", key)
		}
	}
}

func containsEvidence(evidence []attribution.Evidence, want attribution.Evidence) bool {
	for _, e := range evidence {
		if e == want {
			return true
		}
	}
	return false
}

func containsFindingID(findings []attribution.Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

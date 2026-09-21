package msmq

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/zmap/zgrab2/lib/attribution"
)

// syntheticFixture deterministically builds the i-th synthetic Results,
// cycling through a small set of realistic patterns (mostly compliant
// hosts, one anomalous pattern per 32, per the real-world mix observed
// while scanning live hosts this session) plus a per-host ServerGuid/
// TimeStamp so records aren't byte-identical -- no time.Now()/math.Rand,
// fully deterministic and reproducible.
func syntheticFixture(i int) *Results {
	osValues := []uint16{16, 528, 4224}
	osRaw := osValues[i%len(osValues)]

	var clientGUID [16]byte
	serverGUID := compliantServerGUID
	// Perturb a couple of bytes so ServerGuid varies per host, like real
	// scan data would, without needing real randomness.
	serverGUID[0] = byte(i)
	serverGUID[1] = byte(i >> 8)

	anomalous := i%32 == 31 // ~3% anomalous, matching the 1-in-32 real ratio observed this session
	var paddingByte byte = responsePaddingByte
	if anomalous {
		serverGUID = [16]byte{}
		paddingByte = 0x00
	}

	pkt := buildResponse(clientGUID, serverGUID, false, paddingByte, osRaw)
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
			AnonymousHandshake: anonymousHandshake,
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
		},
		OSIdentification: attribution.OSIdentification{
			FamilyConfidence: attribution.ConfidenceUnknown,
			Confidence:       attribution.ConfidenceUnknown,
			Evidence:         buildOSEvidence(parsed),
		},
		MSMQIdentification:      MSMQIdentification{Confidence: confidence, Evidence: msmqEvidence},
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
	r.Raw = hex.EncodeToString(pkt) // realistic full 572-byte captured response, as --verbose would produce
	r.RawEvidence = rawEvidence(r.Raw, true)
	return r
}

// sizeReport accumulates raw/compressed byte totals for N synthetic
// records marshaled in one mode.
type sizeReport struct {
	n              int
	totalBytes     int64
	rawFieldBytes  int64 // bytes attributable to the debug-only inline "raw" field
	compressedSize int64
}

func measure(n int, marshal func(*Results) ([]byte, []byte, int)) sizeReport {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	report := sizeReport{n: n}
	for i := 0; i < n; i++ {
		r := syntheticFixture(i)
		full, withoutRaw, rawLen := marshal(r)
		report.totalBytes += int64(len(full))
		report.rawFieldBytes += int64(len(full) - len(withoutRaw))
		_ = rawLen
		gz.Write(full)
		gz.Write([]byte("\n"))
	}
	gz.Close()
	report.compressedSize = int64(buf.Len())
	return report
}

func marshalDebug(r *Results) (full, withoutRaw []byte, rawLen int) {
	full, _ = json.Marshal(r)
	stripped := *r
	stripped.Raw = ""
	withoutRaw, _ = json.Marshal(&stripped)
	return full, withoutRaw, len(r.Raw)
}

func marshalStandard(r *Results) (full, withoutRaw []byte, rawLen int) {
	full, _ = json.Marshal(newStandardResults(r))
	return full, full, 0 // standard never carries raw bytes inline -- nothing to strip
}

func marshalCompact(r *Results) (full, withoutRaw []byte, rawLen int) {
	full, _ = json.Marshal(newCompactResults(r))
	return full, full, 0
}

// TestOutputSizeReport measures bytes/asset, total size, raw-evidence
// contribution, and a repeated-string estimate (raw - gzip-compressed size,
// since compression ratio approximates how much of the payload is
// templated/repeated content vs. genuine per-host information) across all
// three output modes. Runs N ∈ {32, 1000} by default; set
// MSMQ_FULL_SIZE_REPORT=1 to also run N ∈ {100000, 1000000} (takes ~30s).
func TestOutputSizeReport(t *testing.T) {
	// Default to the small sizes: this test runs as part of any plain
	// `go test ./modules/msmq/...` invocation, including ones this package
	// doesn't control -- e.g. this repo's CI "Fuzz ./modules/msmq/..." job
	// runs `go test -fuzz=... -timeout=120s ./modules/msmq/...`, which runs
	// every non-fuzz test in the package first, all within that single
	// 120s budget, before fuzzing starts. Relying on -short being passed
	// isn't safe (that workflow doesn't pass it), so the 100K/1M sizes
	// require explicit opt-in instead of opt-out.
	sizes := []int{32, 1_000}
	if os.Getenv("MSMQ_FULL_SIZE_REPORT") == "1" {
		sizes = []int{32, 1_000, 100_000, 1_000_000}
	}
	modes := []struct {
		name    string
		marshal func(*Results) ([]byte, []byte, int)
	}{
		{"debug", marshalDebug},
		{"standard", marshalStandard},
		{"compact", marshalCompact},
	}

	for _, n := range sizes {
		t.Logf("=== N=%d ===", n)
		for _, mode := range modes {
			report := measure(n, mode.marshal)
			bytesPerAsset := float64(report.totalBytes) / float64(n)
			repeatedEstimate := report.totalBytes - report.compressedSize
			t.Logf("%-8s total=%10d bytes  bytes/asset=%8.1f  raw_field=%10d bytes  gzip=%10d bytes  repeated_estimate=%10d bytes",
				mode.name, report.totalBytes, bytesPerAsset, report.rawFieldBytes, report.compressedSize, repeatedEstimate)
		}
	}
}

// BenchmarkMarshalDebug/Standard/Compact report serialization time per
// mode via the standard Go benchmark harness (go test -bench=. -benchmem).
func BenchmarkMarshalDebug(b *testing.B) {
	r := syntheticFixture(0)
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(r)
	}
}

func BenchmarkMarshalStandard(b *testing.B) {
	r := syntheticFixture(0)
	s := newStandardResults(r)
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(s)
	}
}

func BenchmarkMarshalCompact(b *testing.B) {
	r := syntheticFixture(0)
	c := newCompactResults(r)
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(c)
	}
}

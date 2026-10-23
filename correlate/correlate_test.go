package correlate

import (
	"encoding/json"
	"testing"

	"github.com/zmap/zgrab2/lib/attribution"
	"github.com/zmap/zgrab2/lib/ntlm"
	smblog "github.com/zmap/zgrab2/lib/smb/smb"
	"github.com/zmap/zgrab2/modules/msmq"
	"github.com/zmap/zgrab2/modules/msrpc"
	"github.com/zmap/zgrab2/modules/rdp"
)

// fakeScanResponse mirrors zgrab2.ScanResponse for building test fixtures.
type fakeScanResponse struct {
	Status   string `json:"status"`
	Protocol string `json:"protocol"`
	Port     uint   `json:"port"`
	Result   any    `json:"result,omitempty"`
}

func buildGrabLine(t *testing.T, ip string, entries map[string]fakeScanResponse) []byte {
	t.Helper()
	grab := struct {
		IP   string                      `json:"ip"`
		Data map[string]fakeScanResponse `json:"data"`
	}{IP: ip, Data: entries}
	b, err := json.Marshal(grab)
	if err != nil {
		t.Fatalf("marshal grab: %v", err)
	}
	return b
}

// compliantMSMQ is what a genuine, spec-compliant MS-MQQB acceptor that
// accepted our anonymous request produces (see modules/msmq).
var compliantMSMQ = msmq.Results{
	Protocol:  "MSMQ",
	Detection: attribution.Detection{Detected: true, Accepted: true, Confidence: attribution.ConfidenceHigh},
	Accepted:  true,
	VulnerabilityAssessment: attribution.VulnerabilityAssessment{
		Status:            attribution.VulnNotConfirmed,
		Rationale:         "Target accepted an anonymous MS-MQQB EstablishConnection request...",
		KnownIssueClasses: []string{"unauthenticated-mqqb-handshake"},
	},
}

// anomalousMSMQ mirrors the real-world non-compliant responder found during
// live scanning this session.
var anomalousMSMQ = msmq.Results{
	Protocol:  "MSMQ",
	Detection: attribution.Detection{Detected: true, Accepted: true, Confidence: attribution.ConfidenceMedium},
	Accepted:  true,
	VulnerabilityAssessment: attribution.VulnerabilityAssessment{
		Status:    attribution.VulnInsufficientEvidence,
		Rationale: "The acceptor's response deviates from the mandated MS-MQQB response pattern...",
	},
}

var bindAckRPC = msrpc.Results{
	PDUType:       "bind_ack",
	Accepted:      true,
	InterfaceUUID: "e1af8308-5d1f-11c9-91a4-08002b14a0fa",
	CallID:        1,
}

var negotiatedSMBNoNTLM = smblog.SMBLog{
	HasNTLM: true,
	NegotiationLog: &smblog.NegotiationLog{
		DialectRevision: 0x0311,
	},
}

var negotiatedSMBWithNTLM = smblog.SMBLog{
	HasNTLM: true,
	NegotiationLog: &smblog.NegotiationLog{
		DialectRevision: 0x0311,
	},
	SessionSetupLog: &smblog.SessionSetupLog{
		NTLMInfo: &ntlm.Info{OSVersion: "10.0.17763", NetBIOSComputerName: "DC01"},
	},
}

var rdpNoNTLM = rdp.RDPResult{SelectedProtocol: "ssl"}

var rdpWithNTLM = rdp.RDPResult{
	SelectedProtocol: "hybrid",
	NTLM:             &ntlm.Info{OSVersion: "10.0.19041"},
}

func mustAssess(t *testing.T, line []byte) *HostAssessment {
	t.Helper()
	assessment, err := AssessHost(line)
	if err != nil {
		t.Fatalf("AssessHost: %v", err)
	}
	return assessment
}

// TestMSMQOnly: the user's "MSMQ-only host" case. A single, spec-compliant
// MSMQ detection alone must be enough to reach high Windows-family
// confidence (MSMQ is Windows-exclusive), while nothing else was scanned.
func TestMSMQOnly(t *testing.T) {
	line := buildGrabLine(t, "10.0.0.1", map[string]fakeScanResponse{
		"msmq": {Status: "success", Protocol: "msmq", Port: 1801, Result: compliantMSMQ},
	})
	a := mustAssess(t, line)

	if a.Services["msmq"].State != ServiceOpen {
		t.Errorf("msmq state = %s, want open", a.Services["msmq"].State)
	}
	for _, key := range []string{"rpc", "smb", "rdp", "winrm"} {
		if a.Services[key].State != ServiceNotScanned {
			t.Errorf("%s state = %s, want not_scanned", key, a.Services[key].State)
		}
		if a.Exposure[key] != ExposureNotDone {
			t.Errorf("%s exposure = %s, want not_scanned", key, a.Exposure[key])
		}
	}
	if a.OSIdentification.Family == nil || *a.OSIdentification.Family != "Windows" {
		t.Fatalf("OSIdentification.Family = %v, want Windows", a.OSIdentification.Family)
	}
	if a.OSIdentification.FamilyConfidence != attribution.ConfidenceHigh {
		t.Errorf("FamilyConfidence = %s, want high", a.OSIdentification.FamilyConfidence)
	}
	if a.OSIdentification.Version != nil {
		t.Errorf("Version = %v, want nil (no NTLM evidence)", *a.OSIdentification.Version)
	}
	if a.VulnerabilityAssessment.Status != attribution.VulnNotConfirmed {
		t.Errorf("VulnerabilityAssessment.Status = %s, want not_confirmed", a.VulnerabilityAssessment.Status)
	}
}

// TestMSMQPlusRPC: the user's "MSMQ + RPC" case.
func TestMSMQPlusRPC(t *testing.T) {
	line := buildGrabLine(t, "10.0.0.2", map[string]fakeScanResponse{
		"msmq": {Status: "success", Protocol: "msmq", Port: 1801, Result: compliantMSMQ},
		"rpc":  {Status: "success", Protocol: "msrpc", Port: 135, Result: bindAckRPC},
	})
	a := mustAssess(t, line)

	if a.Services["rpc"].State != ServiceOpen || a.Exposure["rpc"] != Exposed {
		t.Errorf("rpc service/exposure = %+v/%s, want open/exposed", a.Services["rpc"], a.Exposure["rpc"])
	}
	if a.OSIdentification.FamilyConfidence != attribution.ConfidenceHigh {
		t.Errorf("FamilyConfidence = %s, want high", a.OSIdentification.FamilyConfidence)
	}
}

// TestMSMQPlusRPCPlusSMB: the user's "MSMQ + RPC + SMB" case, and also
// exercises the multi-signal corroboration bump using two only-medium/low
// signals plus a medium MSMQ signal (anomalous, not spec-compliant) --
// confirming confidence still reaches high through corroboration, not just
// through a single already-high signal.
func TestMSMQPlusRPCPlusSMB(t *testing.T) {
	line := buildGrabLine(t, "10.0.0.3", map[string]fakeScanResponse{
		"msmq": {Status: "success", Protocol: "msmq", Port: 1801, Result: anomalousMSMQ},
		"rpc":  {Status: "success", Protocol: "msrpc", Port: 135, Result: bindAckRPC},
		"smb":  {Status: "success", Protocol: "smb", Port: 445, Result: negotiatedSMBNoNTLM},
	})
	a := mustAssess(t, line)

	if a.Services["smb"].State != ServiceOpen || a.Exposure["smb"] != Exposed {
		t.Errorf("smb service/exposure = %+v/%s, want open/exposed", a.Services["smb"], a.Exposure["smb"])
	}
	// None of the three signals alone is "high" (msmq is medium/anomalous,
	// rpc is medium, smb-without-NTLM is low) -- confidence must still reach
	// high via corroboration across 3 independent protocols.
	if a.OSIdentification.FamilyConfidence != attribution.ConfidenceHigh {
		t.Errorf("FamilyConfidence = %s, want high via corroboration", a.OSIdentification.FamilyConfidence)
	}
	if a.OSIdentification.Version != nil {
		t.Errorf("Version = %v, want nil (no NTLM evidence in this fixture)", *a.OSIdentification.Version)
	}
}

// TestMSMQPlusRPCPlusSMBRDPWinRMUnavailable: the user's "MSMQ+RPC+SMB with
// RDP/WinRM unavailable" case -- absence of RDP/WinRM must not reduce
// Windows-family confidence at all versus the three-service case above.
func TestMSMQPlusRPCPlusSMBRDPWinRMUnavailable(t *testing.T) {
	line := buildGrabLine(t, "10.0.0.4", map[string]fakeScanResponse{
		"msmq": {Status: "success", Protocol: "msmq", Port: 1801, Result: compliantMSMQ},
		"rpc":  {Status: "success", Protocol: "msrpc", Port: 135, Result: bindAckRPC},
		"smb":  {Status: "success", Protocol: "smb", Port: 445, Result: negotiatedSMBNoNTLM},
		"rdp":  {Status: "connection-refused", Protocol: "rdp", Port: 3389},
		// no "winrm" entry at all: no module exists for it.
	})
	a := mustAssess(t, line)

	if a.Services["rdp"].State != ServiceClosed {
		t.Errorf("rdp state = %s, want closed", a.Services["rdp"].State)
	}
	if a.Exposure["rdp"] != ExposureNotSeen {
		t.Errorf("rdp exposure = %s, want not_observed", a.Exposure["rdp"])
	}
	if a.Services["winrm"].State != ServiceNotScanned || a.Exposure["winrm"] != ExposureNotDone {
		t.Errorf("winrm = %+v/%s, want not_scanned/not_scanned", a.Services["winrm"], a.Exposure["winrm"])
	}
	// The critical assertion: RDP/WinRM being unavailable must not have
	// reduced confidence versus the otherwise-identical MSMQ+RPC+SMB case.
	if a.OSIdentification.FamilyConfidence != attribution.ConfidenceHigh {
		t.Errorf("FamilyConfidence = %s, want high (RDP/WinRM absence must not lower confidence)", a.OSIdentification.FamilyConfidence)
	}
}

// TestFilteredAndTimeoutServicesAreNotObserved covers the user's explicit
// "not_observed must never be interpreted as not_installed" requirement,
// and the closed/timeout distinction in Services.
func TestFilteredAndTimeoutServicesAreNotObserved(t *testing.T) {
	line := buildGrabLine(t, "10.0.0.5", map[string]fakeScanResponse{
		"msmq": {Status: "success", Protocol: "msmq", Port: 1801, Result: compliantMSMQ},
		"rpc":  {Status: "connection-timeout", Protocol: "msrpc", Port: 135},
		"smb":  {Status: "connection-refused", Protocol: "smb", Port: 445},
		"rdp":  {Status: "protocol-error", Protocol: "rdp", Port: 3389},
	})
	a := mustAssess(t, line)

	if a.Services["rpc"].State != ServiceTimeout {
		t.Errorf("rpc state = %s, want timeout", a.Services["rpc"].State)
	}
	if a.Services["smb"].State != ServiceClosed {
		t.Errorf("smb state = %s, want closed", a.Services["smb"].State)
	}
	if a.Services["rdp"].State != ServiceNotObserved {
		t.Errorf("rdp state = %s, want not_observed", a.Services["rdp"].State)
	}
	// None of timeout/closed/not_observed is ever "exposed" -- and none of
	// them appears anywhere in this system's vocabulary as "not_installed".
	for _, key := range []string{"rpc", "smb", "rdp"} {
		if a.Exposure[key] == Exposed {
			t.Errorf("%s exposure = exposed, want not_observed (service did not cleanly respond)", key)
		}
		if a.Exposure[key] != ExposureNotSeen {
			t.Errorf("%s exposure = %s, want not_observed", key, a.Exposure[key])
		}
	}
}

// TestWinRMCannotBeSpoofedOpen guards against a crafted/unexpected "winrm"
// key in the input ever being reported as scanned or exposed -- there is no
// WinRM module, so this key must be inert no matter what the input claims.
func TestWinRMCannotBeSpoofedOpen(t *testing.T) {
	line := buildGrabLine(t, "10.0.0.6", map[string]fakeScanResponse{
		"winrm": {Status: "success", Protocol: "winrm", Port: 5985, Result: map[string]any{"fake": true}},
	})
	a := mustAssess(t, line)

	if a.Services["winrm"].State != ServiceNotScanned {
		t.Errorf("winrm state = %s, want not_scanned even with a crafted winrm entry present", a.Services["winrm"].State)
	}
	if a.Exposure["winrm"] != ExposureNotDone {
		t.Errorf("winrm exposure = %s, want not_scanned", a.Exposure["winrm"])
	}
}

// TestNTLMVersionIsTheOnlyPathToAVersion: SMB's NTLM Challenge is the only
// signal in this system allowed to populate OSIdentification.Version.
func TestNTLMVersionIsTheOnlyPathToAVersion(t *testing.T) {
	line := buildGrabLine(t, "10.0.0.7", map[string]fakeScanResponse{
		"smb": {Status: "success", Protocol: "smb", Port: 445, Result: negotiatedSMBWithNTLM},
	})
	a := mustAssess(t, line)

	if a.OSIdentification.Version == nil || *a.OSIdentification.Version != "10.0.17763" {
		t.Fatalf("Version = %v, want \"10.0.17763\"", a.OSIdentification.Version)
	}
	if a.OSIdentification.FamilyConfidence != attribution.ConfidenceHigh {
		t.Errorf("FamilyConfidence = %s, want high", a.OSIdentification.FamilyConfidence)
	}

	// Same for RDP's NTLM Challenge.
	line2 := buildGrabLine(t, "10.0.0.8", map[string]fakeScanResponse{
		"rdp": {Status: "success", Protocol: "rdp", Port: 3389, Result: rdpWithNTLM},
	})
	a2 := mustAssess(t, line2)
	if a2.OSIdentification.Version == nil || *a2.OSIdentification.Version != "10.0.19041" {
		t.Fatalf("Version = %v, want \"10.0.19041\"", a2.OSIdentification.Version)
	}
}

// TestNoVersionWithoutNTLMEvidence: RDP/SMB negotiation alone (no NTLM
// challenge captured) must never populate a version, even though they are
// Windows-capable protocols -- Samba/xrdp exist, and negotiation alone
// proves nothing about version.
func TestNoVersionWithoutNTLMEvidence(t *testing.T) {
	line := buildGrabLine(t, "10.0.0.9", map[string]fakeScanResponse{
		"smb": {Status: "success", Protocol: "smb", Port: 445, Result: negotiatedSMBNoNTLM},
		"rdp": {Status: "success", Protocol: "rdp", Port: 3389, Result: rdpNoNTLM},
	})
	a := mustAssess(t, line)
	if a.OSIdentification.Version != nil {
		t.Errorf("Version = %v, want nil", *a.OSIdentification.Version)
	}
}

// TestVulnerabilityNeverEscalatesBeyondModuleEvidence: even with full
// Windows-family corroboration, this tool must never claim confirmed/likely
// for a specific CVE -- it has no version-to-CVE mapping.
func TestVulnerabilityNeverEscalatesBeyondModuleEvidence(t *testing.T) {
	line := buildGrabLine(t, "10.0.0.10", map[string]fakeScanResponse{
		"msmq": {Status: "success", Protocol: "msmq", Port: 1801, Result: compliantMSMQ},
		"rpc":  {Status: "success", Protocol: "msrpc", Port: 135, Result: bindAckRPC},
		"smb":  {Status: "success", Protocol: "smb", Port: 445, Result: negotiatedSMBWithNTLM},
	})
	a := mustAssess(t, line)

	if a.OSIdentification.Version == nil {
		t.Fatal("expected a version from the NTLM fixture")
	}
	if a.VulnerabilityAssessment.Status == attribution.VulnConfirmed || a.VulnerabilityAssessment.Status == attribution.VulnLikely {
		t.Errorf("VulnerabilityAssessment.Status = %s, must never be confirmed/likely -- this tool has no version-to-CVE mapping", a.VulnerabilityAssessment.Status)
	}
	// The msmq module's own "not_confirmed" assessment must still be the
	// reported status -- correlation adds context, not escalation.
	if a.VulnerabilityAssessment.Status != attribution.VulnNotConfirmed {
		t.Errorf("VulnerabilityAssessment.Status = %s, want not_confirmed (unchanged from msmq's own assessment)", a.VulnerabilityAssessment.Status)
	}
}

// TestNoServicesDetected: nothing open anywhere -- OS family must stay nil
// and vulnerability status must be insufficient_evidence, not unknown (no
// data at all, as opposed to data that simply lacked a vuln signal).
func TestNoServicesDetected(t *testing.T) {
	line := buildGrabLine(t, "10.0.0.11", map[string]fakeScanResponse{
		"msmq": {Status: "connection-timeout", Protocol: "msmq", Port: 1801},
		"rpc":  {Status: "connection-refused", Protocol: "msrpc", Port: 135},
	})
	a := mustAssess(t, line)

	if a.OSIdentification.Family != nil {
		t.Errorf("Family = %v, want nil", *a.OSIdentification.Family)
	}
	if a.VulnerabilityAssessment.Status != attribution.VulnInsufficientEvidence {
		t.Errorf("VulnerabilityAssessment.Status = %s, want insufficient_evidence", a.VulnerabilityAssessment.Status)
	}
}

// TestMalformedGrabLine ensures a garbled input line produces an error
// rather than a panic or a silently-wrong assessment.
func TestMalformedGrabLine(t *testing.T) {
	if _, err := AssessHost([]byte("not json")); err == nil {
		t.Error("AssessHost accepted invalid JSON")
	}
}

// TestMalformedModuleResult ensures a result payload that doesn't match its
// claimed protocol produces an error rather than a silently-wrong decode.
func TestMalformedModuleResult(t *testing.T) {
	line := buildGrabLine(t, "10.0.0.12", map[string]fakeScanResponse{
		"msmq": {Status: "success", Protocol: "msmq", Port: 1801, Result: "not an object"},
	})
	if _, err := AssessHost(line); err == nil {
		t.Error("AssessHost accepted a malformed msmq result payload")
	}
}

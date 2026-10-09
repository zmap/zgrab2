package correlate

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zmap/zgrab2/lib/attribution"
)

// knownModuleProtocols maps this package's stable service-key vocabulary to
// the zgrab2 module protocol name that satisfies it (the value of each
// ScanResponse's own "protocol" field, not the ini section name used as the
// Grab.Data map key -- those can differ). "winrm" intentionally has no
// entry: no WinRM module exists in this codebase, so it is always reported
// not_scanned, never fabricated.
var knownModuleProtocols = map[string]string{
	"msmq": "msmq",
	"rpc":  "msrpc",
	"smb":  "smb",
	"rdp":  "rdp",
}

// serviceKeys is the fixed, ordered set of services this tool reports on.
var serviceKeys = []string{"msmq", "rpc", "smb", "rdp", "winrm"}

// AssessHost builds a HostAssessment from one line of `zgrab2 multiple`
// JSONL output (a processing.Grab record).
func AssessHost(line []byte) (*HostAssessment, error) {
	var grab grabRecord
	if err := json.Unmarshal(line, &grab); err != nil {
		return nil, fmt.Errorf("invalid grab record: %w", err)
	}

	assessment := &HostAssessment{
		IP:        grab.IP,
		Services:  map[string]ServiceResult{},
		Exposure:  map[string]ExposureState{},
		Protocols: map[string]json.RawMessage{},
	}

	// Index the grab's scan responses by their own Protocol field, not by
	// the Grab.Data map key.
	byProtocol := map[string]scanResponse{}
	for _, resp := range grab.Data {
		byProtocol[resp.Protocol] = resp
	}

	for _, key := range serviceKeys {
		moduleProtocol, scannable := knownModuleProtocols[key]
		if !scannable {
			assessment.Services[key] = ServiceResult{State: ServiceNotScanned}
			assessment.Exposure[key] = ExposureNotDone
			continue
		}
		resp, ok := byProtocol[moduleProtocol]
		if !ok {
			assessment.Services[key] = ServiceResult{State: ServiceNotScanned}
			assessment.Exposure[key] = ExposureNotDone
			continue
		}
		state := classifyStatus(resp.Status)
		assessment.Services[key] = ServiceResult{State: state, Confidence: stateConfidence(state)}
		if state == ServiceOpen {
			assessment.Exposure[key] = Exposed
			if len(resp.Result) > 0 {
				assessment.Protocols[key] = resp.Result
			}
		} else {
			assessment.Exposure[key] = ExposureNotSeen
		}
	}

	var signals []protocolSignal
	var vulnCandidates []attribution.VulnerabilityAssessment

	if resp, ok := byProtocol["msmq"]; ok && classifyStatus(resp.Status) == ServiceOpen {
		res, err := extractMSMQ(resp.Result)
		if err != nil {
			return nil, err
		}
		sig, vuln := msmqSignalFrom(res)
		signals = append(signals, sig)
		if vuln != nil {
			vulnCandidates = append(vulnCandidates, *vuln)
		}
	}
	if resp, ok := byProtocol["msrpc"]; ok && classifyStatus(resp.Status) == ServiceOpen {
		res, err := extractMSRPC(resp.Result)
		if err != nil {
			return nil, err
		}
		signals = append(signals, msrpcSignalFrom(res))
	}
	if resp, ok := byProtocol["smb"]; ok && classifyStatus(resp.Status) == ServiceOpen {
		res, err := extractSMB(resp.Result)
		if err != nil {
			return nil, err
		}
		signals = append(signals, smbSignalFrom(res))
	}
	if resp, ok := byProtocol["rdp"]; ok && classifyStatus(resp.Status) == ServiceOpen {
		res, err := extractRDP(resp.Result)
		if err != nil {
			return nil, err
		}
		signals = append(signals, rdpSignalFrom(res))
	}

	assessment.OSIdentification = combineOSIdentification(signals)
	for _, sig := range signals {
		assessment.Evidence = append(assessment.Evidence, sig.evidence...)
	}
	assessment.VulnerabilityAssessment = combineVulnerability(vulnCandidates, assessment.OSIdentification)

	return assessment, nil
}

// combineOSIdentification is the ONLY place in this system allowed to turn
// per-protocol Evidence into an OS family/version conclusion -- it requires
// evidence, and absence of a service never counts as evidence either way.
// Per the design brief: MSMQ alone can justify medium/high confidence
// (protocol is Windows-exclusive); two or more independent protocol signals
// (even individually weaker ones, e.g. RPC+SMB) are treated as corroborating
// each other and bumped to high, matching "MSMQ+RPC+SMB: high confidence."
// The absence of RDP/WinRM is never consulted here, so it can never lower
// confidence -- neither service is required for Windows.
func combineOSIdentification(signals []protocolSignal) attribution.OSIdentification {
	osID := attribution.OSIdentification{
		FamilyConfidence: attribution.ConfidenceUnknown,
		Confidence:       attribution.ConfidenceUnknown,
	}

	windowsSignals := 0
	var highest attribution.Confidence
	var version *string
	for _, sig := range signals {
		if sig.windowsFamilyConfidence == "" {
			continue
		}
		windowsSignals++
		if confidenceRank(sig.windowsFamilyConfidence) > confidenceRank(highest) {
			highest = sig.windowsFamilyConfidence
		}
		for _, ev := range sig.evidence {
			osID.Evidence = append(osID.Evidence, attribution.Evidence(ev.Source+":"+ev.Signal))
			if v, ok := strings.CutPrefix(ev.Signal, "ntlm_os_version_observed:"); ok && version == nil {
				version = &v
			}
		}
	}
	if windowsSignals == 0 {
		return osID
	}

	family := "Windows"
	osID.Family = &family
	switch {
	case highest == attribution.ConfidenceHigh:
		osID.FamilyConfidence = attribution.ConfidenceHigh
	case windowsSignals >= 2:
		// Independent corroboration from multiple protocols outweighs any
		// single signal's individual ambiguity.
		osID.FamilyConfidence = attribution.ConfidenceHigh
	default:
		osID.FamilyConfidence = highest
	}
	osID.Confidence = osID.FamilyConfidence
	osID.Version = version

	return osID
}

// vulnRank orders VulnAssessmentStatus so the strongest candidate among
// multiple protocols' own assessments can be selected -- this function
// never produces a status stronger than any individual candidate already
// justified.
func vulnRank(s attribution.VulnAssessmentStatus) int {
	switch s {
	case attribution.VulnConfirmed:
		return 5
	case attribution.VulnLikely:
		return 4
	case attribution.VulnPotential:
		return 3
	// VulnNotConfirmed ("a security-relevant behavior was observed, but
	// nothing beyond it was tested") is more informative than VulnUnknown
	// ("no signal either way"), so it outranks it, but it's not an
	// affirmative concern like VulnPotential.
	case attribution.VulnNotConfirmed:
		return 2
	case attribution.VulnUnknown:
		return 1
	default: // VulnInsufficientEvidence
		return 0
	}
}

// combineVulnerability never escalates beyond what a single module's own
// assessment already supports -- this package maintains no version-to-CVE
// mapping, so higher OS-family confidence from correlation is noted in the
// rationale but never used to promote the status itself.
func combineVulnerability(candidates []attribution.VulnerabilityAssessment, os attribution.OSIdentification) attribution.VulnerabilityAssessment {
	if len(candidates) == 0 {
		if os.Family != nil {
			return attribution.VulnerabilityAssessment{
				Status:    attribution.VulnUnknown,
				Rationale: "Host services were detected and OS family could be inferred, but none of the correlated protocols in this run produced a vulnerability-relevant signal.",
			}
		}
		return attribution.VulnerabilityAssessment{
			Status:    attribution.VulnInsufficientEvidence,
			Rationale: "No correlated protocol produced a vulnerability-relevant or OS-identifying signal for this host.",
		}
	}

	best := candidates[0]
	for _, c := range candidates[1:] {
		if vulnRank(c.Status) > vulnRank(best.Status) {
			best = c
		}
	}

	rationale := best.Rationale
	if os.Family != nil {
		rationale += fmt.Sprintf(" Cross-protocol correlation independently supports OS family %q at %s confidence, but this tool maintains no version-to-CVE mapping, so status is not escalated beyond what the underlying protocol evidence alone supports.", *os.Family, os.FamilyConfidence)
	}
	return attribution.VulnerabilityAssessment{
		Status:            best.Status,
		Rationale:         rationale,
		KnownIssueClasses: best.KnownIssueClasses,
	}
}

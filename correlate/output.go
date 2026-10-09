package correlate

import (
	"encoding/json"

	"github.com/zmap/zgrab2/lib/attribution"
)

// ServiceState is a per-service reachability/detection status. closed,
// timeout, and not_observed are all "we didn't see it" -- never "it isn't
// installed."
type ServiceState string

const (
	ServiceOpen ServiceState = "open"
	// ServiceClosed means the target actively refused the connection (TCP
	// RST) -- the port is reachable but nothing is listening there, or a
	// firewall explicitly rejects it. Still not proof the service/software
	// is uninstalled elsewhere or reachable on another port.
	ServiceClosed ServiceState = "closed"
	// ServiceFiltered is reserved for a stronger "deliberately blocked"
	// signal (e.g. ICMP unreachable) that TCP-only scanning as implemented
	// here cannot produce -- a connection timeout looks identical whether a
	// firewall silently drops it or the host is simply unreachable, so this
	// package never emits ServiceFiltered today; see ServiceTimeout.
	ServiceFiltered ServiceState = "filtered"
	// ServiceTimeout means no response was received before the connection
	// attempt gave up. Could be a firewall drop or a genuinely offline
	// host -- this package does not guess which.
	ServiceTimeout ServiceState = "timeout"
	// ServiceNotObserved means a TCP-level connection happened but the
	// expected protocol didn't cleanly manifest (e.g. protocol/application
	// error) -- inconclusive, never treated as proof of absence.
	ServiceNotObserved ServiceState = "not_observed"
	// ServiceNotScanned means this run made no attempt at all to check this
	// service (no module for it, or no ini section configured it).
	ServiceNotScanned ServiceState = "not_scanned"
)

// ExposureState is the coarser exposed/not_observed/not_scanned summary
// derived from ServiceState.
type ExposureState string

const (
	Exposed         ExposureState = "exposed"
	ExposureNotSeen ExposureState = "not_observed"
	ExposureNotDone ExposureState = "not_scanned"
)

// ServiceResult is one protocol's contribution to a HostAssessment.
type ServiceResult struct {
	State ServiceState `json:"state"`
	// Confidence that State reflects reality (e.g. a single dropped packet
	// can produce a spurious timeout). Omitted when not meaningful.
	Confidence attribution.Confidence `json:"confidence,omitempty"`
}

// Evidence is one host-level, source-attributed observation feeding
// OSIdentification/VulnerabilityAssessment.
type Evidence struct {
	Source     string                 `json:"source"`
	Signal     string                 `json:"signal"`
	Confidence attribution.Confidence `json:"confidence"`
}

// HostAssessment is this package's per-host output: the correlation of
// every protocol module's independent result for one target IP.
type HostAssessment struct {
	IP                      string                              `json:"ip"`
	Services                map[string]ServiceResult            `json:"services"`
	Exposure                map[string]ExposureState            `json:"exposure"`
	OSIdentification        attribution.OSIdentification        `json:"os_identification"`
	VulnerabilityAssessment attribution.VulnerabilityAssessment `json:"vulnerability_assessment"`
	Evidence                []Evidence                          `json:"evidence"`
	// Protocols carries each open protocol's own raw result object
	// verbatim (keyed the same as Services/Exposure), so downstream
	// consumers can drill into exactly what this assessment was built from
	// without re-scanning.
	Protocols map[string]json.RawMessage `json:"protocols,omitempty"`
}

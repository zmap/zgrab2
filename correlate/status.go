package correlate

import "github.com/zmap/zgrab2/lib/attribution"

// classifyStatus maps a zgrab2 ScanStatus string (see status.go's
// ScanStatus constants in the root zgrab2 package) to this package's
// ServiceState vocabulary.
func classifyStatus(status string) ServiceState {
	switch status {
	case "success":
		return ServiceOpen
	case "connection-refused":
		return ServiceClosed
	case "connection-timeout", "io-timeout":
		return ServiceTimeout
	case "blocklisted-target", "invalid-inputs":
		// No meaningful probe was actually attempted/completed.
		return ServiceNotScanned
	default:
		// connection-closed, handshake-error, protocol-error,
		// application-error, post-tls-application-error, unknown-error:
		// something answered at the TCP layer but the expected protocol
		// didn't cleanly manifest. Inconclusive -- never proof of absence.
		return ServiceNotObserved
	}
}

// stateConfidence grades how much a ServiceState should be trusted as a
// durable fact about the target, independent of any OS/vulnerability
// conclusion drawn from it. Returns "" (omitted in JSON) when the state
// carries no meaningful confidence grading of its own.
func stateConfidence(state ServiceState) attribution.Confidence {
	switch state {
	case ServiceOpen, ServiceClosed:
		return attribution.ConfidenceHigh // a clean success/refusal is a reliable signal
	case ServiceTimeout, ServiceFiltered:
		return attribution.ConfidenceLow // could be transient network loss, not necessarily the service's true state
	default:
		return ""
	}
}

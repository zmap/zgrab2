package zgrab2

import "testing"

func TestScanTLSApplicationErrorConstant(t *testing.T) {
	// Verify the constant has the expected string value used in JSON output.
	const want = ScanStatus("tls-application-error")
	if SCAN_TLS_APPLICATION_ERROR != want {
		t.Errorf("SCAN_TLS_APPLICATION_ERROR = %q, want %q", SCAN_TLS_APPLICATION_ERROR, want)
	}
}

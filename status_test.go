package zgrab2

import "testing"

func TestScanPostTLSApplicationErrorConstant(t *testing.T) {
	// Verify the constant has the expected string value used in JSON output.
	const want = ScanStatus("post-tls-application-error")
	if SCAN_POST_TLS_APPLICATION_ERROR != want {
		t.Errorf("SCAN_POST_TLS_APPLICATION_ERROR = %q, want %q", SCAN_POST_TLS_APPLICATION_ERROR, want)
	}
}

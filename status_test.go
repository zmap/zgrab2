package zgrab2

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
)

func TestScanPostTLSApplicationErrorConstant(t *testing.T) {
	// Verify the constant has the expected string value used in JSON output.
	const want = ScanStatus("post-tls-application-error")
	if SCAN_POST_TLS_APPLICATION_ERROR != want {
		t.Errorf("SCAN_POST_TLS_APPLICATION_ERROR = %q, want %q", SCAN_POST_TLS_APPLICATION_ERROR, want)
	}
}

func TestScanErrorUnwrap(t *testing.T) {
	opErr := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("i/o timeout")}
	scanErr := NewScanError(SCAN_CONNECTION_TIMEOUT, fmt.Errorf("could not connect: %w", opErr))

	if !errors.Is(scanErr, opErr) {
		t.Errorf("errors.Is did not find the wrapped *net.OpError through *ScanError")
	}
	var gotOpErr *net.OpError
	if !errors.As(scanErr, &gotOpErr) || gotOpErr != opErr {
		t.Errorf("errors.As did not find the wrapped *net.OpError through *ScanError")
	}

	// A *ScanError nested inside another is still reachable.
	outer := NewScanError(SCAN_UNKNOWN_ERROR, fmt.Errorf("outer: %w", NewScanError(SCAN_IO_TIMEOUT, io.EOF)))
	if !errors.Is(outer, io.EOF) {
		t.Errorf("errors.Is did not find io.EOF through nested *ScanError values")
	}
	var gotScanErr *ScanError
	if !errors.As(outer, &gotScanErr) || gotScanErr != outer {
		t.Errorf("errors.As should return the outermost *ScanError")
	}

	if (&ScanError{Status: SCAN_UNKNOWN_ERROR}).Unwrap() != nil {
		t.Errorf("Unwrap of a *ScanError with no wrapped error should return nil")
	}
}

func TestTryGetScanStatusUsesOutermostScanError(t *testing.T) {
	inner := NewScanError(SCAN_CONNECTION_TIMEOUT, &net.OpError{Op: "dial", Err: errors.New("timeout")})
	outer := NewScanError(SCAN_APPLICATION_ERROR, fmt.Errorf("wrapped: %w", inner))
	if got := TryGetScanStatus(outer); got != SCAN_APPLICATION_ERROR {
		t.Errorf("TryGetScanStatus(outer) = %q, want %q", got, SCAN_APPLICATION_ERROR)
	}
}

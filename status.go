package zgrab2

import (
	"io"
	"net"
	"runtime/debug"

	log "github.com/sirupsen/logrus"
)

// ScanStatus is the enum value that states how the scan ended.
type ScanStatus string

// TODO: Conform to standard string const format (names, capitalization, hyphens/underscores, etc)
// TODO: Enumerate further status types
// TODO: lump connection closed / io timeout?
// TODO: Add SCAN_TLS_PROTOCOL_ERROR? For purely TLS-wrapped protocols, SCAN_PROTOCOL_ERROR is fine -- but for protocols that have a non-TLS bootstrap (e.g. a STARTTLS procedure), SCAN_PROTOCOL_ERROR is misleading, since it did get far-enough into the application protocol to start TLS handshaking -- but a garbled TLS handshake is certainly not a SCAN_APPLICATION_ERROR
const (
	SCAN_SUCCESS            = ScanStatus("success")            // The protocol in question was positively identified and the scan encountered no errors
	SCAN_CONNECTION_REFUSED = ScanStatus("connection-refused") // TCP connection was actively rejected
	SCAN_CONNECTION_TIMEOUT = ScanStatus("connection-timeout") // No response to TCP connection request
	SCAN_CONNECTION_CLOSED  = ScanStatus("connection-closed")  // The TCP connection was unexpectedly closed
	SCAN_IO_TIMEOUT         = ScanStatus("io-timeout")         // Timed out waiting on data
	SCAN_PROTOCOL_ERROR     = ScanStatus("protocol-error")     // Received data incompatible with the target protocol
	SCAN_APPLICATION_ERROR  = ScanStatus("application-error")  // The application reported an error
	SCAN_UNKNOWN_ERROR      = ScanStatus("unknown-error")      // Catch-all for unrecognized errors
)

// ScanError an error that also includes a ScanStatus.
type ScanError struct {
	Status ScanStatus
	Err    error
}

// Error is an implementation of the builtin.error interface -- just forward the wrapped error's Error() method
func (err *ScanError) Error() string {
	if err.Err == nil {
		return "<nil>"
	}
	return err.Err.Error()
}

func (err *ScanError) Unpack(results interface{}) (ScanStatus, interface{}, error) {
	return err.Status, results, err.Err
}

// NewScanError returns a ScanError with the given status and error.
func NewScanError(status ScanStatus, err error) *ScanError {
	return &ScanError{Status: status, Err: err}
}

// DetectScanError returns a ScanError that attempts to detect the status from the given error.
func DetectScanError(err error) *ScanError {
	return &ScanError{Status: TryGetScanStatus(err), Err: err}
}

// TryGetScanStatus attempts to get the ScanStatus enum value corresponding to the given error.
// Mostly supports network errors. A nil error is interpreted as SCAN_SUCCESS.
// An unrecognized error is interpreted as SCAN_UNKNOWN_ERROR.
func TryGetScanStatus(err error) ScanStatus {
	if err == nil {
		return SCAN_SUCCESS
	}
	if err == io.EOF {
		// Presumably the caller did not call TryGetScanStatus if the EOF was expected
		return SCAN_IO_TIMEOUT
	}
	switch e := err.(type) {
	case *ScanError:
		return e.Status
	case *net.OpError:
		switch e.Op {
		case "dial":
			// TODO: Distinguish connection timeout / connection refused
			// Windows examples:
			//	"dial tcp 192.168.30.3:22: connectex: A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond."
			//	"dial tcp 127.0.0.1:22: connectex: No connection could be made because the target machine actively refused it."
			return SCAN_CONNECTION_TIMEOUT
		case "read":
			// TODO: Distinguish connection reset vs timeout
			return SCAN_IO_TIMEOUT
		case "write":
			// TODO: Distinguish connection reset vs timeout
			return SCAN_IO_TIMEOUT
		default:
			// TODO: Do we need a generic network error?
			log.Debugf("Failed to detect error from net.OpError %v, op = %s at %s", e, e.Op, string(debug.Stack()))
			return SCAN_UNKNOWN_ERROR
		}
	// TODO: More error types
	default:
		log.Debugf("Failed to detect error from %v at %s", e, string(debug.Stack()))
		return SCAN_UNKNOWN_ERROR
	}
}

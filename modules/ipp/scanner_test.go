package ipp

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http"
)

// TestGrabPreservesSendStatus checks that Grab keeps the status sendIPPRequest detected
// (here, a dial failure) rather than replacing it with SCAN_UNKNOWN_ERROR.
func TestGrabPreservesSendStatus(t *testing.T) {
	dialErr := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("i/o timeout")}
	client := http.MakeNewClient()
	client.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, dialErr
		},
	}
	s := &scan{
		client: client,
		url:    getHTTPURL(false, "192.0.2.1", 631, "/ipp"),
	}
	scanner := &Scanner{config: &Flags{}}

	err := scanner.Grab(s, &zgrab2.ScanTarget{IP: net.ParseIP("192.0.2.1"), Port: 631}, &Versions[0])
	if err == nil {
		t.Fatal("Grab returned nil error for a failed dial")
	}
	if err.Status != zgrab2.SCAN_CONNECTION_TIMEOUT {
		t.Errorf("Grab status = %q, want %q", err.Status, zgrab2.SCAN_CONNECTION_TIMEOUT)
	}
	var gotOpErr *net.OpError
	if !errors.As(err, &gotOpErr) {
		t.Errorf("Grab error does not wrap the dial *net.OpError: %v", err)
	}
}

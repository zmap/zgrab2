package smb

import (
	"net"
	"testing"
)

func TestGetSMBLogV1ReturnsNegotiationError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	serverConn.Close()
	defer clientConn.Close()

	log, err := GetSMBLog(clientConn, false, true, false)
	if err == nil {
		t.Fatal("expected SMBv1 negotiation error")
	}
	if log != nil {
		t.Fatalf("expected nil log before negotiation response, got %#v", log)
	}
}

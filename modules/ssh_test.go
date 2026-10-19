package modules

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/ssh"
)

const testServerBanner = "SSH-2.0-OpenSSH_9.6"

// sshNameList encodes an SSH name-list (RFC 4251 section 5).
func sshNameList(names string) []byte {
	b := make([]byte, 4+len(names))
	binary.BigEndian.PutUint32(b, uint32(len(names)))
	copy(b[4:], names)
	return b
}

// kexInitPacket returns an unencrypted SSH_MSG_KEXINIT binary packet
// (RFC 4253 sections 6 and 7.1) offering the given MAC algorithms.
func kexInitPacket(macs string) []byte {
	payload := make([]byte, 17, 256) // SSH_MSG_KEXINIT + 16-byte zero cookie
	payload[0] = 20
	for _, l := range []string{
		"curve25519-sha256", // kex_algorithms
		"ssh-ed25519",       // server_host_key_algorithms
		"aes128-ctr",        // encryption client to server
		"aes128-ctr",        // encryption server to client
		macs,                // mac client to server
		macs,                // mac server to client
		"none",              // compression client to server
		"none",              // compression server to client
		"",                  // languages client to server
		"",                  // languages server to client
	} {
		payload = append(payload, sshNameList(l)...)
	}
	payload = append(payload, 0, 0, 0, 0, 0) // first_kex_packet_follows, reserved

	// Pad so that packet_length+padding_length+payload+padding is a
	// multiple of 8, with at least 4 bytes of padding.
	padLen := 8 - (5+len(payload))%8
	if padLen < 4 {
		padLen += 8
	}
	pkt := make([]byte, 4, 5+len(payload)+padLen)
	binary.BigEndian.PutUint32(pkt, uint32(1+len(payload)+padLen))
	pkt = append(pkt, byte(padLen))
	pkt = append(pkt, payload...)
	return append(pkt, make([]byte, padLen)...)
}

// TestSSHHandshakeErrorPreservesPartialResult checks that when algorithm
// negotiation fails (here: the server offers only -etm MACs and the client
// is restricted to non-etm MACs), the scan still returns the HandshakeLog
// captured so far (server identification and KEXINIT) instead of nil.
func TestSSHHandshakeErrorPreservesPartialResult(t *testing.T) {
	// A real loopback socket: both peers send their identification string
	// at once, which deadlocks on an unbuffered net.Pipe.
	ln, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatal(listenErr)
	}
	defer ln.Close()

	go func() {
		serverConn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer serverConn.Close()
		_ = serverConn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := serverConn.Write([]byte(testServerBanner + "\r\n")); err != nil {
			return
		}
		// Consume the client's identification string, then send a KEXINIT
		// offering only -etm MACs and drain the client's KEXINIT until it
		// gives up on negotiation and closes the connection.
		r := bufio.NewReader(serverConn)
		if _, err := r.ReadString('\n'); err != nil {
			return
		}
		if _, err := serverConn.Write(kexInitPacket("hmac-sha2-256-etm@openssh.com")); err != nil {
			return
		}
		_, _ = r.WriteTo(io.Discard)
	}()

	scanner := &SSHScanner{config: &SSHFlags{
		BaseFlags:             zgrab2.BaseFlags{ConnectTimeout: 5 * time.Second},
		ClientID:              "SSH-2.0-Go",
		KexAlgorithms:         "curve25519-sha256",
		HostKeyAlgorithms:     "ssh-ed25519",
		Ciphers:               "aes128-ctr",
		MACs:                  "hmac-sha2-256",
		CompressionAlgorithms: "none",
	}}
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: 22}
	dialGroup := &zgrab2.DialerGroup{
		TransportAgnosticDialer: func(ctx context.Context, _ *zgrab2.ScanTarget) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", ln.Addr().String())
		},
	}

	status, result, err := scanner.Scan(context.Background(), dialGroup, target)
	if err == nil {
		t.Fatal("expected a handshake error")
	}
	if status != zgrab2.SCAN_HANDSHAKE_ERROR {
		t.Errorf("expected SCAN_HANDSHAKE_ERROR, got %s", status)
	}
	log, ok := result.(*ssh.HandshakeLog)
	if !ok || log == nil {
		t.Fatalf("expected non-nil *ssh.HandshakeLog, got %T", result)
	}
	if log.ServerID == nil || log.ServerID.Raw != testServerBanner {
		t.Errorf("server ID = %+v, want raw %q", log.ServerID, testServerBanner)
	}
	if log.ServerKex == nil {
		t.Error("expected server KEXINIT to be captured")
	}
}

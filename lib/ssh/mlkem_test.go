package ssh

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	upstream "golang.org/x/crypto/ssh"
)

func TestMLKEMClientRejectsMalformedReply(t *testing.T) {
	tests := []struct {
		name   string
		public []byte
		err    string
	}{
		{"empty", nil, "wrong length"},
		{"short", make([]byte, mlkem.CiphertextSize768+31), "wrong length"},
		{"long", make([]byte, mlkem.CiphertextSize768+33), "wrong length"},
		{"low-order-curve25519", make([]byte, mlkem.CiphertextSize768+32), "not valid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := memPipe()
			defer client.Close()
			defer server.Close()
			hostKey := testSigners["ecdsa"].PublicKey().Marshal()
			reply := &kexECDHReplyMsg{
				HostKey:         hostKey,
				EphemeralPubKey: tt.public,
				Signature:       []byte("signature"),
			}
			if err := server.writePacket(Marshal(reply)); err != nil {
				t.Fatal(err)
			}
			kex := new(mlkem768WithCurve25519sha256)
			if _, err := kex.Client(client, rand.Reader, &handshakeMagics{}, &Config{}); err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Fatalf("Client error = %v, want %q", err, tt.err)
			}
			if kex.JsonLog.ServerHostKey == nil || !bytes.Equal(kex.JsonLog.ServerHostKey.Raw, hostKey) {
				t.Error("missing partial server host key")
			}
			if !bytes.Equal(kex.JsonLog.Parameters.ServerPublic, tt.public) {
				t.Error("missing partial server public value")
			}
			if kex.JsonLog.ServerSignature == nil || !bytes.Equal(kex.JsonLog.ServerSignature.Raw, reply.Signature) {
				t.Error("missing partial server signature")
			}
		})
	}
}

func TestMLKEMServerRejectsMalformedInit(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	lowOrder := append(dk.EncapsulationKey().Bytes(), make([]byte, 32)...)
	invalidKey := bytes.Repeat([]byte{0xff}, mlkem.EncapsulationKeySize768+32)
	tests := []struct {
		name   string
		public []byte
		err    string
	}{
		{"empty", nil, "wrong length"},
		{"short", make([]byte, mlkem.EncapsulationKeySize768+31), "wrong length"},
		{"long", make([]byte, mlkem.EncapsulationKeySize768+33), "wrong length"},
		{"invalid-mlkem-key", invalidKey, "encapsulation key is not valid"},
		{"low-order-curve25519", lowOrder, "public value is not valid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := memPipe()
			defer client.Close()
			defer server.Close()
			if err := client.writePacket(Marshal(&kexECDHInitMsg{ClientPubKey: tt.public})); err != nil {
				t.Fatal(err)
			}
			kex := new(mlkem768WithCurve25519sha256)
			signer := testSigners["ecdsa"].(AlgorithmSigner)
			if _, err := kex.Server(server, rand.Reader, &handshakeMagics{}, signer, signer.PublicKey().Type(), &Config{}); err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Fatalf("Server error = %v, want %q", err, tt.err)
			}
		})
	}
}

func TestMLKEMClientEntropyFailure(t *testing.T) {
	for _, tt := range []struct {
		name string
		size int
	}{
		{"curve25519", 0},
		{"mlkem", 32},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, server := memPipe()
			defer client.Close()
			defer server.Close()
			kex := new(mlkem768WithCurve25519sha256)
			_, err := kex.Client(client, bytes.NewReader(make([]byte, tt.size)), &handshakeMagics{}, &Config{})
			if !errors.Is(err, io.EOF) {
				t.Fatalf("Client error = %v, want EOF from entropy reader", err)
			}
		})
	}
}

func TestMLKEMServerUpstreamInterop(t *testing.T) {
	serverSocket, clientSocket, err := netPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer serverSocket.Close()
	defer clientSocket.Close()
	for _, socket := range []net.Conn{serverSocket, clientSocket} {
		if err := socket.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}

	type serverResult struct {
		conn *ServerConn
		err  error
	}
	done := make(chan serverResult, 1)
	go func() {
		config := &ServerConfig{
			Config:       Config{KeyExchanges: []string{kexAlgoMLKEM768X25519SHA256}},
			NoClientAuth: true,
		}
		config.AddHostKey(testSigners["ecdsa"])
		conn, _, _, err := NewServerConn(serverSocket, config)
		done <- serverResult{conn, err}
	}()

	hostKey, err := upstream.ParsePublicKey(testSigners["ecdsa"].PublicKey().Marshal())
	if err != nil {
		t.Fatal(err)
	}
	config := &upstream.ClientConfig{
		Config:          upstream.Config{KeyExchanges: []string{kexAlgoMLKEM768X25519SHA256}},
		User:            "test",
		HostKeyCallback: upstream.FixedHostKey(hostKey),
	}
	client, _, _, err := upstream.NewClientConn(clientSocket, "", config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	defer result.conn.Close()
	if !bytes.Equal(client.SessionID(), result.conn.SessionID()) {
		t.Error("upstream client and fork server derived different session IDs")
	}
}

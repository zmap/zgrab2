package telnet

import (
	"net"
	"testing"
)

func FuzzGetIACIndex(f *testing.F) {
	// Seed: IAC WILL OPT sequence
	f.Add([]byte{0xFF, 0xFB, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = getIACIndex(data)
	})
}

func FuzzNegotiateOptions(f *testing.F) {
	// Seed: Plain banner with no IAC commands (causes immediate exit from negotiation loop)
	f.Add([]byte("Welcome\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		clientConn, serverConn := net.Pipe()
		done := make(chan struct{})

		go func() {
			defer close(done)
			defer serverConn.Close()
			// Send fuzz data then close write direction so NegotiateOptions
			// sees EOF instead of blocking forever on Read.
			serverConn.Write(data)
			// Use CloseWrite if available, otherwise just close.
			// net.Pipe returns *net.pipe which doesn't have CloseWrite,
			// so we close fully — NegotiateOptions will get an error on Read.
			serverConn.Close()
		}()

		logStruct := &TelnetLog{}
		_ = NegotiateOptions(logStruct, clientConn)
		clientConn.Close()
		<-done
	})
}

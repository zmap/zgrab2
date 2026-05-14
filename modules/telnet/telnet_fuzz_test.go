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
			// Send fuzz data immediately
			serverConn.Write(data)
			// Keep reading to drain any responses (ignore errors)
			buf := make([]byte, 1024)
			for {
				if _, err := serverConn.Read(buf); err != nil {
					break
				}
			}
		}()

		logStruct := &TelnetLog{}
		_ = NegotiateOptions(logStruct, clientConn)
		clientConn.Close()
		<-done
	})
}

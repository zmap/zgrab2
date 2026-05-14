package mssql

import (
	"net"
	"testing"
)

func FuzzReadPacket(f *testing.F) {
	// Seed with a valid TDS pre-login response packet
	// TDS packet header is 8 bytes: type(1), status(1), length(2, big-endian), SPID(2), packetID(1), window(1)
	// Followed by payload (if any)
	f.Add([]byte("\x04\x01\x00\x0b\x00\x00\x00\x00\x00\x00\x00"))
	
	// Seed with a minimal valid packet (just header, no payload)
	f.Add([]byte("\x04\x01\x00\x08\x00\x00\x00\x00"))
	
	// Seed with a packet with some payload
	f.Add([]byte("\x04\x01\x00\x10\x00\x00\x00\x00TESTDATA"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a pipe to feed fuzz data to the connection
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()

		// Create a tdsConnection with the client side
		tdsConn := &tdsConnection{
			conn:    clientConn,
			enabled: true,
			session: &Connection{}, // Initialize session to prevent nil pointer dereference
		}

		// Feed fuzz data from the server side in a goroutine
		go func() {
			serverConn.Write(data)
			serverConn.Close()
		}()

		// Try to read a packet - let any panics propagate
		tdsConn.ReadPacket()
	})
}

package pptp

import (
	"net"
	"testing"
)

func FuzzReadResponse(f *testing.F) {
	// Seed: valid PPTP response with magic cookie
	f.Add([]byte{
		0x00, 0x9c, // Length (156 bytes)
		0x00, 0x01, // PPTP Message Type
		0x1A, 0x2B, 0x3C, 0x4D, // Magic Cookie
		0x00, 0x02, // Control Message Type (Start-Control-Connection-Reply)
		0x00, 0x00, // Reserved
	})
	// Seed: minimal response
	f.Add([]byte{0x00, 0x08, 0x00, 0x01, 0x1A, 0x2B, 0x3C, 0x4D})

	f.Fuzz(func(t *testing.T, data []byte) {
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()

		conn := &Connection{
			conn: clientConn,
		}

		go func() {
			serverConn.Write(data)
			serverConn.Close()
		}()

		_, _, _ = conn.readResponse()
	})
}

func FuzzValidateMagicCookie(f *testing.F) {
	// Seed: 16+ bytes with PPTP magic cookie bytes
	f.Add([]byte{0x00, 0x10, 0x00, 0x01, 0x1A, 0x2B, 0x3C, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0x1A, 0x2B, 0x3C, 0x4D})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = validateMagicCookie(data)
	})
}

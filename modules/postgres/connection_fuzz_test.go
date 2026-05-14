package postgres

import (
	"net"
	"testing"

	"github.com/zmap/zgrab2"
)

func FuzzReadPacket(f *testing.F) {
	// Seed: Valid postgres packet - type 'R' (0x52) + length (8 bytes total) + 4 bytes body
	f.Add([]byte{0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		reader, writer := net.Pipe()
		go func() {
			writer.Write(data)
			writer.Close()
		}()

		conn := &Connection{
			Target:     &zgrab2.ScanTarget{},
			Connection: reader,
			Config:     &Flags{},
			IsSSL:      false,
		}

		_, _ = conn.ReadPacket()
		reader.Close()
	})
}

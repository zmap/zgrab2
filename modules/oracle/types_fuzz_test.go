package oracle

import (
	"bytes"
	"testing"
)

func FuzzReadTNSHeader(f *testing.F) {
	// Seed: 8-byte valid TNS header
	f.Add([]byte{
		0x00, 0x08, // Packet length (8 bytes)
		0x00, 0x00, // Packet checksum
		0x01,       // Packet type (CONNECT)
		0x00,       // Reserved byte
		0x00, 0x00, // Header checksum
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		driver := &TNSDriver{}
		driver.ReadTNSHeader(bytes.NewReader(data))
	})
}

func FuzzDecodeTNSDataNSN(f *testing.F) {
	// Seed: minimal valid NSN data
	f.Add([]byte{
		0xde, 0xad, 0xbe, 0xef, // Example NSN data
		0x00, 0x00, 0x00, 0x00,
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		DecodeTNSDataNSN(data)
	})
}

func FuzzDecodeDescriptor(f *testing.F) {
	// Seed: valid Oracle connection descriptor
	f.Add("(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=localhost)(PORT=1521))(CONNECT_DATA=(SID=ORCL)))")

	f.Fuzz(func(t *testing.T, data string) {
		DecodeDescriptor(data)
	})
}

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

func FuzzReadTNSPacket(f *testing.F) {
	// Seed: A valid TNS header followed by minimal body
	f.Add([]byte{
		0x00, 0x08, // Packet length (8 bytes)
		0x00, 0x00, // Packet checksum
		0x01,       // Packet type (CONNECT)
		0x00,       // Reserved byte
		0x00, 0x00, // Header checksum
	})
	// Seed: TNS ACCEPT packet
	f.Add([]byte{
		0x00, 0x0A, // Packet length (10 bytes)
		0x00, 0x00, // Packet checksum
		0x02,       // Packet type (ACCEPT)
		0x00,       // Reserved byte
		0x00, 0x00, // Header checksum
		0x00, 0x00, // Body
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		driver := &TNSDriver{}
		_, _ = driver.ReadTNSPacket(bytes.NewReader(data))
	})
}

func FuzzReadNSNService(f *testing.F) {
	// Seed: Some bytes representing an NSN service entry
	f.Add([]byte{
		0x00, 0x01, // Type (Authentication)
		0x00, 0x01, // Number of values
		0x00, 0x00, 0x00, 0x00, // Marker
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		ret := &NSNService{}
		_, _ = ReadNSNService(bytes.NewReader(data), ret)
	})
}

func FuzzReadNSNValue(f *testing.F) {
	// Seed: Some bytes
	f.Add([]byte{
		0x00, 0x04, // Size (4 bytes)
		0x00, 0x01, // Type (String)
		0x74, 0x65, 0x73, 0x74, // Value "test"
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		ret := &NSNValue{}
		_, _ = ReadNSNValue(bytes.NewReader(data), ret)
	})
}

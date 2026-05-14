package ntlm

import "testing"

func FuzzVersionFromBytes(f *testing.F) {
	// Seed: 8 bytes representing a valid version struct
	f.Add([]byte{0x0a, 0x00, 0x45, 0x51, 0x00, 0x00, 0x00, 0x0F})
	f.Add([]byte{0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0F})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = VersionFromBytes(data)
	})
}

func FuzzCleanString(f *testing.F) {
	// Seed: bytes with embedded nulls
	f.Add([]byte{'h', 'e', 'l', 'l', 'o', 0x00, 0x00})
	f.Add([]byte{0x00, 't', 'e', 's', 't', 0x00})
	f.Add([]byte{'a', 'b', 'c', 0x00, 'd', 'e', 'f'})

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = cleanString(data)
	})
}

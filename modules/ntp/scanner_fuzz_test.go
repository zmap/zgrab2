package ntp

import (
	"testing"
)

func FuzzDecodeNTPHeader(f *testing.F) {
	// Seed with a valid 48-byte NTP header
	// LI=0, VN=4, Mode=4 (server), Stratum=2, Poll=6, Precision=-20
	// Root Delay, Root Dispersion, Reference ID, and timestamps
	validHeader := make([]byte, 48)
	validHeader[0] = 0x24 // LI=0, VN=4, Mode=4
	validHeader[1] = 0x02 // Stratum=2
	validHeader[2] = 0x06 // Poll=6
	validHeader[3] = 0xEC // Precision=-20
	// Fill rest with some reasonable values
	for i := 4; i < 48; i++ {
		validHeader[i] = byte(i)
	}
	f.Add(validHeader)

	// Seed with a minimal valid header (different values)
	minimalHeader := make([]byte, 48)
	minimalHeader[0] = 0x1C // LI=0, VN=3, Mode=4
	f.Add(minimalHeader)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Let panics propagate
		decodeNTPHeader(data)
	})
}

func FuzzNTPShortDecode(f *testing.F) {
	// Seed with a valid 4-byte value
	f.Add([]byte{0x00, 0x01, 0x80, 0x00})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		var s NTPShort
		// Let panics propagate
		s.Decode(data)
	})
}

func FuzzNTPLongDecode(f *testing.F) {
	// Seed with a valid 8-byte value
	f.Add([]byte{0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Seed with a realistic NTP timestamp (seconds since 1900)
	f.Add([]byte{0xE4, 0x91, 0xC0, 0x00, 0x7F, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		var l NTPLong
		// Let panics propagate
		l.Decode(data)
	})
}

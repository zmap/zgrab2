package mysql

import "testing"

// FuzzReadHandshakePacket fuzzes the main MySQL handshake packet parser.
// It creates a minimal Connection and calls readHandshakePacket with arbitrary data.
func FuzzReadHandshakePacket(f *testing.F) {
	// Seed: minimal valid MySQL 5.7 handshake packet
	// Protocol version 10, server version "5.7.0\x00", thread ID, auth plugin data,
	// capabilities, charset, status flags, auth plugin name
	seed := []byte{
		0x0a,                               // protocol version 10
		0x35, 0x2e, 0x37, 0x2e, 0x30, 0x00, // "5.7.0\x00"
		0x01, 0x00, 0x00, 0x00, // thread ID (4 bytes)
		// auth-plugin-data-part-1 (8 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x00,       // filler
		0xff, 0xf7, // capability flags (lower 2 bytes)
		0x21,       // character set
		0x02, 0x00, // status flags
		0x0f, 0x80, // capability flags (upper 2 bytes)
		0x15,                                                       // auth plugin data length (21)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved (10 bytes)
		// auth-plugin-data-part-2 (12 bytes + NUL)
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x00,
		// auth plugin name
		0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00, // "mysql_native_password\x00"
	}
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		conn := &Connection{
			Config: &Config{},
		}
		_, _ = conn.readHandshakePacket(data)
	})
}

// FuzzReadLenInt fuzzes the length-encoded integer parser.
func FuzzReadLenInt(f *testing.F) {
	// Seed: single byte literal (< 0xFB)
	f.Add([]byte{0x00})
	f.Add([]byte{0x7f})
	f.Add([]byte{0xfa})

	// Seed: 0xFC + 2-byte integer
	f.Add([]byte{0xfc, 0x34, 0x12})

	// Seed: 0xFD + 3-byte integer
	f.Add([]byte{0xfd, 0x56, 0x34, 0x12})

	// Seed: 0xFE + 8-byte integer
	f.Add([]byte{0xfe, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = readLenInt(data)
	})
}

// FuzzReadLenString fuzzes the length-encoded string parser.
func FuzzReadLenString(f *testing.F) {
	// Seed: single-byte length + string
	f.Add([]byte{0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f}) // 0x05 + "hello"

	// Seed: 0xFC + 2-byte length + string
	seed2 := []byte{0xfc, 0x05, 0x00} // length = 5
	seed2 = append(seed2, []byte("world")...)
	f.Add(seed2)

	// Seed: empty string
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = readLenString(data)
	})
}

// FuzzReadNulString fuzzes the NUL-terminated string parser.
// Note: readNulString returns (string, []byte) with no error, so only panics are caught.
func FuzzReadNulString(f *testing.F) {
	// Seed: "hello\x00rest"
	f.Add([]byte{0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x72, 0x65, 0x73, 0x74})

	// Seed: empty string "\x00"
	f.Add([]byte{0x00})

	// Seed: string with no NUL terminator (edge case)
	f.Add([]byte{0x68, 0x65, 0x6c, 0x6c, 0x6f})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = readNulString(data)
	})
}

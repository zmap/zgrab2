package mysql

import (
	"encoding/binary"
	"strings"
	"testing"
)

// --- readNulString tests ---

func TestReadNulString_Valid(t *testing.T) {
	input := []byte("hello\x00world")
	str, rest, err := readNulString(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if str != "hello" {
		t.Errorf("expected 'hello', got %q", str)
	}
	if string(rest) != "world" {
		t.Errorf("expected 'world' remaining, got %q", string(rest))
	}
}

func TestReadNulString_EmptyString(t *testing.T) {
	input := []byte("\x00rest")
	str, rest, err := readNulString(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if str != "" {
		t.Errorf("expected empty string, got %q", str)
	}
	if string(rest) != "rest" {
		t.Errorf("expected 'rest' remaining, got %q", string(rest))
	}
}

func TestReadNulString_NoNulTerminator(t *testing.T) {
	input := []byte("no terminator")
	_, _, err := readNulString(input)
	if err == nil {
		t.Fatal("expected error for missing NUL terminator, got nil")
	}
}

func TestReadNulString_EmptyInput(t *testing.T) {
	_, _, err := readNulString([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
}

// --- readHandshakePacket tests ---

// buildMinimalHandshake creates a minimal valid MySQL handshake packet body.
func buildMinimalHandshake(serverVersion string) []byte {
	var buf []byte
	buf = append(buf, 0x0a) // protocol version
	buf = append(buf, []byte(serverVersion)...)
	buf = append(buf, 0x00) // NUL terminator
	// ConnectionID (4 bytes)
	connID := make([]byte, 4)
	binary.LittleEndian.PutUint32(connID, 42)
	buf = append(buf, connID...)
	// AuthPluginData1 (8 bytes)
	buf = append(buf, make([]byte, 8)...)
	// Filler1 (1 byte)
	buf = append(buf, 0x00)
	// CapabilityFlags lower 2 bytes
	capFlags := make([]byte, 2)
	binary.LittleEndian.PutUint16(capFlags, 0)
	buf = append(buf, capFlags...)
	return buf
}

func TestReadHandshakePacket_EmptyBody(t *testing.T) {
	c := &Connection{}
	_, err := c.readHandshakePacket([]byte{})
	if err == nil {
		t.Fatal("expected error for empty body, got nil")
	}
}

func TestReadHandshakePacket_NoNulInServerVersion(t *testing.T) {
	// ProtocolVersion byte followed by a string with no NUL
	body := []byte{0x0a}
	body = append(body, []byte("no-nul-terminator")...)
	c := &Connection{}
	_, err := c.readHandshakePacket(body)
	if err == nil {
		t.Fatal("expected error for missing NUL in ServerVersion, got nil")
	}
}

func TestReadHandshakePacket_TruncatedAfterServerVersion(t *testing.T) {
	// Valid protocol version and NUL-terminated server version, but rest is too short
	body := []byte{0x0a}
	body = append(body, []byte("5.7.0\x00")...)
	body = append(body, 0x01, 0x02) // only 2 bytes of rest, need 15
	c := &Connection{}
	_, err := c.readHandshakePacket(body)
	if err == nil {
		t.Fatal("expected error for truncated packet after ServerVersion, got nil")
	}
}

func TestReadHandshakePacket_MinimalValid(t *testing.T) {
	body := buildMinimalHandshake("5.7.0")
	c := &Connection{}
	pkt, err := c.readHandshakePacket(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkt.ProtocolVersion != 0x0a {
		t.Errorf("expected protocol version 0x0a, got 0x%02x", pkt.ProtocolVersion)
	}
	if pkt.ServerVersion != "5.7.0" {
		t.Errorf("expected server version '5.7.0', got %q", pkt.ServerVersion)
	}
	if pkt.ConnectionID != 42 {
		t.Errorf("expected connection ID 42, got %d", pkt.ConnectionID)
	}
	// With only 15 bytes of rest, it should be a short handshake
	if !pkt.ShortHandshake {
		t.Error("expected ShortHandshake=true for minimal packet")
	}
}

func TestReadHandshakePacket_LongServerVersionTruncatesRest(t *testing.T) {
	// A very long server version string that leaves rest too short
	longVersion := strings.Repeat("x", 200)
	body := []byte{0x0a}
	body = append(body, []byte(longVersion)...)
	body = append(body, 0x00) // NUL terminator
	body = append(body, 0x01) // only 1 byte of rest
	c := &Connection{}
	_, err := c.readHandshakePacket(body)
	if err == nil {
		t.Fatal("expected error for truncated rest after long ServerVersion, got nil")
	}
}

func TestReadHandshakePacket_AuthPluginDataLenUnderflow(t *testing.T) {
	// Build a full handshake with AuthPluginDataLen = 2 (< 8), which would
	// underflow in byte arithmetic: byte(2-8) = 250
	body := buildMinimalHandshake("5.7.0")
	// Extend rest to 31+ bytes to enter the non-short path
	// We need: 15 (already have) + 16 more = CharSet(1) + StatusFlags(2) + CapFlagsHigh(2) + AuthPluginDataLen(1) + Reserved(10) = 16
	body = append(body, 0x21)       // CharacterSet
	body = append(body, 0x00, 0x00) // StatusFlags
	capFlagsHigh := make([]byte, 2)
	binary.LittleEndian.PutUint16(capFlagsHigh, uint16(CLIENT_PLUGIN_AUTH>>16))
	body = append(body, capFlagsHigh...)     // CapabilityFlags high
	body = append(body, 2)                   // AuthPluginDataLen = 2 (< 8, triggers underflow in old code)
	body = append(body, make([]byte, 10)...) // Reserved

	c := &Connection{}
	pkt, err := c.readHandshakePacket(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With int arithmetic, part2Len = max(13, 2-8) = max(13, -6) = 13
	// But len(rest)-31 is small, so AuthPluginData2 should not be set
	// The key point: no panic from byte underflow
	if pkt.ShortHandshake {
		t.Error("expected ShortHandshake=false for extended packet")
	}
}

// --- readERRPacket tests ---

func TestReadERRPacket_TooShort(t *testing.T) {
	c := &Connection{}
	_, err := c.readERRPacket([]byte{0xff, 0x01})
	if err == nil {
		t.Fatal("expected error for 2-byte ERR packet, got nil")
	}
}

func TestReadERRPacket_MinimalValid(t *testing.T) {
	body := []byte{0xff, 0x48, 0x04} // header + error code 1096
	body = append(body, []byte("Access denied")...)
	c := &Connection{}
	pkt, err := c.readERRPacket(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkt.ErrorCode != 0x0448 {
		t.Errorf("expected error code 0x0448, got 0x%04x", pkt.ErrorCode)
	}
	if pkt.ErrorMessage != "Access denied" {
		t.Errorf("expected 'Access denied', got %q", pkt.ErrorMessage)
	}
}

func TestReadERRPacket_Protocol41TooShort(t *testing.T) {
	body := []byte{0xff, 0x48, 0x04, '#', 'H', 'Y'} // only 3 bytes after error code, need 6
	c := &Connection{}
	// Set up a handshake with CLIENT_PROTOCOL_41
	handshake := &HandshakePacket{CapabilityFlags: CLIENT_PROTOCOL_41}
	c.ConnectionLog.Handshake = &ConnectionLogEntry{
		Parsed: handshake,
	}
	_, err := c.readERRPacket(body)
	if err == nil {
		t.Fatal("expected error for truncated CLIENT_PROTOCOL_41 ERR packet, got nil")
	}
}

// --- readLenInt tests ---

func TestReadLenInt_0xfd_ExactlyFourBytes(t *testing.T) {
	// 0xfd followed by exactly 3 data bytes (4 total)
	body := []byte{0xfd, 0x01, 0x02, 0x03}
	val, rest, err := readLenInt(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := uint64(0x01) | uint64(0x02)<<8 | uint64(0x03)<<16
	if val != expected {
		t.Errorf("expected %d, got %d", expected, val)
	}
	if len(rest) != 0 {
		t.Errorf("expected empty rest, got %d bytes", len(rest))
	}
}

func TestReadLenInt_0xfd_TooShort(t *testing.T) {
	// 0xfd followed by only 2 bytes (need 3)
	body := []byte{0xfd, 0x01, 0x02}
	_, _, err := readLenInt(body)
	if err == nil {
		t.Fatal("expected error for truncated 0xfd LEN INT, got nil")
	}
}

func TestReadLenInt_0xfc_Valid(t *testing.T) {
	body := []byte{0xfc, 0x34, 0x12}
	val, rest, err := readLenInt(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 0x1234 {
		t.Errorf("expected 0x1234, got 0x%x", val)
	}
	if len(rest) != 0 {
		t.Errorf("expected empty rest, got %d bytes", len(rest))
	}
}

func TestReadLenInt_SingleByte(t *testing.T) {
	body := []byte{42, 0xff}
	val, rest, err := readLenInt(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 42 {
		t.Errorf("expected 42, got %d", val)
	}
	if len(rest) != 1 {
		t.Errorf("expected 1 byte rest, got %d", len(rest))
	}
}

func TestReadLenInt_Empty(t *testing.T) {
	_, _, err := readLenInt([]byte{})
	if err == nil {
		t.Fatal("expected error for empty body, got nil")
	}
}

// --- readLenString tests ---

func TestReadLenString_Valid(t *testing.T) {
	// length=5, then "hello", then "extra"
	body := []byte{5}
	body = append(body, []byte("hello")...)
	body = append(body, []byte("extra")...)
	str, rest, err := readLenString(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if str != "hello" {
		t.Errorf("expected 'hello', got %q", str)
	}
	if string(rest) != "extra" {
		t.Errorf("expected 'extra' remaining, got %q", string(rest))
	}
}

func TestReadLenString_ExactLength(t *testing.T) {
	// length=3, then "abc", no extra bytes
	body := []byte{3, 'a', 'b', 'c'}
	str, rest, err := readLenString(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if str != "abc" {
		t.Errorf("expected 'abc', got %q", str)
	}
	if len(rest) != 0 {
		t.Errorf("expected empty rest, got %d bytes: %q", len(rest), string(rest))
	}
}

func TestReadLenString_TooShort(t *testing.T) {
	// length=10 but only 3 bytes of data
	body := []byte{10, 'a', 'b', 'c'}
	_, _, err := readLenString(body)
	if err == nil {
		t.Fatal("expected error for truncated string, got nil")
	}
}

func TestReadLenString_Empty(t *testing.T) {
	_, _, err := readLenString([]byte{})
	if err == nil {
		t.Fatal("expected error for empty body, got nil")
	}
}

func TestReadLenString_ZeroLength(t *testing.T) {
	body := []byte{0, 'x', 'y'}
	str, rest, err := readLenString(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if str != "" {
		t.Errorf("expected empty string, got %q", str)
	}
	if string(rest) != "xy" {
		t.Errorf("expected 'xy' remaining, got %q", string(rest))
	}
}

package siemens

import (
	"encoding/binary"
	"testing"
)

// --- COTPDataPacket.Unmarshal tests ---

func TestCOTPDataUnmarshal_EmptyInput(t *testing.T) {
	pkt := &COTPDataPacket{}
	if err := pkt.Unmarshal([]byte{}); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestCOTPDataUnmarshal_HeaderSize0xFF_NoWrap(t *testing.T) {
	// headerSize=0xFF: old code did int(byte(0xFF)+1) = int(0) = 0, bypassing check.
	// With the fix, int(0xFF)+1 = 256, which exceeds len(bytes)=2.
	bytes := []byte{0xFF, 0x00}
	pkt := &COTPDataPacket{}
	if err := pkt.Unmarshal(bytes); err == nil {
		t.Fatal("expected error for headerSize=0xFF with 2-byte input")
	}
}

func TestCOTPDataUnmarshal_HeaderSizeExceedsLength(t *testing.T) {
	// headerSize=5 but only 3 bytes total
	bytes := []byte{0x05, 0xf0, 0x80}
	pkt := &COTPDataPacket{}
	if err := pkt.Unmarshal(bytes); err == nil {
		t.Fatal("expected error for headerSize exceeding packet length")
	}
}

func TestCOTPDataUnmarshal_ValidMinimal(t *testing.T) {
	// headerSize=2, then 2 header bytes, then data
	bytes := []byte{0x02, 0xf0, 0x80, 0xAA, 0xBB}
	pkt := &COTPDataPacket{}
	if err := pkt.Unmarshal(bytes); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkt.Data) != 2 || pkt.Data[0] != 0xAA || pkt.Data[1] != 0xBB {
		t.Errorf("expected data [0xAA, 0xBB], got %v", pkt.Data)
	}
}

func TestCOTPDataUnmarshal_HeaderSizeZero(t *testing.T) {
	// headerSize=0: data starts at bytes[1]
	bytes := []byte{0x00, 0xCC}
	pkt := &COTPDataPacket{}
	if err := pkt.Unmarshal(bytes); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkt.Data) != 1 || pkt.Data[0] != 0xCC {
		t.Errorf("expected data [0xCC], got %v", pkt.Data)
	}
}

func TestCOTPDataUnmarshal_HeaderConsumesAll(t *testing.T) {
	// headerSize=2, total length=3 → data is empty (bytes[3:] = [])
	bytes := []byte{0x02, 0xf0, 0x80}
	pkt := &COTPDataPacket{}
	if err := pkt.Unmarshal(bytes); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkt.Data) != 0 {
		t.Errorf("expected empty data, got %d bytes", len(pkt.Data))
	}
}

// --- S7Packet.Unmarshal tests ---

func buildS7Packet(pduType byte, paramLen, dataLen int) []byte {
	headerSize := 10
	if pduType == S7_ACKNOWLEDGEMENT || pduType == S7_RESPONSE {
		headerSize = 12
	}
	buf := make([]byte, headerSize+paramLen+dataLen)
	buf[0] = S7_PROTOCOL_ID
	buf[1] = pduType
	// bytes[2:4] reserved
	binary.BigEndian.PutUint16(buf[4:6], 0) // requestId
	binary.BigEndian.PutUint16(buf[6:8], uint16(paramLen))
	binary.BigEndian.PutUint16(buf[8:10], uint16(dataLen))
	if headerSize == 12 {
		binary.BigEndian.PutUint16(buf[10:12], 0) // error
	}
	return buf
}

func TestS7Unmarshal_EmptyInput(t *testing.T) {
	pkt := &S7Packet{}
	if err := pkt.Unmarshal([]byte{}); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestS7Unmarshal_TooShortForHeader(t *testing.T) {
	// Only 5 bytes — not enough for even a request header (10 bytes)
	pkt := &S7Packet{}
	if err := pkt.Unmarshal([]byte{S7_PROTOCOL_ID, S7_REQUEST, 0, 0, 0}); err == nil {
		t.Fatal("expected error for 5-byte packet")
	}
}

func TestS7Unmarshal_TooShortForAckHeader(t *testing.T) {
	// 10 bytes — enough for request (10) but not ACK (12)
	buf := make([]byte, 10)
	buf[0] = S7_PROTOCOL_ID
	buf[1] = S7_RESPONSE
	pkt := &S7Packet{}
	if err := pkt.Unmarshal(buf); err == nil {
		t.Fatal("expected error for 10-byte ACK packet (needs 12)")
	}
}

func TestS7Unmarshal_NotS7Protocol(t *testing.T) {
	buf := make([]byte, 12)
	buf[0] = 0x99 // wrong protocol ID
	pkt := &S7Packet{}
	if err := pkt.Unmarshal(buf); err != errNotS7 {
		t.Fatalf("expected errNotS7, got %v", err)
	}
}

func TestS7Unmarshal_UnknownPDUType(t *testing.T) {
	buf := make([]byte, 12)
	buf[0] = S7_PROTOCOL_ID
	buf[1] = 0xEE // unknown PDU type
	pkt := &S7Packet{}
	if err := pkt.Unmarshal(buf); err == nil {
		t.Fatal("expected error for unknown PDU type")
	}
}

func TestS7Unmarshal_ValidRequest(t *testing.T) {
	buf := buildS7Packet(S7_REQUEST, 4, 2)
	// Fill param and data areas
	copy(buf[10:14], []byte{0x01, 0x02, 0x03, 0x04})
	copy(buf[14:16], []byte{0xAA, 0xBB})

	pkt := &S7Packet{}
	if err := pkt.Unmarshal(buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkt.PDUType != S7_REQUEST {
		t.Errorf("expected PDU type 0x%02x, got 0x%02x", S7_REQUEST, pkt.PDUType)
	}
	if len(pkt.Parameters) != 4 {
		t.Errorf("expected 4 param bytes, got %d", len(pkt.Parameters))
	}
	if len(pkt.Data) != 2 {
		t.Errorf("expected 2 data bytes, got %d", len(pkt.Data))
	}
}

func TestS7Unmarshal_ValidResponse(t *testing.T) {
	buf := buildS7Packet(S7_RESPONSE, 0, 0)
	binary.BigEndian.PutUint16(buf[10:12], 0x1234) // error field

	pkt := &S7Packet{}
	if err := pkt.Unmarshal(buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkt.Error != 0x1234 {
		t.Errorf("expected error 0x1234, got 0x%04x", pkt.Error)
	}
}

func TestS7Unmarshal_ParamLengthExceedsPacket(t *testing.T) {
	buf := buildS7Packet(S7_REQUEST, 0, 0)
	// Claim paramLength=100 but packet is only 10 bytes
	binary.BigEndian.PutUint16(buf[6:8], 100)

	pkt := &S7Packet{}
	if err := pkt.Unmarshal(buf); err == nil {
		t.Fatal("expected error for paramLength exceeding packet")
	}
}

func TestS7Unmarshal_DataLengthExceedsPacket(t *testing.T) {
	buf := buildS7Packet(S7_REQUEST, 0, 0)
	// Claim dataLength=50 but no extra data
	binary.BigEndian.PutUint16(buf[8:10], 50)

	pkt := &S7Packet{}
	if err := pkt.Unmarshal(buf); err == nil {
		t.Fatal("expected error for dataLength exceeding packet")
	}
}

func TestS7Unmarshal_SingleBytePacket(t *testing.T) {
	// 1 byte: passes old len<1 check but should fail new len<10 check
	pkt := &S7Packet{}
	if err := pkt.Unmarshal([]byte{S7_PROTOCOL_ID}); err == nil {
		t.Fatal("expected error for 1-byte packet")
	}
}

// --- TPKTPacket.Unmarshal tests ---

func TestTPKTUnmarshal_TooShort(t *testing.T) {
	pkt := &TPKTPacket{}
	if err := pkt.Unmarshal([]byte{0x03, 0x00}); err == nil {
		t.Fatal("expected error for 2-byte TPKT")
	}
}

func TestTPKTUnmarshal_ValidMinimal(t *testing.T) {
	buf := []byte{0x03, 0x00, 0x00, 0x05, 0xFF}
	pkt := &TPKTPacket{}
	if err := pkt.Unmarshal(buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkt.Data) != 1 || pkt.Data[0] != 0xFF {
		t.Errorf("expected data [0xFF], got %v", pkt.Data)
	}
}

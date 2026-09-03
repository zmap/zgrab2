package msmq

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// makeEstablishConnectionResponse synthesizes an EstablishConnection Packet
// as an acceptor would send it, mirroring buildEstablishConnection's layout.
func makeEstablishConnectionResponse(clientGUID, serverGUID [16]byte, timeStamp uint32, refused bool, paddingByte byte) []byte {
	pkt := make([]byte, establishConnectionPacketLen)

	pkt[0] = baseHeaderVersion
	pkt[1] = 0
	binary.LittleEndian.PutUint16(pkt[2:4], baseFlagsPriorityDefault|baseFlagsIN)
	binary.LittleEndian.PutUint32(pkt[4:8], baseHeaderSignature)
	binary.LittleEndian.PutUint32(pkt[8:12], establishConnectionPacketLen)
	binary.LittleEndian.PutUint32(pkt[12:16], 0xFFFFFFFF)

	internalFlags := uint16(internalPacketTypeEstablishConnection)
	if refused {
		internalFlags |= internalFlagsCS
	}
	binary.LittleEndian.PutUint16(pkt[16:18], 0)
	binary.LittleEndian.PutUint16(pkt[18:20], internalFlags)

	off := 20
	copy(pkt[off:off+16], clientGUID[:])
	off += 16
	copy(pkt[off:off+16], serverGUID[:])
	off += 16
	binary.LittleEndian.PutUint32(pkt[off:off+4], timeStamp)
	off += 4
	off += 4 // OperatingSystem + Reserved, left zero

	for i := off; i < len(pkt); i++ {
		pkt[i] = paddingByte
	}
	return pkt
}

func TestFormatGUIDRoundTrip(t *testing.T) {
	// e1af8308-5d1f-11c9-91a4-08002b14a0fa wire-encoded, reused from the
	// well-known DCE/RPC endpoint mapper UUID since the wire layout is
	// identical to an MS-DTYP GUID.
	wire := [16]byte{0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa}
	got := formatGUID(wire)
	want := "e1af8308-5d1f-11c9-91a4-08002b14a0fa"
	if got != want {
		t.Errorf("formatGUID = %q, want %q", got, want)
	}
}

func TestBuildEstablishConnection(t *testing.T) {
	var clientGUID, serverGUID [16]byte
	pkt := buildEstablishConnection(clientGUID, serverGUID, 0x1234)

	if len(pkt) != establishConnectionPacketLen {
		t.Fatalf("packet length = %d, want %d", len(pkt), establishConnectionPacketLen)
	}
	if pkt[0] != baseHeaderVersion {
		t.Errorf("VersionNumber = 0x%02x, want 0x%02x", pkt[0], baseHeaderVersion)
	}
	if flags := binary.LittleEndian.Uint16(pkt[2:4]); flags != baseFlagsPriorityDefault|baseFlagsIN {
		t.Errorf("BaseHeader.Flags = 0x%04x, want IN bit + default priority (0x%04x)", flags, baseFlagsPriorityDefault|baseFlagsIN)
	}
	if sig := binary.LittleEndian.Uint32(pkt[4:8]); sig != baseHeaderSignature {
		t.Errorf("Signature = 0x%08x, want 0x%08x", sig, baseHeaderSignature)
	}
	if size := binary.LittleEndian.Uint32(pkt[8:12]); size != establishConnectionPacketLen {
		t.Errorf("PacketSize = %d, want %d", size, establishConnectionPacketLen)
	}
	if ttrq := binary.LittleEndian.Uint32(pkt[12:16]); ttrq != 0xFFFFFFFF {
		t.Errorf("TimeToReachQueue = 0x%x, want 0xFFFFFFFF", ttrq)
	}
	if internalFlags := binary.LittleEndian.Uint16(pkt[18:20]); internalFlags&0x000F != internalPacketTypeEstablishConnection {
		t.Errorf("InternalHeader.Flags.PT = 0x%x, want 0x%x", internalFlags&0x000F, internalPacketTypeEstablishConnection)
	}
	if ts := binary.LittleEndian.Uint32(pkt[52:56]); ts != 0x1234 {
		t.Errorf("TimeStamp = 0x%x, want 0x1234", ts)
	}
}

func TestParseEstablishConnectionAccepted(t *testing.T) {
	clientGUID := [16]byte{0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa}
	var serverGUID [16]byte
	pkt := makeEstablishConnectionResponse(clientGUID, serverGUID, 42, false, responsePaddingByte)

	res, err := parseEstablishConnection(pkt)
	if err != nil {
		t.Fatalf("parseEstablishConnection failed: %v", err)
	}
	if res.Refused {
		t.Error("Refused = true, want false")
	}
	if !res.PaddingMatchesResponse {
		t.Error("PaddingMatchesResponse = false, want true")
	}
	if res.TimeStamp != 42 {
		t.Errorf("TimeStamp = %d, want 42", res.TimeStamp)
	}
	if got := formatGUID(res.ClientGUID); got != "e1af8308-5d1f-11c9-91a4-08002b14a0fa" {
		t.Errorf("ClientGUID = %q", got)
	}
}

func TestParseEstablishConnectionRefused(t *testing.T) {
	var clientGUID, serverGUID [16]byte
	pkt := makeEstablishConnectionResponse(clientGUID, serverGUID, 0, true, responsePaddingByte)

	res, err := parseEstablishConnection(pkt)
	if err != nil {
		t.Fatalf("parseEstablishConnection failed: %v", err)
	}
	if !res.Refused {
		t.Error("Refused = false, want true")
	}
}

func TestParseEstablishConnectionNonServerPadding(t *testing.T) {
	var clientGUID, serverGUID [16]byte
	pkt := makeEstablishConnectionResponse(clientGUID, serverGUID, 0, false, 0x00)

	res, err := parseEstablishConnection(pkt)
	if err != nil {
		t.Fatalf("parseEstablishConnection failed: %v", err)
	}
	if res.PaddingMatchesResponse {
		t.Error("PaddingMatchesResponse = true, want false for non-0x5A padding")
	}
}

func TestParseEstablishConnectionErrors(t *testing.T) {
	var clientGUID, serverGUID [16]byte
	valid := makeEstablishConnectionResponse(clientGUID, serverGUID, 0, false, responsePaddingByte)

	t.Run("too short", func(t *testing.T) {
		if _, err := parseEstablishConnection(valid[:establishConnectionPacketLen-1]); err == nil {
			t.Error("accepted truncated packet")
		}
	})

	t.Run("bad version", func(t *testing.T) {
		bad := append([]byte(nil), valid...)
		bad[0] = 0x11
		if _, err := parseEstablishConnection(bad); err == nil {
			t.Error("accepted bad VersionNumber")
		}
	})

	t.Run("bad signature", func(t *testing.T) {
		bad := append([]byte(nil), valid...)
		binary.LittleEndian.PutUint32(bad[4:8], 0xDEADBEEF)
		if _, err := parseEstablishConnection(bad); err == nil {
			t.Error("accepted bad Signature")
		}
	})

	t.Run("wrong packet type", func(t *testing.T) {
		bad := append([]byte(nil), valid...)
		binary.LittleEndian.PutUint16(bad[18:20], uint16(internalPacketTypeSessionAckForTest))
		if _, err := parseEstablishConnection(bad); err == nil {
			t.Error("accepted wrong InternalHeader packet type")
		}
	})
}

// internalPacketTypeSessionAckForTest mirrors [MS-MQQB] 2.2.1's SessionAck
// packet type (0x1), used only to construct a negative test case.
const internalPacketTypeSessionAckForTest = 0x1

// TestLive performs a real scan against an MSMQ queue manager. Set
// MSMQ_LIVE_TARGET to an "ip:port" (e.g. 192.168.1.10:1801) to enable it.
func TestLive(t *testing.T) {
	target := os.Getenv("MSMQ_LIVE_TARGET")
	if target == "" {
		t.Skip("set MSMQ_LIVE_TARGET=ip:port to run the live test")
	}
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var clientGUID, serverGUID [16]byte
	if _, err = conn.Write(buildEstablishConnection(clientGUID, serverGUID, 0)); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp := make([]byte, establishConnectionPacketLen)
	if _, err = io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read: %v", err)
	}
	res, err := parseEstablishConnection(resp)
	if err != nil {
		t.Fatalf("parseEstablishConnection: %v", err)
	}
	t.Logf("refused=%v client_guid=%s server_guid=%s padding_matches=%v",
		res.Refused, formatGUID(res.ClientGUID), formatGUID(res.ServerGUID), res.PaddingMatchesResponse)
}

package gesrtp

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func makeInitResponse(valid bool) []byte {
	resp := make([]byte, headerLen)
	if valid {
		resp[0] = initAckByte
		resp[8] = protocolIDByte
	}
	return resp
}

func makeControllerTypeResponse(svcEcho byte, deviceIndicator byte, plcName string) []byte {
	payload := make([]byte, ctrlPayloadMaxLen)
	payload[ctrlSvcEchoOffset] = svcEcho
	payload[ctrlDeviceIndicatorOffset] = deviceIndicator
	copy(payload[ctrlPLCNameOffset:ctrlPLCNameOffset+ctrlPLCNameLen], plcName)

	header := make([]byte, headerLen, headerLen+len(payload))
	binary.LittleEndian.PutUint16(header[textLengthOffset:textLengthOffset+2], uint16(len(payload)))
	return append(header, payload...)
}

func TestBuildInitPacket(t *testing.T) {
	pkt := buildInitPacket()
	if len(pkt) != headerLen {
		t.Fatalf("len = %d, want %d", len(pkt), headerLen)
	}
	for i, b := range pkt {
		if b != 0 {
			t.Errorf("byte %d = 0x%02x, want 0x00", i, b)
		}
	}
}

func TestValidateInitResponse(t *testing.T) {
	if !validateInitResponse(makeInitResponse(true)) {
		t.Error("valid Init response rejected")
	}
	if validateInitResponse(makeInitResponse(false)) {
		t.Error("invalid Init response accepted")
	}
	if validateInitResponse(make([]byte, headerLen-1)) {
		t.Error("truncated Init response accepted")
	}
}

// TestExtractGEBannerRealWorld uses the exact Init response bytes observed
// from a live, internet-facing PACSystems RX7i (IC698CPE020) during
// accuracy validation of this module: a non-standard ack byte (0x06, not
// 0x01) followed directly by a plaintext model/firmware/serial string.
func TestExtractGEBannerRealWorld(t *testing.T) {
	resp := []byte("\x06\x00\x00\x00\x001PACSystems RX7i IC698CPE020 FW:9.50 SN:GE9706AF73\x06\x00\x00\x00\x00")
	if validateInitResponse(resp) {
		t.Fatal("expected the standard ack check to reject this non-standard response")
	}
	banner, ok := extractGEBanner(resp)
	if !ok {
		t.Fatal("extractGEBanner did not recognize a real-world PACSystems banner")
	}
	if !strings.Contains(banner, "PACSystems RX7i") {
		t.Errorf("banner = %q, want it to contain %q", banner, "PACSystems RX7i")
	}
}

func TestExtractGEBannerNoMatch(t *testing.T) {
	if _, ok := extractGEBanner([]byte("HTTP/1.1 400 Bad Request\r\n")); ok {
		t.Error("unrelated HTTP response was accepted as a GE banner")
	}
	if _, ok := extractGEBanner(make([]byte, 56)); ok {
		t.Error("all-zero response was accepted as a GE banner")
	}
}

func TestValidateScadaEnableResponse(t *testing.T) {
	if !validateScadaEnableResponse([]byte{packetTypeReturn, 0, 0}) {
		t.Error("valid SCADA Enable response rejected")
	}
	if validateScadaEnableResponse([]byte{0x02, 0, 0}) {
		t.Error("wrong packet type accepted")
	}
	if validateScadaEnableResponse(nil) {
		t.Error("empty response accepted")
	}
}

func TestControllerTypePayloadLen(t *testing.T) {
	header := make([]byte, headerLen)
	binary.LittleEndian.PutUint16(header[textLengthOffset:textLengthOffset+2], 40)
	n, err := controllerTypePayloadLen(header)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 40 {
		t.Errorf("payload len = %d, want 40", n)
	}

	tooLong := make([]byte, headerLen)
	binary.LittleEndian.PutUint16(tooLong[textLengthOffset:textLengthOffset+2], 41)
	if _, err := controllerTypePayloadLen(tooLong); err == nil {
		t.Error("declared length exceeding max was accepted")
	}

	if _, err := controllerTypePayloadLen(make([]byte, headerLen-1)); err == nil {
		t.Error("truncated header was accepted")
	}
}

func TestParseControllerTypeResponse(t *testing.T) {
	full := makeControllerTypeResponse(svcReturnControllerType, 0x05, "RX3I")
	info, ok := parseControllerTypeResponse(full)
	if !ok {
		t.Fatal("parseControllerTypeResponse returned ok=false")
	}
	if info.PLCName != "RX3I" {
		t.Errorf("PLCName = %q, want %q", info.PLCName, "RX3I")
	}
	if !info.HasDevice || info.DeviceIndicator != 0x05 {
		t.Errorf("DeviceIndicator = %v (has=%v), want 0x05", info.DeviceIndicator, info.HasDevice)
	}
}

func TestParseControllerTypeResponseBadEcho(t *testing.T) {
	full := makeControllerTypeResponse(0xFF, 0x05, "RX3I")
	if _, ok := parseControllerTypeResponse(full); ok {
		t.Error("response with mismatched service echo was accepted")
	}
}

func TestParseControllerTypeResponseTooShort(t *testing.T) {
	if _, ok := parseControllerTypeResponse(make([]byte, headerLen)); ok {
		t.Error("header-only response (no payload) was accepted")
	}
}

func TestNullTerminatedASCII(t *testing.T) {
	if got := nullTerminatedASCII([]byte("RX3I\x00\x00\x00\x00")); got != "RX3I" {
		t.Errorf("got %q, want %q", got, "RX3I")
	}
	if got := nullTerminatedASCII([]byte("ABCDEFGH")); got != "ABCDEFGH" {
		t.Errorf("got %q, want %q", got, "ABCDEFGH")
	}
}

// TestLive performs a real scan against a GE SRTP device. Set
// GESRTP_LIVE_TARGET to an "ip:port" (e.g. 192.168.1.10:18245) to enable it.
func TestLive(t *testing.T) {
	target := os.Getenv("GESRTP_LIVE_TARGET")
	if target == "" {
		t.Skip("set GESRTP_LIVE_TARGET=ip:port to run the live test")
	}
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err = conn.Write(buildInitPacket()); err != nil {
		t.Fatalf("write init: %v", err)
	}
	initResp := make([]byte, headerLen)
	if _, err = io.ReadFull(conn, initResp); err != nil {
		t.Fatalf("read init response: %v", err)
	}
	if !validateInitResponse(initResp) {
		t.Fatalf("not a valid GE SRTP Init response: %x", initResp)
	}
	t.Logf("Init OK, response: %x", initResp)

	if _, err = conn.Write(scadaEnablePacket); err != nil {
		t.Fatalf("write scada enable: %v", err)
	}
	scadaResp := make([]byte, headerLen)
	if _, err = io.ReadFull(conn, scadaResp); err != nil {
		t.Fatalf("read scada enable response: %v", err)
	}
	t.Logf("SCADA Enable acknowledged: %v", validateScadaEnableResponse(scadaResp))

	if _, err = conn.Write(returnControllerTypePacket); err != nil {
		t.Fatalf("write return controller type: %v", err)
	}
	ctrlHeader := make([]byte, headerLen)
	if _, err = io.ReadFull(conn, ctrlHeader); err != nil {
		t.Fatalf("read controller type header: %v", err)
	}
	payloadLen, err := controllerTypePayloadLen(ctrlHeader)
	if err != nil {
		t.Fatalf("controllerTypePayloadLen: %v", err)
	}
	full := ctrlHeader
	if payloadLen > 0 {
		payload := make([]byte, payloadLen)
		if _, err = io.ReadFull(conn, payload); err != nil {
			t.Fatalf("read controller type payload: %v", err)
		}
		full = append(full, payload...)
	}
	if info, ok := parseControllerTypeResponse(full); ok {
		t.Logf("PLCName=%q DeviceIndicator=%v", info.PLCName, info.DeviceIndicator)
	} else {
		t.Log("no controller type enrichment available")
	}
}

package msrpc

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"
)

// makeBindAck synthesizes a bind_ack PDU with the given field values, mirroring
// the wire format documented in msrpc.go's parseBindAck.
func makeBindAck(callID uint32, maxXmit, maxRecv uint16, assocGroup uint32, secAddr string, resultCode, reason uint16, transferUUID [16]byte, verMajor, verMinor uint16) []byte {
	var body []byte
	var b2 [2]byte
	binary.LittleEndian.PutUint16(b2[:], maxXmit)
	body = append(body, b2[:]...)
	binary.LittleEndian.PutUint16(b2[:], maxRecv)
	body = append(body, b2[:]...)
	var b4 [4]byte
	binary.LittleEndian.PutUint32(b4[:], assocGroup)
	body = append(body, b4[:]...)

	var secBytes []byte
	if secAddr != "" {
		secBytes = append([]byte(secAddr), 0) // NUL-terminated
	}
	binary.LittleEndian.PutUint16(b2[:], uint16(len(secBytes)))
	body = append(body, b2[:]...)
	body = append(body, secBytes...)

	for (commonHeaderLen+len(body))%4 != 0 {
		body = append(body, 0)
	}

	body = append(body, 1, 0, 0, 0) // n_results=1, reserved, reserved2
	binary.LittleEndian.PutUint16(b2[:], resultCode)
	body = append(body, b2[:]...)
	binary.LittleEndian.PutUint16(b2[:], reason)
	body = append(body, b2[:]...)
	body = appendSyntaxID(body, transferUUID, verMajor, verMinor)

	header := make([]byte, commonHeaderLen)
	header[0] = rpcVersionMajor
	header[1] = rpcVersionMinor
	header[2] = ptypeBindAck
	header[3] = pfcFirstFrag | pfcLastFrag
	copy(header[4:8], packedDrepLE[:])
	binary.LittleEndian.PutUint16(header[8:10], uint16(commonHeaderLen+len(body)))
	binary.LittleEndian.PutUint32(header[12:16], callID)
	return append(header, body...)
}

func makeBindNak(callID uint32, reason uint16) []byte {
	body := make([]byte, 2)
	binary.LittleEndian.PutUint16(body, reason)

	header := make([]byte, commonHeaderLen)
	header[0] = rpcVersionMajor
	header[1] = rpcVersionMinor
	header[2] = ptypeBindNak
	header[3] = pfcFirstFrag | pfcLastFrag
	copy(header[4:8], packedDrepLE[:])
	binary.LittleEndian.PutUint16(header[8:10], uint16(commonHeaderLen+len(body)))
	binary.LittleEndian.PutUint32(header[12:16], callID)
	return append(header, body...)
}

func TestParseUUIDFormatUUIDRoundTrip(t *testing.T) {
	wire, err := parseUUID(EPMUUID)
	if err != nil {
		t.Fatalf("parseUUID(%q) failed: %v", EPMUUID, err)
	}
	got := formatUUID(wire[:])
	if got != EPMUUID {
		t.Errorf("formatUUID(parseUUID(%q)) = %q, want %q", EPMUUID, got, EPMUUID)
	}
}

func TestParseUUIDInvalid(t *testing.T) {
	for _, s := range []string{"", "not-a-uuid", "e1af8308-5d1f-11c9-91a4-08002b14a0f"} {
		if _, err := parseUUID(s); err == nil {
			t.Errorf("parseUUID(%q) succeeded, want error", s)
		}
	}
}

func TestBuildBind(t *testing.T) {
	abstractUUID, err := parseUUID(EPMUUID)
	if err != nil {
		t.Fatalf("parseUUID failed: %v", err)
	}
	pkt := buildBind(0x2a, 4280, abstractUUID, EPMVersionMajor, EPMVersionMinor)

	if len(pkt) != int(binary.LittleEndian.Uint16(pkt[8:10])) {
		t.Fatalf("frag_length %d != actual packet length %d", binary.LittleEndian.Uint16(pkt[8:10]), len(pkt))
	}
	if pkt[0] != rpcVersionMajor || pkt[1] != rpcVersionMinor {
		t.Errorf("rpc version = %d.%d, want %d.%d", pkt[0], pkt[1], rpcVersionMajor, rpcVersionMinor)
	}
	if pkt[2] != ptypeBind {
		t.Errorf("ptype = %d, want %d (bind)", pkt[2], ptypeBind)
	}
	if callID := binary.LittleEndian.Uint32(pkt[12:16]); callID != 0x2a {
		t.Errorf("call_id = %d, want 42", callID)
	}
	// The abstract syntax UUID should appear verbatim in the context element.
	abstractOffset := commonHeaderLen + 12 + 4 // header + fixed bind fields (12) + p_cont_id/n_transfer_syn/reserved (4)
	if got := pkt[abstractOffset : abstractOffset+16]; formatUUID(got) != EPMUUID {
		t.Errorf("abstract syntax UUID = %s, want %s", formatUUID(got), EPMUUID)
	}
}

func TestParseBindAckAccepted(t *testing.T) {
	transferUUID, _ := parseUUID(ndrUUID)
	pkt := makeBindAck(7, 4280, 4280, 0x1234, "", resultAcceptance, 0, transferUUID, ndrVersionMajor, ndrVersionMinor)

	hdr, err := parseCommonHeader(pkt)
	if err != nil {
		t.Fatalf("parseCommonHeader failed: %v", err)
	}
	if hdr.PType != ptypeBindAck {
		t.Fatalf("PType = %d, want bind_ack (%d)", hdr.PType, ptypeBindAck)
	}
	ack, err := parseBindAck(pkt)
	if err != nil {
		t.Fatalf("parseBindAck failed: %v", err)
	}
	if ack.ResultCode != resultAcceptance {
		t.Errorf("ResultCode = %d, want acceptance", ack.ResultCode)
	}
	if ack.AssocGroupID != 0x1234 {
		t.Errorf("AssocGroupID = 0x%x, want 0x1234", ack.AssocGroupID)
	}
	if ack.TransferSyntaxUUID != ndrUUID {
		t.Errorf("TransferSyntaxUUID = %q, want %q", ack.TransferSyntaxUUID, ndrUUID)
	}
	if ack.TransferSyntaxVerMajor != ndrVersionMajor || ack.TransferSyntaxVerMinor != ndrVersionMinor {
		t.Errorf("TransferSyntax version = %d.%d, want %d.%d", ack.TransferSyntaxVerMajor, ack.TransferSyntaxVerMinor, ndrVersionMajor, ndrVersionMinor)
	}
}

// TestParseBindAckWithSecondaryAddress exercises the alignment-padding logic
// for a non-empty (odd-length) secondary address string.
func TestParseBindAckWithSecondaryAddress(t *testing.T) {
	transferUUID, _ := parseUUID(ndrUUID)
	pkt := makeBindAck(1, 4280, 4280, 0, "445", resultAcceptance, 0, transferUUID, ndrVersionMajor, ndrVersionMinor)

	ack, err := parseBindAck(pkt)
	if err != nil {
		t.Fatalf("parseBindAck failed: %v", err)
	}
	if ack.SecondaryAddress != "445" {
		t.Errorf("SecondaryAddress = %q, want %q", ack.SecondaryAddress, "445")
	}
	if ack.ResultCode != resultAcceptance {
		t.Errorf("ResultCode = %d, want acceptance", ack.ResultCode)
	}
}

func TestParseBindAckProviderRejection(t *testing.T) {
	var zeroUUID [16]byte
	pkt := makeBindAck(1, 4280, 4280, 0, "", resultProviderRejection, 2, zeroUUID, 0, 0)

	ack, err := parseBindAck(pkt)
	if err != nil {
		t.Fatalf("parseBindAck failed: %v", err)
	}
	if ack.ResultCode != resultProviderRejection {
		t.Errorf("ResultCode = %d, want provider_rejection", ack.ResultCode)
	}
	if ack.RejectReason != 2 {
		t.Errorf("RejectReason = %d, want 2", ack.RejectReason)
	}
	if got := rejectReasonName(ack.RejectReason); got != "proposed_transfer_syntaxes_not_supported" {
		t.Errorf("rejectReasonName(2) = %q", got)
	}
}

func TestParseBindNak(t *testing.T) {
	pkt := makeBindNak(3, 1)
	hdr, err := parseCommonHeader(pkt)
	if err != nil {
		t.Fatalf("parseCommonHeader failed: %v", err)
	}
	if hdr.PType != ptypeBindNak {
		t.Fatalf("PType = %d, want bind_nak (%d)", hdr.PType, ptypeBindNak)
	}
	nak, err := parseBindNak(pkt)
	if err != nil {
		t.Fatalf("parseBindNak failed: %v", err)
	}
	if nak.RejectReason != 1 {
		t.Errorf("RejectReason = %d, want 1", nak.RejectReason)
	}
	if got := rejectReasonName(nak.RejectReason); got != "abstract_syntax_not_supported" {
		t.Errorf("rejectReasonName(1) = %q, want %q", got, "abstract_syntax_not_supported")
	}
}

func TestParseCommonHeaderErrors(t *testing.T) {
	cases := map[string][]byte{
		"too short":             {5, 0, 12, 3},
		"wrong rpc version":     {4, 0, 12, 3, 0x10, 0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0},
		"frag_length too small": {5, 0, 12, 3, 0x10, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0},
	}
	for name, data := range cases {
		if _, err := parseCommonHeader(data); err == nil {
			t.Errorf("%s: parseCommonHeader accepted invalid header", name)
		}
	}
}

// TestLive performs a real scan against an MSRPC endpoint mapper. Set
// MSRPC_LIVE_TARGET to an "ip:port" (e.g. 192.168.1.10:135) to enable it.
func TestLive(t *testing.T) {
	target := os.Getenv("MSRPC_LIVE_TARGET")
	if target == "" {
		t.Skip("set MSRPC_LIVE_TARGET=ip:port to run the live test")
	}
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	abstractUUID, err := parseUUID(EPMUUID)
	if err != nil {
		t.Fatalf("parseUUID: %v", err)
	}
	if _, err = conn.Write(buildBind(1, 4280, abstractUUID, EPMVersionMajor, EPMVersionMinor)); err != nil {
		t.Fatalf("write: %v", err)
	}
	full, hdr, err := readPDU(conn)
	if err != nil {
		t.Fatalf("readPDU: %v", err)
	}
	switch hdr.PType {
	case ptypeBindAck:
		ack, err := parseBindAck(full)
		if err != nil {
			t.Fatalf("parseBindAck: %v", err)
		}
		t.Logf("bind_ack: result=%s transfer_syntax=%s v%d.%d sec_addr=%q",
			resultCodeName(ack.ResultCode), ack.TransferSyntaxUUID, ack.TransferSyntaxVerMajor, ack.TransferSyntaxVerMinor, ack.SecondaryAddress)
	case ptypeBindNak:
		nak, err := parseBindNak(full)
		if err != nil {
			t.Fatalf("parseBindNak: %v", err)
		}
		t.Logf("bind_nak: reason=%s", rejectReasonName(nak.RejectReason))
	default:
		t.Fatalf("unexpected PDU type %d", hdr.PType)
	}
}

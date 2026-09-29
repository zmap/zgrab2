package pptp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/zmap/zgrab2"
)

func testReply() []byte {
	reply := make([]byte, pptpSCCRLength)
	binary.BigEndian.PutUint16(reply[:2], pptpSCCRLength)
	binary.BigEndian.PutUint16(reply[2:4], PPTP_CONTROL_MESSAGE)
	binary.BigEndian.PutUint32(reply[4:8], PPTP_MAGIC_COOKIE)
	binary.BigEndian.PutUint16(reply[8:10], PPTP_START_CONN_REPLY)
	binary.BigEndian.PutUint16(reply[12:14], PPTP_PROTOCOL_VERSION)
	reply[14] = 1
	binary.BigEndian.PutUint32(reply[16:20], 2)
	binary.BigEndian.PutUint32(reply[20:24], 2)
	binary.BigEndian.PutUint16(reply[24:26], 10)
	binary.BigEndian.PutUint16(reply[26:28], 57640)
	return reply
}

func TestCreateSCCRMessage(t *testing.T) {
	request := createSCCRMessage()
	if len(request) != pptpSCCRLength ||
		binary.BigEndian.Uint16(request[:2]) != pptpSCCRLength ||
		binary.BigEndian.Uint16(request[2:4]) != PPTP_CONTROL_MESSAGE ||
		binary.BigEndian.Uint32(request[4:8]) != PPTP_MAGIC_COOKIE ||
		binary.BigEndian.Uint16(request[8:10]) != PPTP_START_CONN_REQUEST ||
		binary.BigEndian.Uint16(request[12:14]) != PPTP_PROTOCOL_VERSION ||
		!bytes.Equal(request[10:12], []byte{0, 0}) ||
		!bytes.Equal(request[14:28], make([]byte, 14)) ||
		!bytes.HasPrefix(request[28:92], []byte("ZGRAB2-SCANNER")) ||
		!bytes.HasPrefix(request[92:], []byte("ZGRAB2")) {
		t.Fatalf("invalid SCCRQ layout: %x", request)
	}
}

func TestParseSCCRP(t *testing.T) {
	reply := testReply()
	copy(reply[28:92], "example.test")
	copy(reply[92:], "Example Vendor")
	parsed, err := parseSCCRP(reply)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ProtocolVersion != 0x0100 || parsed.ResultCode != 1 || parsed.ErrorCode != 0 ||
		parsed.FramingCapability != 2 || parsed.BearerCapability != 2 ||
		parsed.MaximumChannels != 10 || parsed.FirmwareRevision != 57640 ||
		parsed.Hostname != "example.test" || parsed.Vendor != "Example Vendor" {
		t.Fatalf("unexpected SCCRP: %+v", parsed)
	}
	output, err := json.Marshal(&ScanResults{Banner: "request", ControlMessage: "reply", SCCRP: parsed})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(output, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["firmware_revision"] != float64(57640) || fields["hostname"] != "example.test" ||
		fields["vendor"] != "Example Vendor" || fields["banner"] != "request" ||
		fields["control_message"] != "reply" {
		t.Fatalf("unexpected JSON fields: %s", output)
	}
}

func TestParseSCCRPEmptyIdentity(t *testing.T) {
	parsed, err := parseSCCRP(testReply())
	if err != nil {
		t.Fatal(err)
	}
	output, err := json.Marshal(&ScanResults{SCCRP: parsed})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output, []byte(`"hostname":""`)) ||
		!bytes.Contains(output, []byte(`"vendor":""`)) ||
		!bytes.Contains(output, []byte(`"error_code":0`)) {
		t.Fatalf("missing empty or zero fields: %s", output)
	}
}

func TestParseSCCRPRejectsMalformed(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"empty", func([]byte) []byte { return nil }},
		{"short", func(reply []byte) []byte { return reply[:27] }},
		{"wrong length", func(reply []byte) []byte { reply[1] = 8; return reply }},
		{"wrong message type", func(reply []byte) []byte { reply[3] = 2; return reply }},
		{"wrong cookie", func(reply []byte) []byte { reply[4] = 0; return reply }},
		{"wrong control type", func(reply []byte) []byte { reply[9] = 1; return reply }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if parsed, err := parseSCCRP(tc.edit(testReply())); err == nil || parsed != nil {
				t.Fatalf("expected protocol error, got %+v, %v", parsed, err)
			}
		})
	}
}

func TestReadResponseSplitAndTruncated(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		t.Run(map[bool]string{false: "split", true: "truncated"}[truncated], func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			reply := testReply()
			go func() {
				defer server.Close()
				_, _ = server.Write(reply[:1])
				_, _ = server.Write(reply[1:12])
				if truncated {
					return
				}
				_, _ = server.Write(reply[12:])
			}()
			got, err := (&Connection{conn: client}).readResponse()
			if truncated {
				if err == nil || !strings.Contains(err.Error(), "response body") ||
					zgrab2.TryGetScanStatus(err) != zgrab2.SCAN_PROTOCOL_ERROR {
					t.Fatalf("expected incomplete body, got %v", err)
				}
			} else if err != nil || !bytes.Equal(got, reply) {
				t.Fatalf("readResponse() = %x, %v", got, err)
			}
		})
	}
}

func TestReadResponseRejectsLength(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		defer server.Close()
		_, _ = server.Write([]byte{0, 8})
	}()
	_, err := (&Connection{conn: client}).readResponse()
	if zgrab2.TryGetScanStatus(err) != zgrab2.SCAN_PROTOCOL_ERROR {
		t.Fatalf("expected protocol error for invalid length, got %v", err)
	}
}

func TestScanReplyStatus(t *testing.T) {
	tests := []struct {
		name        string
		reply       func() []byte
		wantStatus  zgrab2.ScanStatus
		wantRawData bool
	}{
		{"success", testReply, zgrab2.SCAN_SUCCESS, true},
		{"rejected", func() []byte {
			reply := testReply()
			reply[14], reply[15] = 2, 3
			return reply
		}, zgrab2.SCAN_PROTOCOL_ERROR, true},
		{"wrong magic cookie", func() []byte {
			reply := testReply()
			reply[4] = 0
			return reply
		}, zgrab2.SCAN_PROTOCOL_ERROR, true},
		{"wrong control type", func() []byte {
			reply := testReply()
			reply[9] = PPTP_START_CONN_REQUEST
			return reply
		}, zgrab2.SCAN_PROTOCOL_ERROR, true},
		{"incomplete reply", func() []byte { return testReply()[:40] }, zgrab2.SCAN_PROTOCOL_ERROR, false},
		{"incomplete header", func() []byte { return testReply()[:1] }, zgrab2.SCAN_PROTOCOL_ERROR, false},
		{"invalid length", func() []byte { return []byte{0, 8} }, zgrab2.SCAN_PROTOCOL_ERROR, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			reply := tc.reply()
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				defer conn.Close()
				_, _ = io.ReadFull(conn, make([]byte, pptpSCCRLength))
				_, _ = conn.Write(reply)
			}()
			port := uint(listener.Addr().(*net.TCPAddr).Port)
			module := NewModule()
			scanner := module.NewScanner()
			flags := module.NewFlags().(*Flags)
			flags.Port = port
			flags.TargetTimeout = time.Second
			if initErr := scanner.Init(flags); initErr != nil {
				t.Fatal(initErr)
			}
			group, err := scanner.GetDialerGroupConfig().GetDefaultDialerGroupFromConfig()
			if err != nil {
				t.Fatal(err)
			}
			status, result, err := scanner.Scan(context.Background(), group, &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1"), Port: port})
			if status != tc.wantStatus || (err == nil) != (status == zgrab2.SCAN_SUCCESS) {
				t.Fatalf("got status %s, error %v; want %s", status, err, tc.wantStatus)
			}
			parsed := result.(*ScanResults)
			if tc.wantRawData && len(parsed.ControlMessage) != pptpSCCRLength {
				t.Fatalf("unexpected result: %+v", parsed)
			}
			if (tc.name == "success" || tc.name == "rejected") && parsed.FirmwareRevision != 57640 {
				t.Fatalf("unexpected firmware revision: %+v", parsed)
			}
			if tc.name != "success" && tc.name != "rejected" && parsed.SCCRP != nil {
				t.Fatalf("parsed malformed reply: %+v", parsed.SCCRP)
			}
			if tc.name == "rejected" && (parsed.ResultCode != 2 || parsed.ErrorCode != 3) {
				t.Fatalf("missing rejection codes: %+v", parsed)
			}
		})
	}
}

package drda

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"
)

// a2e inverts the e2a table so tests can synthesize EBCDIC-encoded attributes.
func a2e() [256]byte {
	var t [256]byte
	for e := 0; e < 256; e++ {
		t[e2a[e]] = byte(e)
	}
	return t
}

func asciiToEBCDIC(s string) []byte {
	tbl := a2e()
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		out[i] = tbl[s[i]]
	}
	return out
}

func makeParam(cp int, data []byte) []byte {
	p := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(p[0:2], uint16(4+len(data)))
	binary.BigEndian.PutUint16(p[2:4], uint16(cp))
	copy(p[4:], data)
	return p
}

func makeEXCSATRD(params ...[]byte) []byte {
	var body []byte
	for _, p := range params {
		body = append(body, p...)
	}
	total := ddmHeaderLen + len(body)
	ddm := make([]byte, ddmHeaderLen)
	binary.BigEndian.PutUint16(ddm[0:2], uint16(total))
	ddm[2] = ddmMagic
	ddm[3] = 0x41
	binary.BigEndian.PutUint16(ddm[4:6], 1)
	binary.BigEndian.PutUint16(ddm[6:8], uint16(total-6))
	binary.BigEndian.PutUint16(ddm[8:10], cpEXCSATRD)
	return append(ddm, body...)
}

func TestBuildEXCSAT(t *testing.T) {
	got := buildEXCSAT()
	// Header must start with total length, DDM magic and EXCSAT codepoint.
	if len(got) != int(binary.BigEndian.Uint16(got[0:2])) {
		t.Fatalf("length prefix %d != actual length %d", binary.BigEndian.Uint16(got[0:2]), len(got))
	}
	if got[2] != ddmMagic {
		t.Errorf("magic = 0x%02x, want 0x%02x", got[2], ddmMagic)
	}
	if cp := binary.BigEndian.Uint16(got[8:10]); cp != cpEXCSAT {
		t.Errorf("codepoint = 0x%04x, want 0x%04x", cp, cpEXCSAT)
	}
}

func TestParseEXCSATRD(t *testing.T) {
	pkt := makeEXCSATRD(
		makeParam(cpEXTNAM, asciiToEBCDIC("DB2     db2sysc 2D9425E0")),
		makeParam(cpSRVCLSNM, asciiToEBCDIC("QDB2/NT64")),
		makeParam(cpSRVNAM, asciiToEBCDIC("DB2")),
		makeParam(cpSRVRLSLV, asciiToEBCDIC("SQL11013")),
	)
	attrs, ok := parseEXCSATRD(pkt)
	if !ok {
		t.Fatal("parseEXCSATRD returned ok=false")
	}
	if attrs.serverClass != "QDB2/NT64" {
		t.Errorf("serverClass = %q, want %q", attrs.serverClass, "QDB2/NT64")
	}
	if attrs.serverName != "DB2" {
		t.Errorf("serverName = %q, want %q", attrs.serverName, "DB2")
	}
	if attrs.releaseLevel != "SQL11013" {
		t.Errorf("releaseLevel = %q, want %q", attrs.releaseLevel, "SQL11013")
	}
	if attrs.externalName != "DB2     db2sysc 2D9425E0" {
		t.Errorf("externalName = %q", attrs.externalName)
	}
	if v := versionFromReleaseLevel(attrs.releaseLevel); v != "11.01.3" {
		t.Errorf("version = %q, want %q", v, "11.01.3")
	}
}

func TestParseEXCSATRD_NotDB2(t *testing.T) {
	if _, ok := parseEXCSATRD([]byte("not a drda response at all")); ok {
		t.Error("parseEXCSATRD accepted non-DRDA data")
	}
}

// TestLive performs a real scan against a DRDA/DB2 server. Set DRDA_LIVE_TARGET
// to an "ip:port" (e.g. 45.5.105.132:50000) to enable it.
func TestLive(t *testing.T) {
	target := os.Getenv("DRDA_LIVE_TARGET")
	if target == "" {
		t.Skip("set DRDA_LIVE_TARGET=ip:port to run the live test")
	}
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = conn.Write(buildEXCSAT()); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := readDDM(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	attrs, ok := parseEXCSATRD(data)
	if !ok {
		t.Fatalf("not an EXCSATRD response: %x", data)
	}
	t.Logf("serverClass=%q instanceName=%q releaseLevel=%q version=%q externalName=%q productID=%q",
		attrs.serverClass, attrs.serverName, attrs.releaseLevel,
		versionFromReleaseLevel(attrs.releaseLevel), attrs.externalName, attrs.productID)
}

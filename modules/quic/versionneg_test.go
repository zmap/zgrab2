package quic

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// makeVersionNegotiation builds a Version Negotiation packet.
func makeVersionNegotiation(dcid, scid []byte, versions ...uint32) []byte {
	pkt := []byte{0x80 | 0x2a, 0, 0, 0, 0}
	pkt = append(pkt, byte(len(dcid)))
	pkt = append(pkt, dcid...)
	pkt = append(pkt, byte(len(scid)))
	pkt = append(pkt, scid...)
	for _, v := range versions {
		pkt = binary.BigEndian.AppendUint32(pkt, v)
	}
	return pkt
}

func TestBuildVersionProbe(t *testing.T) {
	probe, err := newVersionProbe()
	if err != nil {
		t.Fatal(err)
	}
	pkt := probe.Packet
	if len(pkt) != minInitialDatagramSize {
		t.Fatalf("probe is %d bytes, want %d", len(pkt), minInitialDatagramSize)
	}
	if pkt[0]&0xc0 != 0xc0 {
		t.Errorf("first byte %#x does not have the long header and fixed bits set", pkt[0])
	}
	version := binary.BigEndian.Uint32(pkt[1:5])
	if !isReservedVersion(version) {
		t.Errorf("probe version %#08x is not a reserved version", version)
	}
	if int(pkt[5]) != probeConnIDLen || !bytes.Equal(pkt[6:6+probeConnIDLen], probe.DestConnID) {
		t.Errorf("destination connection ID not encoded correctly")
	}
	scidOff := 6 + probeConnIDLen
	if int(pkt[scidOff]) != probeConnIDLen || !bytes.Equal(pkt[scidOff+1:scidOff+1+probeConnIDLen], probe.SrcConnID) {
		t.Errorf("source connection ID not encoded correctly")
	}
	other, err := newVersionProbe()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(other.DestConnID, probe.DestConnID) {
		t.Errorf("connection IDs are not randomized")
	}
}

func TestParseVersionNegotiation(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	scid := []byte{9, 10, 11}
	pkt := makeVersionNegotiation(dcid, scid, 0x00000001, 0x6b3343cf, 0xff00001d, 0x0a1a2a3a)
	vn, err := parseVersionNegotiation(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(vn.DestConnID, dcid) || !bytes.Equal(vn.SrcConnID, scid) {
		t.Errorf("connection IDs = %x/%x, want %x/%x", vn.DestConnID, vn.SrcConnID, dcid, scid)
	}
	want := []uint32{0x00000001, 0x6b3343cf, 0xff00001d, 0x0a1a2a3a}
	if len(vn.Versions) != len(want) {
		t.Fatalf("got %d versions, want %d", len(vn.Versions), len(want))
	}
	for i := range want {
		if vn.Versions[i] != want[i] {
			t.Errorf("version %d = %#08x, want %#08x", i, vn.Versions[i], want[i])
		}
	}
	if vn.TrailingBytes != 0 {
		t.Errorf("TrailingBytes = %d, want 0", vn.TrailingBytes)
	}

	// Zero-length connection IDs are valid, and a partial trailing version is
	// reported rather than rejected.
	pkt = append(makeVersionNegotiation(nil, nil, 0x00000001), 0xff, 0x00)
	vn, err = parseVersionNegotiation(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if len(vn.DestConnID) != 0 || len(vn.SrcConnID) != 0 || len(vn.Versions) != 1 || vn.TrailingBytes != 2 {
		t.Errorf("unexpected parse of packet with empty connection IDs: %+v", vn)
	}
}

func TestParseVersionNegotiationRejects(t *testing.T) {
	valid := makeVersionNegotiation([]byte{1, 2, 3, 4}, []byte{5, 6, 7, 8}, 0x00000001)
	shortHeader := bytes.Clone(valid)
	shortHeader[0] &^= 0x80
	initial := bytes.Clone(valid)
	binary.BigEndian.PutUint32(initial[1:5], 0x00000001)

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"empty", nil, ErrTruncatedPacket},
		{"short header", shortHeader, ErrNotVersionNegotiation},
		{"nonzero version", initial, ErrNotVersionNegotiation},
		{"dcid length past end", []byte{0x80, 0, 0, 0, 0, 20, 1, 2}, ErrTruncatedPacket},
		{"scid length past end", []byte{0x80, 0, 0, 0, 0, 0, 9, 1}, ErrTruncatedPacket},
		{"missing scid length", []byte{0x80, 0, 0, 0, 0, 1, 1}, ErrTruncatedPacket},
		{"no versions", makeVersionNegotiation([]byte{1}, []byte{2}), ErrTruncatedPacket},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseVersionNegotiation(tt.data); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVersionName(t *testing.T) {
	tests := map[uint32]string{
		0x00000001: "QUICv1",
		0x6b3343cf: "QUICv2",
		0x709a50c4: "QUICv2-draft",
		0xff00001d: "draft-29",
		0xff000022: "draft-34",
		0xfaceb002: "mvfst-02",
		0xfaceb013: "mvfst-13",
		0xfacefeed: "",
		0x1a2a3a4a: "reserved",
		0xdacafaba: "reserved",
		0x51303530: "gQUIC-Q050",
		0x54303531: "gQUIC-T051",
		0x12345678: "",
		0x00000000: "",
		0x51414243: "",
	}
	for v, want := range tests {
		if got := versionName(v); got != want {
			t.Errorf("versionName(%#08x) = %q, want %q", v, got, want)
		}
	}
	if got := newVersion(1); got.Value != "0x00000001" || got.Name != "QUICv1" {
		t.Errorf("newVersion(1) = %+v", got)
	}
}

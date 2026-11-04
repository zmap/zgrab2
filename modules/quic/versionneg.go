package quic

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// minInitialDatagramSize is the smallest UDP payload a client may use for a
	// datagram carrying an Initial packet (RFC 9000, Section 14.1). Servers are
	// only expected to answer packets of at least this size with a Version
	// Negotiation packet (RFC 9000, Section 6.1).
	minInitialDatagramSize = 1200

	// probeConnIDLen is the length of the connection IDs placed in the probe.
	probeConnIDLen = 8

	// probeVersion is a reserved version of the form 0x?a?a?a?a (RFC 9000,
	// Section 15), which servers must not support, so a conforming server
	// answers with a Version Negotiation packet listing what it does support.
	probeVersion uint32 = 0x1a2a3a4a
)

var (
	// ErrNotVersionNegotiation is returned when a datagram is not a Version
	// Negotiation packet.
	ErrNotVersionNegotiation = errors.New("not a QUIC version negotiation packet")

	// ErrTruncatedPacket is returned when a datagram ends before the end of
	// the header it claims to contain.
	ErrTruncatedPacket = errors.New("truncated QUIC packet")
)

// versionProbe is a single version negotiation probe and the connection IDs
// it was sent with.
type versionProbe struct {
	DestConnID []byte
	SrcConnID  []byte
	Packet     []byte
}

// newVersionProbe builds a long header packet carrying a reserved version,
// padded to minInitialDatagramSize, with random connection IDs.
func newVersionProbe() (*versionProbe, error) {
	dcid := make([]byte, probeConnIDLen)
	scid := make([]byte, probeConnIDLen)
	if _, err := rand.Read(dcid); err != nil {
		return nil, err
	}
	if _, err := rand.Read(scid); err != nil {
		return nil, err
	}
	return &versionProbe{
		DestConnID: dcid,
		SrcConnID:  scid,
		Packet:     buildVersionProbe(probeVersion, dcid, scid),
	}, nil
}

// buildVersionProbe serializes a long header packet (RFC 8999, Section 5.1)
// with the given version and connection IDs. The packet type bits are those of
// an Initial packet, and the rest of the datagram is zero padding, which a
// server cannot interpret anyway since it does not know the version.
func buildVersionProbe(version uint32, dcid, scid []byte) []byte {
	pkt := make([]byte, 0, minInitialDatagramSize)
	// Header form (1) and fixed bit (1), packet type Initial (00)
	pkt = append(pkt, 0xc0)
	pkt = binary.BigEndian.AppendUint32(pkt, version)
	pkt = append(pkt, byte(len(dcid)))
	pkt = append(pkt, dcid...)
	pkt = append(pkt, byte(len(scid)))
	pkt = append(pkt, scid...)
	for len(pkt) < minInitialDatagramSize {
		pkt = append(pkt, 0)
	}
	return pkt
}

// versionNegotiation is a parsed Version Negotiation packet (RFC 8999,
// Section 6).
type versionNegotiation struct {
	DestConnID []byte
	SrcConnID  []byte
	Versions   []uint32
	// TrailingBytes is the number of bytes after the last complete version.
	TrailingBytes int
}

// parseVersionNegotiation parses a Version Negotiation packet.
func parseVersionNegotiation(data []byte) (*versionNegotiation, error) {
	if len(data) < 7 {
		return nil, ErrTruncatedPacket
	}
	if data[0]&0x80 == 0 || binary.BigEndian.Uint32(data[1:5]) != 0 {
		return nil, ErrNotVersionNegotiation
	}
	pos := 5
	readConnID := func() ([]byte, error) {
		if pos >= len(data) {
			return nil, ErrTruncatedPacket
		}
		l := int(data[pos])
		pos++
		if pos+l > len(data) {
			return nil, ErrTruncatedPacket
		}
		id := bytes.Clone(data[pos : pos+l])
		pos += l
		return id, nil
	}
	dcid, err := readConnID()
	if err != nil {
		return nil, err
	}
	scid, err := readConnID()
	if err != nil {
		return nil, err
	}
	vn := &versionNegotiation{DestConnID: dcid, SrcConnID: scid}
	for ; pos+4 <= len(data); pos += 4 {
		vn.Versions = append(vn.Versions, binary.BigEndian.Uint32(data[pos:pos+4]))
	}
	vn.TrailingBytes = len(data) - pos
	if len(vn.Versions) == 0 {
		return nil, fmt.Errorf("version negotiation packet lists no versions: %w", ErrTruncatedPacket)
	}
	return vn, nil
}

// isReservedVersion reports whether v follows the 0x?a?a?a?a pattern used to
// exercise version negotiation (RFC 9000, Section 15).
func isReservedVersion(v uint32) bool {
	return v&0x0f0f0f0f == 0x0a0a0a0a
}

// versionName returns a human-readable name for a QUIC version number, or an
// empty string if the version is not recognized.
func versionName(v uint32) string {
	switch {
	case v == 0x00000001:
		return "QUICv1"
	case v == 0x6b3343cf:
		return "QUICv2"
	case v == 0x709a50c4:
		return "QUICv2-draft"
	case v>>8 == 0xff0000:
		return fmt.Sprintf("draft-%d", v&0xff)
	case v>>8 == 0xfaceb0:
		// Facebook's mvfst uses 0xfaceb0xx for its own versions.
		return fmt.Sprintf("mvfst-%02x", v&0xff)
	case isReservedVersion(v):
		return "reserved"
	}
	// Google QUIC (Q0xx) and Google QUIC with TLS (T0xx) versions are four
	// ASCII characters, such as "Q050" or "T051".
	b := binary.BigEndian.AppendUint32(nil, v)
	if (b[0] == 'Q' || b[0] == 'T') && isDigit(b[1]) && isDigit(b[2]) && isDigit(b[3]) {
		return "gQUIC-" + string(b)
	}
	return ""
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

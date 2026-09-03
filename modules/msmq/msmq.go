// Package msmq implements the wire format of the MS-MQQB "Binary Reliable
// Messaging Protocol" session-establishment exchange, as documented in
// Microsoft's public Open Specifications:
//
//   - [MS-MQQB]: Message Queuing (MSMQ): Binary Reliable Messaging Protocol
//     (the raw TCP/IP block protocol used between two queue managers,
//     distinct from the RPC-based MS-MQMP/MS-MQMR client/management
//     protocols, which is why the msrpc module's endpoint-mapper probe
//     doesn't identify this listener).
//   - [MS-MQMQ]: Message Queuing (MSMQ): Data Structures (the common packet
//     headers -- BaseHeader, InternalHeader -- shared by MS-MQQB).
//
// This file implements only the single exchange needed to positively
// identify a listener: building an EstablishConnection Packet (MS-MQQB
// section 2.2.3) and parsing the EstablishConnection Packet sent back in
// response (accepting or refusing the session). No further MS-MQQB messages
// (e.g. actual message transfer) are implemented, by design -- this keeps
// the probe to a single request/response exchange.
package msmq

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const (
	baseHeaderLen                = 16
	internalHeaderLen            = 4
	establishConnectionHeaderLen = 552
	// establishConnectionPacketLen is BaseHeader + InternalHeader +
	// EstablishConnectionHeader: 16 + 4 + 552.
	establishConnectionPacketLen = baseHeaderLen + internalHeaderLen + establishConnectionHeaderLen

	// baseHeaderVersion is the only defined value of BaseHeader.VersionNumber
	// ([MS-MQMQ] 2.2.19.1): "This field MUST be set to the value 0x10."
	baseHeaderVersion = 0x10
	// baseHeaderSignature is BaseHeader.Signature ([MS-MQMQ] 2.2.19.1):
	// "This field MUST be set to 0x524F494C." -- a fixed magic number present
	// in every MS-MQMQ-derived packet, which is what this module checks for.
	baseHeaderSignature = 0x524F494C
	// baseFlagsIN is the BaseHeader.Flags.IN bit ([MS-MQMQ] 2.2.19.1): bit 3
	// (after the 3-bit PR priority field), which MUST be set on an
	// EstablishConnection Packet.
	baseFlagsIN = 0x0008
	// baseFlagsPriorityDefault is BaseHeader.Flags.PR ([MS-MQMQ] 2.2.19.1),
	// the 3-bit message priority field occupying bits 0-2. The spec's
	// documented default is 0x3.
	baseFlagsPriorityDefault = 0x3

	// internalPacketTypeEstablishConnection is InternalHeader.Flags.PT ==
	// 0x2 ([MS-MQQB] 2.2.1), identifying an EstablishConnection Packet. PT
	// occupies the low 4 bits (bits 0-3) of InternalHeader.Flags.
	internalPacketTypeEstablishConnection = 0x2
	// internalFlagsCS is InternalHeader.Flags.CS ([MS-MQQB] 2.2.1), bit 4
	// (immediately above the 4-bit PT field): when set in a response, the
	// acceptor is refusing the connection.
	internalFlagsCS = 0x0010

	// ecOSReserved is EstablishConnectionHeader.OperatingSystem's reserved
	// high byte ([MS-MQQB] 2.2.3.1): "This field is reserved. MUST be set to
	// 0x10."
	ecOSReserved = 0x10
	// ecOSFlagSE is the SE (session/ping) bit of
	// EstablishConnectionHeader.OperatingSystem's low byte. Setting it tells
	// the acceptor that no separate Ping Request will follow, keeping this
	// module's probe to a single packet.
	ecOSFlagSE = 0x80

	// responsePaddingByte is the fixed fill value MS-MQQB mandates for
	// EstablishConnectionHeader.Padding "when part of a response packet from
	// a server" -- an additional signal that a response is genuine.
	responsePaddingByte = 0x5A
)

// buildEstablishConnection constructs an EstablishConnection Packet
// ([MS-MQQB] 2.2.3): a BaseHeader, an InternalHeader, and an
// EstablishConnectionHeader. clientGUID/serverGUID may be the zero GUID --
// per [MS-MQQB] 2.2.3.1, a zero ServerGuid is the documented way to request a
// connection by "direct format name" without knowing the acceptor's queue
// manager GUID in advance, which is exactly the scanner's situation.
func buildEstablishConnection(clientGUID, serverGUID [16]byte, timeStamp uint32) []byte {
	pkt := make([]byte, establishConnectionPacketLen)

	// BaseHeader (16 bytes).
	pkt[0] = baseHeaderVersion // VersionNumber
	pkt[1] = 0                 // Reserved
	binary.LittleEndian.PutUint16(pkt[2:4], baseFlagsPriorityDefault|baseFlagsIN)
	binary.LittleEndian.PutUint32(pkt[4:8], baseHeaderSignature)
	binary.LittleEndian.PutUint32(pkt[8:12], establishConnectionPacketLen) // PacketSize
	binary.LittleEndian.PutUint32(pkt[12:16], 0xFFFFFFFF)                  // TimeToReachQueue: not a UserMessage Packet

	// InternalHeader (4 bytes).
	binary.LittleEndian.PutUint16(pkt[16:18], 0) // Reserved
	binary.LittleEndian.PutUint16(pkt[18:20], uint16(internalPacketTypeEstablishConnection))

	// EstablishConnectionHeader (552 bytes).
	off := 20
	copy(pkt[off:off+16], clientGUID[:])
	off += 16
	copy(pkt[off:off+16], serverGUID[:])
	off += 16
	binary.LittleEndian.PutUint32(pkt[off:off+4], timeStamp)
	off += 4
	osField := uint16(ecOSReserved)<<8 | uint16(ecOSFlagSE)
	binary.LittleEndian.PutUint16(pkt[off:off+2], osField)
	off += 2
	binary.LittleEndian.PutUint16(pkt[off:off+2], 0) // Reserved
	// The remaining 512 bytes are Padding, left zeroed: "When the
	// EstablishConnectionHeader is not part of a response packet from a
	// server, each byte in this field contains an uninitialized value."

	return pkt
}

// establishConnectionResponse holds the fields parsed out of an
// EstablishConnection Packet sent back by an acceptor.
type establishConnectionResponse struct {
	ClientGUID             [16]byte
	ServerGUID             [16]byte
	TimeStamp              uint32
	Refused                bool
	OperatingSystem        uint16 // low byte: SE(bit7), NP(bit4); high byte: reserved (0x10)
	PaddingMatchesResponse bool
}

// parseEstablishConnection parses and validates a full EstablishConnection
// Packet (BaseHeader + InternalHeader + EstablishConnectionHeader).
func parseEstablishConnection(pkt []byte) (*establishConnectionResponse, error) {
	if len(pkt) < establishConnectionPacketLen {
		return nil, fmt.Errorf("packet is %d bytes, want %d", len(pkt), establishConnectionPacketLen)
	}
	if pkt[0] != baseHeaderVersion {
		return nil, fmt.Errorf("BaseHeader.VersionNumber is 0x%02x, want 0x%02x", pkt[0], baseHeaderVersion)
	}
	if sig := binary.LittleEndian.Uint32(pkt[4:8]); sig != baseHeaderSignature {
		return nil, fmt.Errorf("BaseHeader.Signature is 0x%08x, want 0x%08x", sig, baseHeaderSignature)
	}

	internalFlags := binary.LittleEndian.Uint16(pkt[18:20])
	if pt := internalFlags & 0x000F; pt != internalPacketTypeEstablishConnection {
		return nil, fmt.Errorf("InternalHeader.Flags.PT is 0x%x, want EstablishConnection (0x%x)", pt, internalPacketTypeEstablishConnection)
	}

	res := &establishConnectionResponse{
		Refused: internalFlags&internalFlagsCS != 0,
	}
	off := 20
	copy(res.ClientGUID[:], pkt[off:off+16])
	off += 16
	copy(res.ServerGUID[:], pkt[off:off+16])
	off += 16
	res.TimeStamp = binary.LittleEndian.Uint32(pkt[off : off+4])
	off += 4
	res.OperatingSystem = binary.LittleEndian.Uint16(pkt[off : off+2])
	off += 4 // OperatingSystem(2) + Reserved(2)

	padding := pkt[off : off+512]
	res.PaddingMatchesResponse = true
	for _, b := range padding {
		if b != responsePaddingByte {
			res.PaddingMatchesResponse = false
			break
		}
	}
	return res, nil
}

// formatGUID renders a 16-byte wire-format GUID ([MS-DTYP] 2.3.4.1, the same
// layout as a DCE UUID) as a standard hyphenated string. The first three
// fields are little-endian on the wire; the rest are a plain byte string.
func formatGUID(g [16]byte) string {
	b := make([]byte, 16)
	b[0], b[1], b[2], b[3] = g[3], g[2], g[1], g[0]
	b[4], b[5] = g[5], g[4]
	b[6], b[7] = g[7], g[6]
	copy(b[8:16], g[8:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]))
}

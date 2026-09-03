// Package msrpc implements the DCE/RPC ("MSRPC") wire protocol used by
// Microsoft's RPC runtime, as documented in MS-RPCE and the original DCE 1.1
// RPC specification.
//
// This file implements only what is needed to build a single Bind PDU and
// parse the resulting bind_ack / bind_nak PDU. It does not implement any
// further DCE/RPC operations (e.g. ept_map endpoint lookups), by design: a
// single Bind exchange is the minimal, well-defined probe that distinguishes
// a genuine MSRPC listener from anything else, at the cost of exactly one
// packet in each direction.
package msrpc

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	rpcVersionMajor = 5
	rpcVersionMinor = 0

	ptypeBind    = 11
	ptypeBindAck = 12
	ptypeBindNak = 13

	pfcFirstFrag = 0x01
	pfcLastFrag  = 0x02

	// commonHeaderLen is the size of the DCE/RPC common connection-oriented
	// PDU header (MS-RPCE 2.2.3.1 / DCE 1.1 rpc_cn_common_hdr_t).
	commonHeaderLen = 16

	// resultEntryLen is the size of a single p_result_t entry in a bind_ack's
	// result list: result(2) + reason(2) + transfer_syntax p_syntax_id_t(20).
	resultEntryLen = 24
)

// packedDrepLE is the NDR data representation every Windows RPC client
// advertises: little-endian integers, ASCII characters, IEEE floating point.
var packedDrepLE = [4]byte{0x10, 0x00, 0x00, 0x00}

// Well-known interface/transfer-syntax UUIDs.
const (
	// EPMUUID is the RPC Endpoint Mapper interface UUID. It is always
	// registered on the RPC listener bound to TCP/135 on Windows, so binding
	// to it is the standard way to confirm a real MSRPC endpoint mapper is
	// listening (see MS-RPCE 2.2.1.1.9 and nmap's msrpc-enum.nse). This is
	// the module's default abstract syntax.
	EPMUUID         = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"
	EPMVersionMajor = 3
	EPMVersionMinor = 0

	// ndrUUID is the NDR (Network Data Representation) 2.0 transfer syntax,
	// the classic 32-bit transfer syntax supported by every DCE/RPC 1.1
	// implementation, including every version of the Windows RPC runtime.
	ndrUUID         = "8a885d04-1ceb-11c9-9fe8-08002b104860"
	ndrVersionMajor = 2
	ndrVersionMinor = 0
)

// Bind result codes (DCE 1.1 p_cont_def_result_t, MS-RPCE 2.2.2.7).
const (
	resultAcceptance        = 0
	resultUserRejection     = 1
	resultProviderRejection = 2
	resultNegotiateAck      = 3
)

var resultCodeNames = map[uint16]string{
	resultAcceptance:        "acceptance",
	resultUserRejection:     "user_rejection",
	resultProviderRejection: "provider_rejection",
	resultNegotiateAck:      "negotiate_ack",
}

// providerRejectReasonNames covers both a p_result_t's "reason" field (when
// result == provider_rejection) and a bind_nak's provider_reject_reason
// field -- both are drawn from the same DCE 1.1 enumeration.
var providerRejectReasonNames = map[uint16]string{
	0:  "reason_not_specified",
	1:  "abstract_syntax_not_supported",
	2:  "proposed_transfer_syntaxes_not_supported",
	3:  "local_limit_exceeded",
	4:  "protocol_version_not_supported",
	8:  "invalid_pres_context_id",
	9:  "unsupported_authn_level",
	11: "invalid_checksum",
}

func resultCodeName(code uint16) string {
	if name, ok := resultCodeNames[code]; ok {
		return name
	}
	return fmt.Sprintf("unknown (%d)", code)
}

func rejectReasonName(code uint16) string {
	if name, ok := providerRejectReasonNames[code]; ok {
		return name
	}
	return fmt.Sprintf("unknown (%d)", code)
}

// parseUUID parses a standard hyphenated UUID string (e.g.
// "e1af8308-5d1f-11c9-91a4-08002b14a0fa") into the 16-byte wire
// representation used by p_syntax_id_t. The first three fields (time_low,
// time_mid, time_hi_and_version) are transmitted little-endian; the clock
// sequence and node are transmitted as a plain byte string.
func parseUUID(s string) ([16]byte, error) {
	var out [16]byte
	stripped := strings.ReplaceAll(s, "-", "")
	if len(stripped) != 32 {
		return out, fmt.Errorf("invalid UUID %q: expected 32 hex digits", s)
	}
	raw, err := hex.DecodeString(stripped)
	if err != nil {
		return out, fmt.Errorf("invalid UUID %q: %w", s, err)
	}
	out[0], out[1], out[2], out[3] = raw[3], raw[2], raw[1], raw[0]
	out[4], out[5] = raw[5], raw[4]
	out[6], out[7] = raw[7], raw[6]
	copy(out[8:16], raw[8:16])
	return out, nil
}

// formatUUID is the inverse of parseUUID: it renders a 16-byte wire UUID back
// into the standard hyphenated string form for display in results.
func formatUUID(wire []byte) string {
	if len(wire) != 16 {
		return hex.EncodeToString(wire)
	}
	b := make([]byte, 16)
	b[0], b[1], b[2], b[3] = wire[3], wire[2], wire[1], wire[0]
	b[4], b[5] = wire[5], wire[4]
	b[6], b[7] = wire[7], wire[6]
	copy(b[8:16], wire[8:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]))
}

// appendSyntaxID appends a p_syntax_id_t (a 16-byte UUID followed by a 4-byte
// version, major in the low 16 bits and minor in the high 16 bits) to buf.
func appendSyntaxID(buf []byte, uuid [16]byte, verMajor, verMinor uint16) []byte {
	buf = append(buf, uuid[:]...)
	var verBytes [4]byte
	binary.LittleEndian.PutUint32(verBytes[:], uint32(verMajor)|uint32(verMinor)<<16)
	return append(buf, verBytes[:]...)
}

// buildBind constructs a DCE/RPC Bind PDU proposing a single presentation
// context: the given abstract syntax (interface UUID/version), offering the
// NDR transfer syntax.
func buildBind(callID uint32, maxFrag uint16, abstractUUID [16]byte, abstractVerMajor, abstractVerMinor uint16) []byte {
	transferUUID, _ := parseUUID(ndrUUID) // constant, always valid

	var body []byte
	var maxFragBytes [2]byte
	binary.LittleEndian.PutUint16(maxFragBytes[:], maxFrag)
	body = append(body, maxFragBytes[:]...) // max_xmit_frag
	body = append(body, maxFragBytes[:]...) // max_recv_frag
	body = append(body, 0, 0, 0, 0)         // assoc_group_id (0 == request new)
	body = append(body, 1, 0, 0, 0)         // n_context_elem=1, reserved, reserved2

	var ctxID [2]byte
	binary.LittleEndian.PutUint16(ctxID[:], 0) // p_cont_id = 0
	body = append(body, ctxID[:]...)
	body = append(body, 1, 0) // n_transfer_syn=1, reserved
	body = appendSyntaxID(body, abstractUUID, abstractVerMajor, abstractVerMinor)
	body = appendSyntaxID(body, transferUUID, ndrVersionMajor, ndrVersionMinor)

	header := make([]byte, commonHeaderLen, commonHeaderLen+len(body))
	header[0] = rpcVersionMajor
	header[1] = rpcVersionMinor
	header[2] = ptypeBind
	header[3] = pfcFirstFrag | pfcLastFrag
	copy(header[4:8], packedDrepLE[:])
	binary.LittleEndian.PutUint16(header[8:10], uint16(commonHeaderLen+len(body))) // frag_length
	binary.LittleEndian.PutUint16(header[10:12], 0)                                // auth_length
	binary.LittleEndian.PutUint32(header[12:16], callID)

	return append(header, body...)
}

// commonHeader holds the parsed DCE/RPC common connection-oriented PDU
// header shared by every PDU type.
type commonHeader struct {
	PType      byte
	FragLength uint16
	CallID     uint32
}

// parseCommonHeader validates and parses the 16-byte DCE/RPC common header at
// the start of data.
func parseCommonHeader(data []byte) (*commonHeader, error) {
	if len(data) < commonHeaderLen {
		return nil, fmt.Errorf("response too short for a DCE/RPC header: %d bytes", len(data))
	}
	if data[0] != rpcVersionMajor {
		return nil, fmt.Errorf("unexpected RPC version %d.%d", data[0], data[1])
	}
	fragLength := binary.LittleEndian.Uint16(data[8:10])
	if fragLength < commonHeaderLen {
		return nil, fmt.Errorf("frag_length %d is smaller than the header itself", fragLength)
	}
	return &commonHeader{
		PType:      data[2],
		FragLength: fragLength,
		CallID:     binary.LittleEndian.Uint32(data[12:16]),
	}, nil
}

// bindAckResult holds the fields of interest parsed out of a bind_ack PDU.
type bindAckResult struct {
	MaxXmitFrag      uint16
	MaxRecvFrag      uint16
	AssocGroupID     uint32
	SecondaryAddress string

	ResultCode   uint16
	RejectReason uint16

	TransferSyntaxUUID     string
	TransferSyntaxVerMajor uint16
	TransferSyntaxVerMinor uint16
}

// parseBindAck parses a full bind_ack PDU (including its 16-byte common
// header) and extracts the first (and, for our single-context Bind request,
// only) presentation context result.
func parseBindAck(data []byte) (*bindAckResult, error) {
	body := data[commonHeaderLen:]
	if len(body) < 10 {
		return nil, errors.New("bind_ack body too short for its fixed fields")
	}
	res := &bindAckResult{
		MaxXmitFrag:  binary.LittleEndian.Uint16(body[0:2]),
		MaxRecvFrag:  binary.LittleEndian.Uint16(body[2:4]),
		AssocGroupID: binary.LittleEndian.Uint32(body[4:8]),
	}

	secLen := int(binary.LittleEndian.Uint16(body[8:10]))
	pos := 10 + secLen
	if secLen < 0 || pos > len(body) {
		return nil, fmt.Errorf("bind_ack secondary address (%d bytes) overruns the body", secLen)
	}
	if secLen > 0 {
		res.SecondaryAddress = strings.TrimRight(string(body[10:pos]), "\x00")
	}

	// port_any_t is followed by padding to align the result list on a 4-byte
	// boundary, measured from the start of the PDU (the header is itself a
	// multiple of 4 bytes).
	if pad := (4 - (commonHeaderLen+pos)%4) % 4; pad > 0 {
		pos += pad
	}
	if pos+4 > len(body) {
		return nil, errors.New("bind_ack is missing its presentation context result list")
	}
	nResults := int(body[pos])
	pos += 4 // n_results(1) + reserved(1) + reserved2(2)
	if nResults < 1 {
		return nil, errors.New("bind_ack result list is empty")
	}
	if pos+resultEntryLen > len(body) {
		return nil, errors.New("bind_ack result list is truncated")
	}

	res.ResultCode = binary.LittleEndian.Uint16(body[pos : pos+2])
	res.RejectReason = binary.LittleEndian.Uint16(body[pos+2 : pos+4])
	res.TransferSyntaxUUID = formatUUID(body[pos+4 : pos+20])
	transferVer := binary.LittleEndian.Uint32(body[pos+20 : pos+24])
	res.TransferSyntaxVerMajor = uint16(transferVer & 0xffff)
	res.TransferSyntaxVerMinor = uint16(transferVer >> 16)

	return res, nil
}

// bindNakResult holds the fields parsed out of a bind_nak PDU.
type bindNakResult struct {
	RejectReason uint16
}

// parseBindNak parses a full bind_nak PDU (including its common header).
func parseBindNak(data []byte) (*bindNakResult, error) {
	body := data[commonHeaderLen:]
	if len(body) < 2 {
		return nil, errors.New("bind_nak body too short")
	}
	return &bindNakResult{RejectReason: binary.LittleEndian.Uint16(body[0:2])}, nil
}

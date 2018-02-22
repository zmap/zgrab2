package oracle

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/zmap/zgrab2"
)

var (
	// ErrInvalidData is returned when the server returns syntactically-invalid
	// (or very unlikely / problematic) data.
	ErrInvalidData error = errors.New("server returned invalid data")

	// ErrInvalidInput is returned when user-supplied data is not valid.
	ErrInvalidInput = errors.New("caller provided invalid input")

	// ErrUnexpectedResponse is returned when the server returns a valid TNS
	// response but it is not the expected type.
	ErrUnexpectedResponse = errors.New("server returned unexpected response")

	// ErrBufferTooSmall is returned when the caller provides a buffer that is
	// too small for the required data.
	ErrBufferTooSmall error = errors.New("buffer too small")
)

// References:
// https://wiki.wireshark.org/Oracle
// https://blog.pythian.com/repost-oracle-protocol/
// http://www.nyoug.org/Presentations/2008/Sep/Harris_Listening%20In.pdf

// PacketType is the type identifier used in the TNS header to identify the
// format of the packet.
type PacketType uint8

const (
	// PacketTypeConnect identifies a Connect packet (first packet sent by the
	// client, containing the connection string).
	PacketTypeConnect PacketType = 1

	// PacketTypeAccept identifies an Accept packet (the server's response to
	// a Connect packet, contains some server configuration flags).
	PacketTypeAccept = 2

	// PacketTypeAcknowledge identifies an Acknowledge packet.
	PacketTypeAcknowledge = 3

	// PacketTypeRefuse identifies a Refuse packet.
	PacketTypeRefuse = 4

	// PacketTypeRedirect idenfies a Redirect packet. The server can respond to
	// a Connect packet with a Redirect containing a new connection string.
	PacketTypeRedirect = 5

	// PacketTypeData identifies a Data packet. The packet's payload may have
	// further structure.
	PacketTypeData = 6

	// PacketTypeNull identifies a Null packet.
	PacketTypeNull = 7

	// PacketTypeAbort identifies an Abort packet.
	PacketTypeAbort = 9

	// PacketTypeResend identifies a Resend packet. When the server sends this
	// packet, the client sends the exact data that it sent previously.
	PacketTypeResend = 11

	// PacketTypeMarker identifies a Marker packet.
	PacketTypeMarker = 12

	// PacketTypeAttention identifies an Attention packet.
	PacketTypeAttention = 13

	// PacketTypeControl identifies a Control packet.
	PacketTypeControl = 14
)

var packetTypeNames = map[PacketType]string{
	PacketTypeConnect:     "CONNECT",
	PacketTypeAccept:      "ACCEPT",
	PacketTypeAcknowledge: "ACKNOWLEDGE",
	PacketTypeRefuse:      "REFUSE",
	PacketTypeRedirect:    "REDIRECT",
	PacketTypeData:        "DATA",
	PacketTypeNull:        "NULL",
	PacketTypeAbort:       "ABORT",
	PacketTypeResend:      "RESEND",
	PacketTypeMarker:      "MARKER",
	PacketTypeAttention:   "ATTENTION",
	PacketTypeControl:     "CONTROL",
}

// String returns the string representation of the PacketType.
func (packetType PacketType) String() string {
	ret, ok := packetTypeNames[packetType]
	if !ok {
		// These must be individually allowed in the schema
		return fmt.Sprintf("UNKNOWN(0x%02x)", packetType)
	}
	return ret
}

// Implementation of io.Reader that returns data from a slice.
// Lets Decode methods re-use Read methods.
type sliceReader struct {
	Data []byte
}

func getSliceReader(data []byte) *sliceReader {
	return &sliceReader{Data: data}
}

func (reader *sliceReader) Read(output []byte) (int, error) {
	if reader.Data == nil {
		return 0, io.EOF
	}
	n := len(output)
	if n > len(reader.Data) {
		n = len(reader.Data)
	}
	copy(output[0:n], reader.Data[0:n])
	reader.Data = reader.Data[n:]
	return n, nil
}

// TNSFlags is the type for the TNS header's flags.
type TNSFlags uint8

// TNSHeader is the 8-byte header that precedes all TNS packets.
type TNSHeader struct {
	// Length is the big-endian length of the entire packet, including the 8
	// bytes of the header itself.
	Length uint16

	// PacketChecksum is in practice set to 0.
	PacketChecksum uint16

	// PacketType identifies the type of packet data.
	Type PacketType

	// Flags is called "Reserved Byte" in Wireshark.
	Flags TNSFlags

	// HeaderChecksum is in practice set to 0.
	HeaderChecksum uint16
}

// Encode returns the encoded TNSHeader.
func (header *TNSHeader) Encode() []byte {
	ret := make([]byte, 8)
	next := outputBuffer(ret)
	next.pushU16(header.Length)
	next.pushU16(header.PacketChecksum)
	next.pushU8(byte(header.Type))
	next.pushU8(byte(header.Flags))
	next.pushU16(header.HeaderChecksum)
	return ret
}

// DecodeTNSHeader reads the header from the first 8 bytes of buf. If no header
// is provided, a new one is allocated.
// The decoded header is returned as well as a slice pointing past the end of
// the header in buf. On failure, returns nil/nil/error.
func DecodeTNSHeader(ret *TNSHeader, buf []byte) (*TNSHeader, []byte, error) {
	if len(buf) < 8 {
		return nil, nil, ErrBufferTooSmall
	}
	if ret == nil {
		ret = new(TNSHeader)
	}
	var u8 uint8
	rest := buf
	ret.Length, rest = popU16(rest)
	ret.PacketChecksum, rest = popU16(rest)
	u8, rest = popU8(rest)
	ret.Type = PacketType(u8)
	u8, rest = popU8(rest)
	ret.Flags = TNSFlags(u8)
	ret.HeaderChecksum, rest = popU16(rest)
	return ret, rest, nil
}

// ReadTNSHeader reads / decodes a TNSHeader from the first 8 bytes of the
// stream.
func ReadTNSHeader(reader io.Reader) (*TNSHeader, error) {
	buf := make([]byte, 8)
	n, err := reader.Read(buf)
	if err != nil {
		return nil, err
	}
	if n != len(buf) {
		return nil, ErrInvalidData
	}
	ret, _, err := DecodeTNSHeader(nil, buf)
	return ret, err
}

// ServiceOptions are flags used by the client and server in negotiating the
// connection settings.
type ServiceOptions uint16

// Set gets a set representation of the ServiceOptions flags.
func (flags ServiceOptions) Set() map[string]bool {
	ret, _ := zgrab2.MapFlagsToSet(uint64(flags), func(bit uint64) (string, error) {
		return soNames[ServiceOptions(bit)], nil
	})
	// there are no unknowns since all 16 flags are accounted for in soNames
	return ret
}

// TODO -- identify what these actually do (names taken from Wireshark)

const (
	SOBrokenConnectNotify ServiceOptions = 0x2000
	SOPacketChecksum                     = 0x1000
	SOHeaderChecksum                     = 0x0800
	SOFullDuplex                         = 0x0400
	SOHalfDuplex                         = 0x0200
	SOUnknown0100                        = 0x0100
	SOUnknown0080                        = 0x0080
	SOUnknown0040                        = 0x0040
	SOUnknown0020                        = 0x0020
	SODirectIO                           = 0x0010
	SOAttentionProcessing                = 0x0008
	SOCanReceiveAttention                = 0x0004
	SOCanSendAttention                   = 0x0002
	SOUnknown0001                        = 0x0001
	SOUnknown4000                        = 0x4000
	SOUnknown8000                        = 0x8000
)

var soNames = map[ServiceOptions]string{
	SOBrokenConnectNotify: "BROKEN_CONNECT_NOTIFY",
	SOPacketChecksum:      "PACKET_CHECKSUM",
	SOHeaderChecksum:      "HEADER_CHECKSUM",
	SOFullDuplex:          "FULL_DUPLEX",
	SOHalfDuplex:          "HALF_DUPLEX",
	SOUnknown0100:         "UNKNOWN_0100",
	SOUnknown0080:         "UNKNOWN_0080",
	SOUnknown0040:         "UNKNOWN_0040",
	SOUnknown0020:         "UNKNOWN_0020",
	SODirectIO:            "DIRECT_IO",
	SOAttentionProcessing: "ATTENTION_PROCESSING",
	SOCanReceiveAttention: "CAN_RECEIVE_ATTENTION",
	SOCanSendAttention:    "CAN_SEND_ATTENTION",
	SOUnknown0001:         "UNKNOWN_0001",
}

// NTProtocolCharacteristics are flags used by the client and the server to
// negotiate connection settings.
type NTProtocolCharacteristics uint16

// TODO -- identify what these actually do (names taken from Wireshark)

const (
	NTPCHangon           NTProtocolCharacteristics = 0x8000
	NTPCConfirmedRelease                           = 0x4000
	NTPCTDUBasedIO                                 = 0x2000
	NTPCSpawnerRunning                             = 0x1000
	NTPCDataTest                                   = 0x0800
	NTPCCallbackIO                                 = 0x0400
	NTPCAsyncIO                                    = 0x0200
	NTPCPacketIO                                   = 0x0100
	NTPCCanGrant                                   = 0x0080
	NTPCCanHandoff                                 = 0x0040
	NTPCGenerateSIGIO                              = 0x0020
	NTPCGenerateSIGPIPE                            = 0x0010
	NTPCGenerateSIGURG                             = 0x0008
	NTPCUrgentIO                                   = 0x0004
	NTPCFullDuplex                                 = 0x0002
	NTPCTestOperation                              = 0x0001
)

var ntpcNames = map[NTProtocolCharacteristics]string{
	NTPCHangon:           "HANG_ON",
	NTPCConfirmedRelease: "CONFIRMED_RELEASE",
	NTPCTDUBasedIO:       "TDU_BASED_UI",
	NTPCSpawnerRunning:   "SPAWNER_RUNNING",
	NTPCDataTest:         "DATA_TEST",
	NTPCCallbackIO:       "CALLBACK_IO",
	NTPCAsyncIO:          "ASYNC_IO",
	NTPCPacketIO:         "PACKET_IO",
	NTPCCanGrant:         "CAN_GRANT",
	NTPCCanHandoff:       "CAN_HANDOFF",
	NTPCGenerateSIGIO:    "GENERATE_SIGIO",
	NTPCGenerateSIGPIPE:  "GENERATE_SIGPIPE",
	NTPCGenerateSIGURG:   "GENERATE_SIGURG",
	NTPCUrgentIO:         "URGENT_IO",
	NTPCFullDuplex:       "FULL_DUPLEX",
	NTPCTestOperation:    "TEST_OPERATION",
}

// Set gets a set representation of the NTProtocolCharacteristics flags.
func (flags NTProtocolCharacteristics) Set() map[string]bool {
	ret, _ := zgrab2.MapFlagsToSet(uint64(flags), func(bit uint64) (string, error) {
		return ntpcNames[NTProtocolCharacteristics(bit)], nil
	})
	// there are no unknowns since all 16 flags are accounted for in ntpcNames
	return ret

}

// ConnectFlags are flags used by the client and the server to negotiate
// connection settings.
type ConnectFlags uint8

// TODO -- identify what these actually do (names taken from Wireshark)

const (
	CFServicesWanted      ConnectFlags = 0x01
	CFInterchangeInvolved              = 0x02
	CFServicesEnabled                  = 0x04
	CFServicesLinkedIn                 = 0x08
	CFServicesRequired                 = 0x10
	CFUnknown20                        = 0x20
	CFUnknown40                        = 0x40
	CFUnknown80                        = 0x80
)

var cfNames = map[ConnectFlags]string{
	CFServicesWanted:      "SERVICES_WANTED",
	CFInterchangeInvolved: "INTERCHANGE_INVOLVED",
	CFServicesEnabled:     "SERVICES_ENABLED",
	CFServicesLinkedIn:    "SERVICES_LINKED_IN",
	CFServicesRequired:    "SERVICES_REQUIRED",
	CFUnknown20:           "UNKNOWN_20",
	CFUnknown40:           "UNKNOWN_40",
	CFUnknown80:           "UNKNOWN_80",
}

// Set gets a set representation of the ConnectFlags.
func (flags ConnectFlags) Set() map[string]bool {
	ret, _ := zgrab2.MapFlagsToSet(uint64(flags), func(bit uint64) (string, error) {
		return cfNames[ConnectFlags(bit)], nil
	})
	// no unknowns since all 8 bits are accounted for in cfNames
	return ret
}

// defaultByteOrder is the little-endian encoding of the uint16 integer 1 --
// the server takes this value in some packets.
var defaultByteOrder = [2]byte{1, 0}

// TNSConnect is sent by the client to request a connection with the server.
// The server may respond with (at least) Accept, Resend or Redirect.
// If len(packet) > 255, send a packet with data="", followed by data
type TNSConnect struct {
	// Version is the client's version.
	// TODO: Find Version format (10r2 = 0x0139? 9r2 = 0x0138? 9i = 0x0137? 8 = 0x0136?)
	Version uint16

	// MinVersion is the lowest version the client supports.
	MinVersion uint16

	// GlobalServiceOptions specify connection settings (TODO: details).
	GlobalServiceOptions ServiceOptions

	// SDU gives the requested Session Data Unit size. (often 0x0000)
	SDU uint16

	// TDU gives the requested Transfer Data Unit size. (often 0x7fff)
	TDU uint16

	// ProtocolCharacteristics specify connection settings (TODO: details).
	ProtocolCharacteristics NTProtocolCharacteristics

	// TODO
	MaxBeforeAck uint16

	// ByteOrder gives the encoding of the integer 1 as a 16-bit integer with
	// the client's desired endianness.
	ByteOrder [2]byte

	// DataLength gives the length of the connection string.
	DataLength uint16

	// DataOffset gives the offset (from the start of the header) of the
	// connection string.
	DataOffset uint16

	// MaxResponseSize gives the client's desired maximum response size.
	MaxResponseSize uint32

	// ConnectFlags0 specifies connection settings (TODO: details).
	ConnectFlags0 ConnectFlags

	// ConnectFlags1 specifies connection settings (TODO: details).
	ConnectFlags1 ConnectFlags

	// TODO
	CrossFacility0 uint32
	// TODO
	CrossFacility1 uint32

	// TODO
	ConnectionID0 [8]byte

	// TODO
	ConnectionID1 [8]byte

	// Unknown3A is the data between the last trace unique connection ID and the
	// connection string, starting from offset 0x3A.
	// The DataOffset points past this, and the DataLength counts from there, so
	// this is indeed part of the "header".
	// On recent versions of MSSQL this is 12 bytes.
	// On older versions, it is 0 bytes.
	Unknown3A []byte

	// ConnectionString is the packet's payload, a nested sequence of
	// (KEY=(KEY1=...)(KEY2=...)).
	ConnectionString string
}

// outputBuffer provides helper methods to write data to a pre-allocated buffer.
type outputBuffer []byte

func (buf *outputBuffer) Write(data []byte) (int, error) {
	if len(data) > len(*buf) {
		return 0, ErrBufferTooSmall
	}
	buf.push(data)
	return len(data), nil
}

func (buf *outputBuffer) push(data []byte) *outputBuffer {
	current := *buf
	copy(current[0:len(data)], data)
	*buf = current[len(data):]
	return buf
}

func (buf *outputBuffer) pushU8(v uint8) *outputBuffer {
	(*buf)[0] = v
	*buf = (*buf)[1:]
	return buf
}

func (buf *outputBuffer) pushU16(v uint16) *outputBuffer {
	current := *buf
	binary.BigEndian.PutUint16(current, v)
	*buf = current[2:]
	return buf
}

func (buf *outputBuffer) pushU32(v uint32) *outputBuffer {
	current := *buf
	binary.BigEndian.PutUint32(current, v)
	*buf = current[4:]
	return buf
}

// Copy data to dest, return the byte immediately following dest
func push(dest []byte, data []byte) []byte {
	copy(dest[0:len(data)], data)
	return dest[len(data):]
}

func pushU16(dest []byte, v uint16) []byte {
	binary.BigEndian.PutUint16(dest[0:2], v)
	return dest[2:]
}

func pushU32(dest []byte, v uint32) []byte {
	binary.BigEndian.PutUint32(dest[0:4], v)
	return dest[4:]
}

func pushU8(dest []byte, v uint8) []byte {
	dest[0] = v
	return dest[1:]
}

func (packet *TNSConnect) Encode() []byte {
	length := 0x3A + len(packet.Unknown3A) + len(packet.ConnectionString)
	if length > 255 {
		temp := packet.ConnectionString
		defer func() {
			packet.ConnectionString = temp
		}()
		packet.ConnectionString = ""
		return append(packet.Encode(), []byte(temp)...)
	}

	ret := make([]byte, length-8)
	next := outputBuffer(ret)

	next.pushU16(packet.Version)
	next.pushU16(packet.MinVersion)
	next.pushU16(uint16(packet.GlobalServiceOptions))
	next.pushU16(packet.SDU)
	next.pushU16(packet.TDU)
	next.pushU16(uint16(packet.ProtocolCharacteristics))
	next.pushU16(packet.MaxBeforeAck)
	next.push(packet.ByteOrder[:])
	next.pushU16(packet.DataLength)
	next.pushU16(packet.DataOffset)
	next.pushU32(packet.MaxResponseSize)
	next.pushU8(uint8(packet.ConnectFlags0))
	next.pushU8(uint8(packet.ConnectFlags1))
	next.pushU32(packet.CrossFacility0)
	next.pushU32(packet.CrossFacility1)
	next.push(packet.ConnectionID0[:])
	next.push(packet.ConnectionID1[:])
	next.push(packet.Unknown3A)
	next.push([]byte(packet.ConnectionString))
	return ret
}

func (header *TNSConnect) String() string {
	ret, err := json.Marshal(*header)
	if err != nil {
		return fmt.Sprintf("(error encoding %v: %v)", header, err)
	}
	return string(ret)
}

func unpanic() error {
	if rerr := recover(); rerr != nil {
		switch err := rerr.(type) {
		case error:
			return err
		default:
			panic(rerr)
		}
	}
	return nil
}

func ReadTNSConnect(reader io.Reader, header *TNSHeader) (ret *TNSConnect, thrown error) {
	defer func() {
		if err := unpanic(); err != nil {
			thrown = err
		}
	}()
	ret = new(TNSConnect)
	ret.Version = readU16(reader)
	ret.MinVersion = readU16(reader)
	ret.GlobalServiceOptions = ServiceOptions(readU16(reader))
	ret.SDU = readU16(reader)
	ret.TDU = readU16(reader)
	ret.ProtocolCharacteristics = NTProtocolCharacteristics(readU16(reader))
	ret.MaxBeforeAck = readU16(reader)
	if _, err := io.ReadFull(reader, ret.ByteOrder[:]); err != nil {
		return nil, err
	}
	ret.DataLength = readU16(reader)
	ret.DataOffset = readU16(reader)
	ret.MaxResponseSize = readU32(reader)
	ret.ConnectFlags0 = ConnectFlags(readU8(reader))
	ret.ConnectFlags1 = ConnectFlags(readU8(reader))
	ret.CrossFacility0 = readU32(reader)
	ret.CrossFacility1 = readU32(reader)
	if _, err := io.ReadFull(reader, ret.ConnectionID0[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(reader, ret.ConnectionID1[:]); err != nil {
		return nil, err
	}
	unknownLen := ret.DataOffset - 0x3A
	ret.Unknown3A = make([]byte, unknownLen)
	if _, err := io.ReadFull(reader, ret.Unknown3A); err != nil {
		return nil, err
	}
	data := make([]byte, ret.DataLength)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, err
	}
	ret.ConnectionString = string(data)
	return ret, nil
}

func (packet *TNSConnect) GetType() PacketType {
	return PacketTypeConnect
}

// TNSResend is just a header with type = PacketTypeResend (0x0b == 11)
type TNSResend struct {
}

func (packet *TNSResend) Encode() []byte {
	return []byte{}
}

func (packet *TNSResend) GetType() PacketType {
	return PacketTypeResend
}

func ReadTNSResend(reader io.Reader, header *TNSHeader) (*TNSResend, error) {
	ret := TNSResend{}
	return &ret, nil
}

// TODO: TNSConnect.Decode()

type TNSAccept struct {
	// 08..09: 0x0136 / 0x0134?
	Version uint16
	// 0A..0B: 0x0801
	GlobalServiceOptions ServiceOptions
	// 0C..0D: 0x0800
	SDU uint16
	// 0E..0F: 0x7fff
	TDU uint16
	// 10..11: 01 00
	ByteOrder [2]byte
	// 12..13: 0x0000
	DataLength uint16
	// 14..15: 0x0020
	DataOffset uint16
	// 16..17: 0x0101
	ConnectFlags0 ConnectFlags
	ConnectFlags1 ConnectFlags

	// Unknown18 provides support for case like TNSConnect, where there is
	// "data" after the end of the known packet but before the start of the
	// AcceptData pointed to by DataOffset.
	// Currently this is always 8 bytes.
	Unknown18  []byte
	AcceptData []byte
}

func popU8(buf []byte) (uint8, []byte) {
	return uint8(buf[0]), buf[1:]
}

func popU16(buf []byte) (uint16, []byte) {
	return binary.BigEndian.Uint16(buf[0:2]), buf[2:]
}

func popU32(buf []byte) (uint32, []byte) {
	return binary.BigEndian.Uint32(buf[0:4]), buf[4:]
}

func popN(buf []byte, n int) ([]byte, []byte) {
	return buf[0:n], buf[n:]
}

func (packet *TNSAccept) Encode() []byte {
	length := 16 + len(packet.Unknown18) + len(packet.AcceptData)
	ret := make([]byte, length)
	next := outputBuffer(ret)
	next.pushU16(packet.Version)
	next.pushU16(uint16(packet.GlobalServiceOptions))
	next.pushU16(packet.SDU)
	next.pushU16(packet.TDU)
	next.push(packet.ByteOrder[:])
	// packet.DataLength = len(packet.AcceptData)
	// packet.DataOffset = 8 + 16 + len(packet.Unknown18) // TNSHeader + accept header + unknown
	next.pushU16(packet.DataLength)
	next.pushU16(packet.DataOffset)
	next.pushU8(uint8(packet.ConnectFlags0))
	next.pushU8(uint8(packet.ConnectFlags1))
	next.push(packet.Unknown18)
	next.push(packet.AcceptData)
	return ret
}

func (packet *TNSAccept) GetType() PacketType {
	return PacketTypeAccept
}

func readU8(reader io.Reader) uint8 {
	buf := make([]byte, 1)
	_, err := io.ReadFull(reader, buf)
	if err != nil {
		panic(err)
	}
	return buf[0]
}

func readU16(reader io.Reader) uint16 {
	buf := make([]byte, 2)
	_, err := io.ReadFull(reader, buf)
	if err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint16(buf)
}

func readU32(reader io.Reader) uint32 {
	buf := make([]byte, 4)
	_, err := io.ReadFull(reader, buf)
	if err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint32(buf)
}

func ReadTNSAccept(reader io.Reader, header *TNSHeader) (ret *TNSAccept, thrown error) {
	defer func() {
		if err := unpanic(); err != nil {
			thrown = err
		}
	}()
	ret = new(TNSAccept)
	ret.Version = readU16(reader)
	ret.GlobalServiceOptions = ServiceOptions(readU16(reader))
	ret.SDU = readU16(reader)
	ret.TDU = readU16(reader)
	if _, err := io.ReadFull(reader, ret.ByteOrder[:]); err != nil {
		return nil, err
	}
	ret.DataLength = readU16(reader)
	ret.DataOffset = readU16(reader)
	ret.ConnectFlags0 = ConnectFlags(readU8(reader))
	ret.ConnectFlags1 = ConnectFlags(readU8(reader))
	unknownLen := ret.DataOffset - 16 - 8
	ret.Unknown18 = make([]byte, unknownLen)
	if _, err := io.ReadFull(reader, ret.Unknown18); err != nil {
		return nil, err
	}
	ret.AcceptData = make([]byte, ret.DataLength)
	if _, err := io.ReadFull(reader, ret.AcceptData); err != nil {
		return nil, err
	}
	return ret, nil
}

type RefuseReason uint8

type TNSRefuse struct {
	// 08: 01
	AppReason RefuseReason
	// 09: 00
	SysReason RefuseReason
	// 0A..0B: 0010
	DataLength uint16
	// 0C...
	Data []byte
}

type TNSRedirect struct {
	DataLength uint16
	Data       []byte
}

type ReleaseVersion uint32

func (v ReleaseVersion) String() string {
	// 0xAAbcddee -> A.b.c.d.e, major.maintenance.appserver.component.platform
	// See https://docs.oracle.com/cd/B28359_01/server.111/b28310/dba004.htm
	return fmt.Sprintf("%d.%d.%d.%d.%d", v>>24, v>>20&0x0F, v>>16&0x0F, v>>8&0xFF, v&0xFF)
}

func (v ReleaseVersion) Bytes() []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(v))
	return buf
}

func EncodeReleaseVersion(value string) ReleaseVersion {
	parts := strings.Split(value, ".")
	if len(parts) != 5 {
		panic(ErrInvalidInput)
	}
	numbers := make([]uint32, 5)
	maxValue := []int{
		255,
		15,
		15,
		255,
		255,
	}
	for i, v := range parts {
		n, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			panic(ErrInvalidInput)
		}
		if int(n) > maxValue[i] {
			panic(ErrInvalidInput)
		}
		numbers[i] = uint32(n)
	}
	return ReleaseVersion((numbers[0] << 24) | (numbers[1] << 20) | (numbers[2] << 16) | (numbers[3] << 8) | numbers[4])
}

type DataFlags uint16

const (
	DFSendToken           DataFlags = 0x0001
	DFRequestConfirmation           = 0x0002
	DFConfirmation                  = 0x0004
	DFReserved                      = 0x0008
	DFUnknown0010                   = 0x0010
	DFMoreData                      = 0x0020
	DFEOF                           = 0x0040
	DFConfirmImmediately            = 0x0080
	DFRequestToSend                 = 0x0100
	DFSendNTTrailer                 = 0x0200
	DFUnknown0400                   = 0x0400
	DFUnknown0800                   = 0x0800
	DFUnknown1000                   = 0x1000
	DFUnknown2000                   = 0x2000
	DFUnknown4000                   = 0x4000
	DFUnknown8000                   = 0x8000
)

var dfNames = map[DataFlags]string{
	DFSendToken:           "SEND_TOKEN",
	DFRequestConfirmation: "REQUEST_CONFIRMATION",
	DFConfirmation:        "CONFIRMATION",
	DFReserved:            "RESERVED",
	DFUnknown0010:         "UNKNOWN_0010",
	DFMoreData:            "MORE_DATA",
	DFEOF:                 "EOF",
	DFConfirmImmediately:  "CONFIRM_IMMEDIATELY",
	DFRequestToSend:       "RTS",
	DFSendNTTrailer:       "SEND_NT_TRAILER",
	DFUnknown0400:         "UNKNOWN_0400",
	DFUnknown0800:         "UNKNOWN_0800",
	DFUnknown1000:         "UNKNOWN_1000",
	DFUnknown2000:         "UNKNOWN_2000",
	DFUnknown4000:         "UNKNOWN_4000",
	DFUnknown8000:         "UNKNOWN_8000",
}

func (flags DataFlags) Set() map[string]bool {
	ret, _ := zgrab2.MapFlagsToSet(uint64(flags), func(bit uint64) (string, error) {
		return dfNames[DataFlags(bit)], nil
	})
	// there are no unknowns since all 16 flags are accounted for in dfNames
	return ret
}

type TNSData struct {
	// 08..09
	DataFlags DataFlags
	// 0A...
	Data []byte
}

type DataType uint8

const (
	DataTypeSetProtocol           DataType = 0x01
	DataTypeSecureNetworkServices          = 0x06
)

const (
	DataIDNSN uint32 = 0xdeadbeef
)

func (packet *TNSData) GetID() uint32 {
	if len(packet.Data) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(packet.Data[0:4])
}

func (packet *TNSData) Encode() []byte {
	ret := make([]byte, len(packet.Data)+2)
	next := outputBuffer(ret)
	next.pushU16(uint16(packet.DataFlags))
	next.push(packet.Data)
	return ret
}

func (packet *TNSData) GetType() PacketType {
	return PacketTypeData
}

func ReadTNSData(reader io.Reader, header *TNSHeader) (ret *TNSData, thrown error) {
	defer func() {
		if err := unpanic(); err != nil {
			thrown = err
		}
	}()
	ret = new(TNSData)
	ret.DataFlags = DataFlags(readU16(reader))
	ret.Data = make([]byte, header.Length-8-2)
	n, err := reader.Read(ret.Data)
	if err != nil {
		return nil, err
	}
	if n != len(ret.Data) {
		return nil, ErrInvalidData
	}
	return ret, nil
}

type NSNServiceType uint16

const (
	NSNServiceAuthentication NSNServiceType = 1
	NSNServiceEncryption                    = 2
	NSNServiceDataIntegrity                 = 3
	NSNServiceSupervisor                    = 4
)

var nsnServiceTypeToName = map[NSNServiceType]string{
	NSNServiceAuthentication: "Authentication",
	NSNServiceEncryption:     "Encryption",
	NSNServiceDataIntegrity:  "DataIntegrity",
	NSNServiceSupervisor:     "Supervisor",
}

func (typ NSNServiceType) String() string {
	ret, ok := nsnServiceTypeToName[typ]
	if !ok {
		return fmt.Sprintf("Unknown(0x%x)", uint16(typ))
	}
	return ret
}

func (typ NSNServiceType) IsUnknown() bool {
	_, ok := nsnServiceTypeToName[typ]
	return !ok
}

// NSN packets somewhat described here: https://docs.oracle.com/cd/B19306_01/network.102/b14212/troublestng.htm
type NSNService struct {
	Type   NSNServiceType
	Values []NSNValue
	Marker uint32
}

func (service *NSNService) GetSize() uint16 {
	ret := uint32(8) // uint16(Type) + uint16(#values) + uint32(marker)
	for _, v := range service.Values {
		ret += uint32(len(v.Value) + 4)
	}
	if ret > 0xffff {
		// This cannot happen when reading data from the server, only when
		// constructing data to send to it.
		panic(ErrInvalidInput)
	}
	return uint16(ret)
}

func (service *NSNService) Encode() []byte {
	// Absolute minimum, if each value had zero length
	ret := make([]byte, service.GetSize())
	next := outputBuffer(ret)
	next.pushU16(uint16(service.Type))
	if len(service.Values) > 0xffff {
		// This is covered by GetSize, but if that were to change, catch this
		// separate issue
		panic(ErrInvalidInput)
	}
	next.pushU16(uint16(len(service.Values)))
	next.pushU32(service.Marker)
	for _, value := range service.Values {
		next.push(value.Encode())
	}
	return ret
}

func ReadNSNService(reader io.Reader, ret *NSNService) (*NSNService, error) {
	if ret == nil {
		ret = &NSNService{}
	}
	ret.Type = NSNServiceType(readU16(reader))
	n := int(readU16(reader))
	if n > 0x0400 {
		// Arbitrary but sufficiently huge cut off. Typical values are single
		// digits. The total encoded size must fit into 16 bits.
		return nil, ErrInvalidData
	}
	ret.Marker = readU32(reader)
	// Check if Marker == 0?
	ret.Values = make([]NSNValue, n)
	for i := 0; i < n; i++ {
		_, err := ReadNSNValue(reader, &ret.Values[i])
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

type NSNValueType uint16

const (
	NSNValueTypeString  NSNValueType = 0
	NSNValueTypeBytes                = 1
	NSNValueTypeUB1                  = 2
	NSNValueTypeUB2                  = 3
	NSNValueTypeUB4                  = 4
	NSNValueTypeVersion              = 5
	NSNValueTypeStatus               = 6
)

type NSNValue struct {
	Type  NSNValueType
	Value []byte
}

func (value *NSNValue) String() string {
	switch value.Type {
	case NSNValueTypeString:
		return string(value.Value)
	case NSNValueTypeBytes:
		return base64.StdEncoding.EncodeToString(value.Value)
	case NSNValueTypeUB1:
		return fmt.Sprintf("%d", value.Value[0])
	case NSNValueTypeUB4:
		return fmt.Sprintf("%d", binary.BigEndian.Uint32(value.Value))
	case NSNValueTypeVersion:
		return ReleaseVersion(binary.BigEndian.Uint32(value.Value)).String()
	case NSNValueTypeStatus:
		fallthrough
	case NSNValueTypeUB2:
		return fmt.Sprintf("%d", binary.BigEndian.Uint16(value.Value))
	default:
		return base64.StdEncoding.EncodeToString(value.Value)
	}
}

func (value *NSNValue) MarshalJSON() ([]byte, error) {
	type Aux struct {
		Type  NSNValueType
		Value interface{}
	}
	ret := Aux{
		Type: value.Type,
	}
	switch value.Type {
	case NSNValueTypeString:
		ret.Value = string(value.Value)
	case NSNValueTypeBytes:
		ret.Value = value.Value
	case NSNValueTypeUB1:
		ret.Value = value.Value[0]
	case NSNValueTypeUB4:
		ret.Value = binary.BigEndian.Uint32(value.Value)
	case NSNValueTypeVersion:
		ret.Value = ReleaseVersion(binary.BigEndian.Uint32(value.Value)).String()
	case NSNValueTypeStatus:
		fallthrough
	case NSNValueTypeUB2:
		ret.Value = binary.BigEndian.Uint16(value.Value)
	default:
		ret.Value = value.Value
	}
	return json.Marshal(ret)
}

func NSNValueVersion(v string) *NSNValue {
	return &NSNValue{
		Type:  5,
		Value: EncodeReleaseVersion(v).Bytes(),
	}
}

func NSNValueBytes(bytes []byte) *NSNValue {
	return &NSNValue{
		Type:  1,
		Value: bytes,
	}
}

func NSNValueUB1(val uint8) *NSNValue {
	return &NSNValue{
		Type:  2,
		Value: []byte{val},
	}
}

func NSNValueUB2(val uint16) *NSNValue {
	ret := make([]byte, 2)
	binary.BigEndian.PutUint16(ret, val)
	return &NSNValue{
		Type:  3,
		Value: ret,
	}
}

func NSNValueStatus(val uint16) *NSNValue {
	ret := NSNValueUB2(val)
	ret.Type = 6
	return ret
}

func NSNValueString(val string) *NSNValue {
	return &NSNValue{
		Type:  0,
		Value: []byte(val),
	}
}

func (value *NSNValue) Encode() []byte {
	if len(value.Value) > 0xffff {
		panic(ErrInvalidInput)
	}
	ret := make([]byte, 4+len(value.Value))
	if len(value.Value) > 0xffff {
		panic(ErrInvalidInput)
	}
	next := outputBuffer(ret)
	next.pushU16(uint16(len(value.Value)))
	next.pushU16(uint16(value.Type))
	next.push(value.Value)
	return ret
}

func ReadNSNValue(reader io.Reader, ret *NSNValue) (*NSNValue, error) {
	if ret == nil {
		ret = &NSNValue{}
	}
	size := readU16(reader)
	ret.Type = NSNValueType(readU16(reader))
	ret.Value = make([]byte, size)
	n, err := reader.Read(ret.Value)
	if err != nil {
		return nil, err
	}
	if n != len(ret.Value) {
		return nil, ErrInvalidData
	}
	return ret, nil
}

type NSNOptions uint8

type TNSDataNSN struct {
	Version  ReleaseVersion
	Options  NSNOptions
	Services []NSNService
}

func (packet *TNSDataNSN) GetSize() uint16 {
	ret := uint32(13) // uint32(id) + uint16(len) + uint32(version) + uint16(#services) + uint8(options)
	for _, v := range packet.Services {
		ret += uint32(v.GetSize())
	}
	if ret > 0xffff {
		// This cannot happen when reading data from the server, only when
		// constructing data to send to it.
		panic(ErrInvalidInput)
	}
	return uint16(ret)
}

func (packet *TNSDataNSN) Encode() []byte {
	size := packet.GetSize()
	ret := make([]byte, size)
	next := outputBuffer(ret)
	next.pushU32(uint32(DataIDNSN))
	next.pushU16(size)
	next.pushU32(uint32(packet.Version))
	if len(packet.Services) > 0xffff {
		panic(ErrInvalidInput)
	}
	next.pushU16(uint16(len(packet.Services)))
	next.pushU8(uint8(packet.Options))
	for _, v := range packet.Services {
		next.push(v.Encode())
	}
	return ret
}

func DecodeTNSDataNSN(data []byte) (*TNSDataNSN, error) {
	reader := getSliceReader(data)
	ret := TNSDataNSN{}
	tag := readU32(reader)
	if tag != DataIDNSN {
		return nil, ErrUnexpectedResponse
	}
	length := readU16(reader)
	if len(data) != int(length) {
		// if we have 0xdeadbeef, but the length is incorrect, that would
		// indicate truncation or corruption
		return nil, ErrInvalidData
	}
	ret.Version = ReleaseVersion(readU32(reader))
	n := int(readU16(reader))
	if n > 0x0400 {
		// arbitrary but certainly sufficiently-high value.
		return nil, ErrInvalidData
	}
	ret.Options = NSNOptions(readU8(reader))
	// TODO: Check for valid options?
	ret.Services = make([]NSNService, n)
	for i := 0; i < n; i++ {
		_, err := ReadNSNService(reader, &ret.Services[i])
		if err != nil {
			return nil, err
		}
	}
	return &ret, nil
}

type TNSDataSetProtocolRequest struct {
	// 08..09
	DataFlags DataFlags
	// 0A
	DataType DataType
	// 0B...(null)
	AcceptedVersions []byte
	// ...
	ClientPlatform string
}

type TNSDataSetProtocolResponse struct {
	// 08..09
	DataFlags DataFlags
	// 0A
	DataType DataType
	// 0B...(null)
	AcceptedVersions []byte
	// ...(null)
	ServerBanner string
	// ...
	Data []byte
}

type TNSPacketBody interface {
	GetType() PacketType
	Encode() []byte
}

type TNSPacket struct {
	Header *TNSHeader
	Body   TNSPacketBody
}

type InputTNSPacket struct {
	TNSPacket
	Raw []byte
}

func (packet *TNSPacket) Encode() []byte {
	body := packet.Body.Encode()
	if packet.Header == nil {
		packet.Header = &TNSHeader{
			Length:         0,
			PacketChecksum: 0,
			Type:           packet.Body.GetType(),
			// Flags -- aka Reserved Byte -- is "04" in some Connect packets?
			Flags:          0,
			HeaderChecksum: 0,
		}
	}
	if packet.Header.Length == 0 {
		// It is up to the user to check the body length for overflows before calling Encode
		packet.Header.Length = uint16(len(body) + 8)
	}
	header := packet.Header.Encode()
	return append(header, body...)
}

func ReadTNSPacket(reader io.Reader) (*TNSPacket, error) {
	var body TNSPacketBody
	var err error
	header, err := ReadTNSHeader(reader)
	if err != nil {
		return nil, err
	}
	switch header.Type {
	case PacketTypeConnect:
		body, err = ReadTNSConnect(reader, header)
	case PacketTypeAccept:
		body, err = ReadTNSAccept(reader, header)
	case PacketTypeResend:
		body, err = ReadTNSResend(reader, header)
	case PacketTypeData:
		body, err = ReadTNSData(reader, header)
	default:
		err = ErrInvalidData
	}
	return &TNSPacket{
		Header: header,
		Body:   body,
	}, err
}

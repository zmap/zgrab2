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
	ErrInvalidData = errors.New("server returned invalid data")

	// ErrInvalidInput is returned when user-supplied data is not valid.
	ErrInvalidInput = errors.New("caller provided invalid input")

	// ErrUnexpectedResponse is returned when the server returns a valid TNS
	// response but it is not the expected type.
	ErrUnexpectedResponse = errors.New("server returned unexpected response")

	// ErrBufferTooSmall is returned when the caller provides a buffer that is
	// too small for the required data.
	ErrBufferTooSmall = errors.New("buffer too small")
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
	// client, containing the connect descriptor).
	PacketTypeConnect PacketType = 1

	// PacketTypeAccept identifies an Accept packet (the server's response to
	// a Connect packet, contains some server configuration flags).
	PacketTypeAccept = 2

	// PacketTypeAcknowledge identifies an Acknowledge packet.
	PacketTypeAcknowledge = 3

	// PacketTypeRefuse identifies a Refuse packet. Sent when e.g. the connect
	// descriptor is incorrect.
	PacketTypeRefuse = 4

	// PacketTypeRedirect idenfies a Redirect packet. The server can respond to
	// a Connect packet with a Redirect containing a new connect descriptor.
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
		return fmt.Sprintf("UNKNOWN(0x%02x)", uint8(packetType))
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

// TNSMode determines the format of the TNSHeader; used in TNSDriver.
type TNSMode int

const (
	// TNSModeOld uses the pre-12c format TNSHeader, with 16-bit lengths.
	TNSModeOld TNSMode = 0

	// TNSMode12c uses the newer TNSHeader format, with 32-bit lengths and no
	// PacketChecksum.
	TNSMode12c = 1
)

// TNSDriver abstracts the bottom-level TNS packet encoding.
type TNSDriver struct {
	// Mode determines what type of packets will be sent -- TNSModeOld or
	// TNSMode12c.
	Mode TNSMode
}

// EncodePacket encodes the packet (header + body). If header is nil, create one
// with no flags and the type set to the body's type. If header.Length == 0, set
// it to the appropriate value (length of encoded body + 8).
func (driver *TNSDriver) EncodePacket(packet *TNSPacket) ([]byte, error) {
	body, err := packet.Body.Encode()
	if err != nil {
		return nil, err
	}
	if packet.Header == nil {
		packet.Header = &TNSHeader{
			mode:           driver.Mode,
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
		if driver.Mode == TNSModeOld {
			if (len(body) + 8) > 0xffff {
				return nil, ErrInvalidInput
			}
			packet.Header.Length = uint32(len(body) + 8)
		} else {
			packet.Header.Length = uint32(len(body) + 8)
		}
	}
	header, err := packet.Header.Encode()
	if err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

// TNSFlags is the type for the TNS header's flags.
type TNSFlags uint8

// TNSHeader is the 8-byte header that precedes all TNS packets.
type TNSHeader struct {
	// mode used for encoding / decoding this packet.
	mode TNSMode

	// Length is the big-endian length of the entire packet, including the 8
	// bytes of the header itself.
	// For versions prior to 12(c?), the length is a uint16. For newer versions,
	// it is a uint32 (taking the place of the PacketChecksum)
	Length uint32

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
func (header *TNSHeader) Encode() ([]byte, error) {
	ret := make([]byte, 8)
	next := outputBuffer(ret)
	switch header.mode {
	case TNSModeOld:
		if header.Length > 0xffff {
			return nil, ErrInvalidInput
		}
		next.pushU16(uint16(header.Length))
		next.pushU16(header.PacketChecksum)
		next.pushU8(byte(header.Type))
		next.pushU8(byte(header.Flags))
		next.pushU16(header.HeaderChecksum)
	case TNSMode12c:
		next.pushU32(header.Length)
		next.pushU8(byte(header.Type))
		next.pushU8(byte(header.Flags))
		next.pushU16(header.HeaderChecksum)
	default:
		return nil, ErrInvalidInput
	}
	return ret, nil
}

// ReadTNSHeader reads/decodes a TNSHeader from the first 8 bytes of the stream.
func (driver *TNSDriver) ReadTNSHeader(reader io.Reader) (*TNSHeader, error) {
	ret := TNSHeader{}
	ret.mode = driver.Mode
	next := startReading(reader)
	switch driver.Mode {
	case TNSModeOld:
		var length uint16
		next.read(&length)
		ret.Length = uint32(length)
		next.read(&ret.PacketChecksum)
		next.read(&ret.Type)
		next.read(&ret.Flags)
		next.read(&ret.HeaderChecksum)
	case TNSMode12c:
		next.read(&ret.Length)
		next.read(&ret.Type)
		next.read(&ret.Flags)
		next.read(&ret.HeaderChecksum)
	}
	if err := next.Error(); err != nil {
		return nil, err
	}
	return &ret, nil
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

	// DataLength gives the length of the connect descriptor.
	DataLength uint16

	// DataOffset gives the offset (from the start of the header) of the
	// connect descriptor -- i.e. 0x3A + len(Unknown3A).
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
	// connect descriptor, starting from offset 0x3A.
	// The DataOffset points past this, and the DataLength counts from there, so
	// this is indeed part of the "header".
	// On recent versions of Oracle this is 12 bytes.
	// On older versions, it is 0 bytes.
	Unknown3A []byte

	// ConnectDescriptor is the packet's payload, a nested sequence of
	// (KEY=(KEY1=...)(KEY2=...)). See Oracle's "About Connect Descriptors" at
	// https://docs.oracle.com/cd/E11882_01/network.112/e41945/concepts.htm#NETAG253
	ConnectDescriptor string
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

// Encode the TNSConnect packet body into a newly-allocated buffer. If the
// packet would be longer than 255 bytes, the data is empty and the connection
// string immediately follows.
func (packet *TNSConnect) Encode() ([]byte, error) {
	length := 0x3A + len(packet.Unknown3A) + len(packet.ConnectDescriptor)
	if length > 255 {
		temp := packet.ConnectDescriptor
		defer func() {
			packet.ConnectDescriptor = temp
		}()
		packet.ConnectDescriptor = ""
		ret, err := packet.Encode()
		if err != nil {
			return nil, err
		}
		return append(ret, []byte(temp)...), nil
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
	next.push([]byte(packet.ConnectDescriptor))
	return ret, nil
}

// chainedReader is a helper for decoding binary data from a stream, primarily
// to remove the need to check for an error after each read. If an error occurs,
// subsequent calls are all noops.
type chainedReader struct {
	reader    io.Reader
	byteOrder binary.ByteOrder
	err       error
}

// startReading returns a new BigEndian chainedReader for the given io.Reader.
func startReading(reader io.Reader) *chainedReader {
	return &chainedReader{reader: reader, byteOrder: binary.BigEndian}
}

// read the value from the stream, unless there was a previous error on the
// reader. Uses binary.Read() to decode the data. dest must be a pointer.
func (reader *chainedReader) read(dest interface{}) *chainedReader {
	if reader.err != nil {
		return reader
	}
	reader.err = binary.Read(reader.reader, binary.BigEndian, dest)
	return reader
}

// readNew allocates a new buffer to read size bytes from the stream and stores
// the buffer in *dest, unless there was a previous error on the reader.
func (reader *chainedReader) readNew(dest *[]byte, size int) *chainedReader {
	if reader.err != nil {
		return reader
	}
	ret := make([]byte, size)
	_, err := io.ReadFull(reader.reader, ret)
	reader.err = err
	*dest = ret
	return reader
}

// readNew allocates a new buffer to read size bytes from the stream and stores
// the buffer in *dest as a string, unless there was a previous error on the
// reader.
func (reader *chainedReader) readNewString(dest *string, size int) *chainedReader {
	if reader.err != nil {
		return reader
	}
	var data []byte
	reader.readNew(&data, size)
	*dest = string(data)
	return reader
}

// Error returns nil if there were no errors during reading, otherwise, it
// returns the error.
func (reader *chainedReader) Error() error {
	return reader.err
}

// readU16 reads and returns an unsigned 16-bit integer, unless there was an
// error, in which case the error is returned.
func (reader *chainedReader) readU16() (uint16, error) {
	var ret uint16
	reader.read(&ret)
	return ret, reader.err
}

// Read implements the io.Reader interface for the chainedReader; forwards the
// call to the underlying reader, unless there was a previous error, in which
// case the error is returned immediately.
// If the underlying reader.Read call fails, that error is returned to the
// caller and also stored in the stream's err property.
func (reader *chainedReader) Read(buf []byte) (int, error) {
	if reader.err != nil {
		return 0, reader.err
	}
	n, err := reader.reader.Read(buf)
	reader.err = err
	return n, err
}

// ReadTNSConnect reads a TNSConnect packet from the reader, which should point
// to the first byte after the end of the TNSHeader.
func ReadTNSConnect(reader io.Reader, header *TNSHeader) (*TNSConnect, error) {
	ret := new(TNSConnect)
	next := startReading(reader)
	next.read(&ret.Version)
	next.read(&ret.MinVersion)
	next.read(&ret.GlobalServiceOptions)
	next.read(&ret.SDU)
	next.read(&ret.TDU)
	next.read(&ret.ProtocolCharacteristics)
	next.read(&ret.MaxBeforeAck)
	next.read(&ret.ByteOrder)
	next.read(&ret.DataLength)
	next.read(&ret.DataOffset)
	next.read(&ret.MaxResponseSize)
	next.read(&ret.ConnectFlags0)
	next.read(&ret.ConnectFlags1)
	next.read(&ret.CrossFacility0)
	next.read(&ret.CrossFacility1)
	next.read(&ret.ConnectionID0)
	next.read(&ret.ConnectionID1)
	unknownLen := ret.DataOffset - 0x3A
	next.readNew(&ret.Unknown3A, int(unknownLen))
	next.readNewString(&ret.ConnectDescriptor, int(ret.DataLength))
	if err := next.Error(); err != nil {
		return nil, err
	}
	return ret, nil
}

// GetType identifies the packet as a PacketTypeConnect.
func (packet *TNSConnect) GetType() PacketType {
	return PacketTypeConnect
}

// TNSResend is empty -- the entire packet is just a header with a type of
// PacketTypeResend (0x0b == 11).
type TNSResend struct {
}

// Encode the packet body (which for a Resend packet just means returning an
// empty byte slice).
func (packet *TNSResend) Encode() ([]byte, error) {
	return []byte{}, nil
}

// GetType identifies the packet as a PacketTypeResend.
func (packet *TNSResend) GetType() PacketType {
	return PacketTypeResend
}

// ReadTNSResend reads a TNSResend packet from the reader, which should point
// to the first byte after the end of the header -- so in this case, it reads
// nothing and returns an empty TNSResend{} instance.
func ReadTNSResend(reader io.Reader, header *TNSHeader) (*TNSResend, error) {
	ret := TNSResend{}
	return &ret, nil
}

// TNSAccept is the server's response to a successful TNSConnect request from
// the client.
type TNSAccept struct {
	// Version is the protocol version the server is using. TODO: find the
	// actual format.
	Version uint16

	// GlobalServiceOptions specify connection settings (TODO: details).
	GlobalServiceOptions ServiceOptions

	// SDU gives the Session Data Unit size for this connection.
	SDU uint16

	// TDU gives the Transfer Data Unit size for this connection.
	TDU uint16

	// ByteOrder gives the encoding of the integer 1 as a 16-bit integer
	// (NOTE: clients and servers seem to routinely send a little-endian 1,
	// while clearly using big-endian encoding for integers, at least at the
	// TNS layer...?)
	ByteOrder [2]byte

	// DataLength is the length of the AcceptData payload.
	DataLength uint16

	// DataOffset is the offset from the start of the packet (including the
	// 8 bytes of the header) of the AcceptData. Always (?) 0x20.
	DataOffset uint16

	// ConnectFlags0 specifies connection settings (TODO: details).
	ConnectFlags0 ConnectFlags

	// ConnectFlags1 specifies connection settings (TODO: details).
	ConnectFlags1 ConnectFlags

	// Unknown18 provides support for case like TNSConnect, where there is
	// "data" after the end of the known packet but before the start of the
	// AcceptData pointed to by DataOffset.
	// Currently this is always 8 bytes.
	Unknown18 []byte

	// AcceptData is the packet payload (TODO: details).
	AcceptData []byte
}

// Encode the TNSAccept packet body into a newly-allocated byte slice.
func (packet *TNSAccept) Encode() ([]byte, error) {
	length := 16 + len(packet.Unknown18) + len(packet.AcceptData)
	if length > 0xffff {
		return nil, ErrInvalidData
	}
	ret := make([]byte, length)
	next := outputBuffer(ret)
	next.pushU16(packet.Version)
	next.pushU16(uint16(packet.GlobalServiceOptions))
	next.pushU16(packet.SDU)
	next.pushU16(packet.TDU)
	next.push(packet.ByteOrder[:])
	next.pushU16(packet.DataLength)
	next.pushU16(packet.DataOffset)
	next.pushU8(uint8(packet.ConnectFlags0))
	next.pushU8(uint8(packet.ConnectFlags1))
	next.push(packet.Unknown18)
	next.push(packet.AcceptData)
	return ret, nil
}

// GetType identifies the packet as a PacketTypeAccept.
func (packet *TNSAccept) GetType() PacketType {
	return PacketTypeAccept
}

// ReadTNSAccept reads a TNSAccept packet body from the stream. reader should
// point to the first byte after the TNSHeader.
func ReadTNSAccept(reader io.Reader, header *TNSHeader) (*TNSAccept, error) {
	ret := new(TNSAccept)
	next := startReading(reader)
	next.read(&ret.Version)
	next.read(&ret.GlobalServiceOptions)
	next.read(&ret.SDU)
	next.read(&ret.TDU)
	next.read(&ret.ByteOrder)
	next.read(&ret.DataLength)
	next.read(&ret.DataOffset)
	next.read(&ret.ConnectFlags0)
	next.read(&ret.ConnectFlags1)
	unknownLen := ret.DataOffset - 16 - 8
	next.readNew(&ret.Unknown18, int(unknownLen))
	next.readNew(&ret.AcceptData, int(ret.DataLength))
	if err := next.Error(); err != nil {
		return nil, err
	}
	return ret, nil
}

// RefuseReason is an enumeration describing the reason the request was refused.
// TODO: details.
type RefuseReason uint8

func (reason RefuseReason) String() string {
	// TODO: Get better const error mappings. AppReason = 0x22 = syntax error?
	return fmt.Sprintf("0x%02x", uint8(reason))
}

// TNSRefuse is returned by the server when an error occurs (for instance, an
// invalid connect descriptor).
type TNSRefuse struct {
	// TODO: details
	AppReason RefuseReason

	// TODO: details
	SysReason RefuseReason

	// DataLength is the length of the packet's Data payload
	DataLength uint16

	// Data is the packet's payload. TODO: details
	Data []byte
}

// Encode the TNSRefuse packet body into a newly-allocated buffer.
func (packet *TNSRefuse) Encode() ([]byte, error) {
	if len(packet.Data)+4 > 0xffff {
		return nil, ErrInvalidData
	}
	ret := make([]byte, len(packet.Data)+4)
	next := outputBuffer(ret)
	next.pushU8(uint8(packet.AppReason))
	next.pushU8(uint8(packet.SysReason))
	next.pushU16(uint16(packet.DataLength))
	next.push(packet.Data)
	return ret, nil
}

// GetType identifies the packet as PacketTypeRefuse.
func (packet *TNSRefuse) GetType() PacketType {
	return PacketTypeRedirect
}

// ReadTNSRefuse reads a TNSRefuse packet from the stream, which should
// point to the first byte after the TNSHeader.
func ReadTNSRefuse(reader io.Reader, header *TNSHeader) (*TNSRefuse, error) {
	ret := new(TNSRefuse)
	next := startReading(reader)
	next.read(&ret.AppReason)
	next.read(&ret.SysReason)
	next.read(&ret.DataLength)
	next.readNew(&ret.Data, int(ret.DataLength))
	if err := next.Error(); err != nil {
		return nil, err
	}
	if uint32(ret.DataLength) != header.Length-8-4 {
		return nil, ErrInvalidData
	}
	return ret, nil
}

// TNSRedirect is returned by the server in response to a TNSConnect when it
// needs to direct the caller elsewhere. Its Data is a new connect descriptor
// for the caller to use.
type TNSRedirect struct {
	// DataLength is the length of the packet's Data payload.
	DataLength uint16

	// Data is the TNSRedirect's payload -- it contains a new connect descriptor
	// for the client to use in a subsequent TNSConnect call.
	Data []byte
}

// Encode the TNSRedirect packet body into a newly-allocated buffer.
func (packet *TNSRedirect) Encode() ([]byte, error) {
	if len(packet.Data)+2 > 0xffff {
		return nil, ErrInvalidData
	}
	ret := make([]byte, len(packet.Data)+2)
	next := outputBuffer(ret)
	next.pushU16(uint16(packet.DataLength))
	next.push(packet.Data)
	return ret, nil
}

// GetType identifies the packet as PacketTypeRedirect.
func (packet *TNSRedirect) GetType() PacketType {
	return PacketTypeRedirect
}

// ReadTNSRedirect reads a TNSRedirect packet from the stream, which should
// point to the first byte after the TNSHeader.
func ReadTNSRedirect(reader io.Reader, header *TNSHeader) (*TNSRedirect, error) {
	ret := new(TNSRedirect)
	next := startReading(reader)
	next.read(&ret.DataLength)
	next.readNew(&ret.Data, int(header.Length-8-2))
	if err := next.Error(); err != nil {
		return nil, err
	}
	if len(ret.Data) != int(ret.DataLength) {
		return nil, ErrInvalidData
	}
	return ret, nil
}

// ReleaseVersion is a packed version number describing the release version of
// a specific (sub-)component. Logically it has five components, described at
// https://docs.oracle.com/cd/B28359_01/server.111/b28310/dba004.htm:
// major.maintenance.appserver.component.platform. The number of bits allocated
// to each are respectively 8.4.4.8.8, so 0x01230405 would denote "1.2.3.4.5".
type ReleaseVersion uint32

// String returns the dotted-decimal representation of the release version:
// major.maintenance.appserver.component.platform.
func (v ReleaseVersion) String() string {
	return fmt.Sprintf("%d.%d.%d.%d.%d", v>>24, v>>20&0x0F, v>>16&0x0F, v>>8&0xFF, v&0xFF)
}

// Bytes returns the big-endian binary encoding of the release version.
func (v ReleaseVersion) Bytes() []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(v))
	return buf
}

// EncodeReleaseVersion gets a ReleaseVersion instance from its dotted-decimal
// representation, e.g.:
// EncodeReleaseVersion("64.3.2.1.0") = ReleaseVersion(0x40320100).
func EncodeReleaseVersion(value string) (ReleaseVersion, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 5 {
		return 0, ErrInvalidInput
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
			return 0, ErrInvalidInput
		}
		if int(n) > maxValue[i] {
			return 0, ErrInvalidInput
		}
		numbers[i] = uint32(n)
	}
	return ReleaseVersion((numbers[0] << 24) | (numbers[1] << 20) | (numbers[2] << 16) | (numbers[3] << 8) | numbers[4]), nil
}

func encodeReleaseVersion(value string) ReleaseVersion {
	ret, err := EncodeReleaseVersion(value)
	if err != nil {
		panic(err)
	}
	return ret
}

// DataFlags is a 16-bit flags field used in the TNSData packet.
type DataFlags uint16

// TODO: details
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

// Set gets a set representation of the DataFlags.
func (flags DataFlags) Set() map[string]bool {
	ret, _ := zgrab2.MapFlagsToSet(uint64(flags), func(bit uint64) (string, error) {
		return dfNames[DataFlags(bit)], nil
	})
	// there are no unknowns since all 16 flags are accounted for in dfNames
	return ret
}

// TNSData is the packet type used to send (more or less) arbitrary data between
// client and server. All packets have the DataFlags, and for many, the first
// four bytes of the data have a 32-bit value identifying the type of data.
type TNSData struct {
	// DataFlags gives information on the data (TODO: details)
	DataFlags DataFlags

	// Data is the packet's payload. Its length is equal to the header's length
	// less 10 bytes (8 for the header itself, 2 for the DataFlags).
	Data []byte
}

const (
	// DataIDNSN identifies a Native Security Negotiation data payload.
	DataIDNSN uint32 = 0xdeadbeef
)

// GetID returns a TNSData's ID (the first four bytes of the data), if available
// otherwise returns 0.
func (packet *TNSData) GetID() uint32 {
	if len(packet.Data) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(packet.Data[0:4])
}

// Encode the TNSData packet body into a newly-allocated buffer.
func (packet *TNSData) Encode() ([]byte, error) {
	if len(packet.Data)+2 > 0xffff {
		return nil, ErrInvalidData
	}
	ret := make([]byte, len(packet.Data)+2)
	next := outputBuffer(ret)
	next.pushU16(uint16(packet.DataFlags))
	next.push(packet.Data)
	return ret, nil
}

// GetType identifies the packet as PacketTypeData.
func (packet *TNSData) GetType() PacketType {
	return PacketTypeData
}

// ReadTNSData reads a TNSData packet from the stream, which should point to the
// first byte after the TNSHeader.
func ReadTNSData(reader io.Reader, header *TNSHeader) (*TNSData, error) {
	ret := new(TNSData)
	next := startReading(reader)
	next.read(&ret.DataFlags)
	next.readNew(&ret.Data, int(header.Length-8-2))
	if err := next.Error(); err != nil {
		return nil, err
	}
	return ret, nil
}

// NSNServiceType is an enumerated type identifying the "service" types inside
// a NSN packet.
type NSNServiceType uint16

const (
	// NSNServiceAuthentication identifies an Authentication service
	// (TODO: details).
	NSNServiceAuthentication NSNServiceType = 1

	// NSNServiceEncryption identifies an Encryption service (TODO: details).
	NSNServiceEncryption = 2

	// NSNServiceDataIntegrity identifies a Data Integrity service
	// (TODO: details).
	NSNServiceDataIntegrity = 3

	// NSNServiceSupervisor identifies a Supervisor service (TODO: details).
	NSNServiceSupervisor = 4
)

var nsnServiceTypeToName = map[NSNServiceType]string{
	NSNServiceAuthentication: "Authentication",
	NSNServiceEncryption:     "Encryption",
	NSNServiceDataIntegrity:  "DataIntegrity",
	NSNServiceSupervisor:     "Supervisor",
}

// String gives the string representation of the service type.
func (typ NSNServiceType) String() string {
	ret, ok := nsnServiceTypeToName[typ]
	if !ok {
		return fmt.Sprintf("Unknown(0x%x)", uint16(typ))
	}
	return ret
}

// IsUnknown returns true iff the service type value is not one of the
// recognized enum values.
func (typ NSNServiceType) IsUnknown() bool {
	_, ok := nsnServiceTypeToName[typ]
	return !ok
}

// NSNService is an individual "packet" inside the NSN data payload; it consists
// in an identifier and a list of values or "sub-packets" giving configuration
// settings for that service type. These are somewhat described here:
// https://docs.oracle.com/cd/B19306_01/network.102/b14212/troublestng.htm
type NSNService struct {
	Type   NSNServiceType
	Values []NSNValue
	Marker uint32
}

// GetSize returns the encoded size of the NSNService. Returns an error rather
// than overflowing.
func (service *NSNService) GetSize() (uint16, error) {
	ret := uint32(8) // uint16(Type) + uint16(#values) + uint32(marker)
	for _, v := range service.Values {
		ret += uint32(len(v.Value) + 4)
	}
	if ret > 0xffff {
		return 0, ErrInvalidInput
	}
	return uint16(ret), nil
}

// Encode returns the encoded NSNService in a newly allocated buffer.
// If the length of the encoded value would be larger than 16 bits, returns an
// error.
func (service *NSNService) Encode() ([]byte, error) {
	size, err := service.GetSize()
	if err != nil {
		return nil, err
	}
	ret := make([]byte, size)
	next := outputBuffer(ret)
	next.pushU16(uint16(service.Type))
	next.pushU16(uint16(len(service.Values)))
	next.pushU32(service.Marker)
	for _, value := range service.Values {
		enc, err := value.Encode()
		if err != nil {
			return nil, err
		}
		next.push(enc)
	}
	return ret, nil
}

// ReadNSNService reads an NSNService packet from the stream. On failure to
// read a service, returns nil + an error (though the stream will be in a bad
// state).
func ReadNSNService(reader io.Reader, ret *NSNService) (*NSNService, error) {
	if ret == nil {
		ret = &NSNService{}
	}
	next := startReading(reader)
	next.read(&ret.Type)
	n, err := next.readU16()
	if err != nil {
		return nil, err
	}
	if n > 0x0400 {
		// Arbitrary but sufficiently huge cut off. Typical values are single
		// digits. The total encoded size must fit into 16 bits.
		return nil, ErrInvalidData
	}
	next.read(&ret.Marker)
	// Check if Marker == 0?
	ret.Values = make([]NSNValue, int(n))
	for i := 0; i < int(n); i++ {
		_, err := ReadNSNValue(reader, &ret.Values[i])
		if err != nil {
			return nil, err
		}
	}
	if err := next.Error(); err != nil {
		return nil, err
	}
	return ret, nil
}

// NSNValueType is a 16-bit enumerated value identifying the different data
// types of the values or "sub-packets" in the NSNService packets. NOTE: this
// list may not be comprehensive.
type NSNValueType uint16

const (
	// NSNValueTypeString identifies a string value type.
	NSNValueTypeString NSNValueType = 0

	// NSNValueTypeBytes identifies a binary value type (an array of bytes).
	NSNValueTypeBytes = 1

	// NSNValueTypeUB1 identifies an unsigned 8-bit integer.
	NSNValueTypeUB1 = 2

	// NSNValueTypeUB2 identifies an unsigned 16-bit big-endian integer.
	NSNValueTypeUB2 = 3

	// NSNValueTypeUB4 identifies an unsigned 32-bit big-endian integer.
	NSNValueTypeUB4 = 4

	// NSNValueTypeVersion identifies a 32-bit ReleaseVersion value.
	NSNValueTypeVersion = 5

	// NSNValueTypeStatus identifies a 16-bit status value.
	NSNValueTypeStatus = 6
)

// NSNValue represents a single value or "sub-packet" within an NSNService. It
// consists of a type identifier and the value itself.
type NSNValue struct {
	Type  NSNValueType
	Value []byte
}

// String gives the friendly encoding of the sub-packet value; integers are
// given in decimal, versions in dotted decimal format, binary data as base64,
// strings as strings.
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

// MarshalJSON encodes the NSNValue as a JSON object: a type/value pair.
func (value *NSNValue) MarshalJSON() ([]byte, error) {
	type Aux struct {
		Type  NSNValueType `json:"type"`
		Value interface{}  `json:"value"`
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

// NSNValueVersion returns a NSNValue of type Version whose value is given in
// dotted-decimal format.
func NSNValueVersion(v string) *NSNValue {
	return &NSNValue{
		Type:  NSNValueTypeVersion,
		Value: encodeReleaseVersion(v).Bytes(),
	}
}

// NSNValueBytes returns a NSNValue of type Bytes with the given value.
func NSNValueBytes(bytes []byte) *NSNValue {
	return &NSNValue{
		Type:  NSNValueTypeBytes,
		Value: bytes,
	}
}

// NSNValueUB1 returns a NSNValue of type UB1 with the given value.
func NSNValueUB1(val uint8) *NSNValue {
	return &NSNValue{
		Type:  NSNValueTypeUB1,
		Value: []byte{val},
	}
}

// NSNValueUB2 returns a NSNValue of type UB2 with the given value.
func NSNValueUB2(val uint16) *NSNValue {
	ret := make([]byte, 2)
	binary.BigEndian.PutUint16(ret, val)
	return &NSNValue{
		Type:  NSNValueTypeUB2,
		Value: ret,
	}
}

// NSNValueStatus returns a NSNValue of type Status with the given value.
func NSNValueStatus(val uint16) *NSNValue {
	ret := NSNValueUB2(val)
	ret.Type = NSNValueTypeStatus
	return ret
}

// NSNValueString returns a NSNValue of type String with the given value.
func NSNValueString(val string) *NSNValue {
	return &NSNValue{
		Type:  0,
		Value: []byte(val),
	}
}

// Encode returns the encoding of the NSNValue in a newly-allocated byte slice.
// Returns an error if the length of the value would be longer than 16 bits.
func (value *NSNValue) Encode() ([]byte, error) {
	if len(value.Value)+4 > 0xffff {
		return nil, ErrInvalidInput
	}
	ret := make([]byte, 4+len(value.Value))
	next := outputBuffer(ret)
	next.pushU16(uint16(len(value.Value)))
	next.pushU16(uint16(value.Type))
	next.push(value.Value)
	return ret, nil
}

// ReadNSNValue reads a NSNValue from the stream, returns nil/error if one
// cannot be read (leaving the stream in a bad state).
func ReadNSNValue(reader io.Reader, ret *NSNValue) (*NSNValue, error) {
	if ret == nil {
		ret = &NSNValue{}
	}
	next := startReading(reader)
	size, err := next.readU16()
	if err != nil {
		return nil, err
	}
	next.read(&ret.Type)
	next.readNew(&ret.Value, int(size))
	if err := next.Error(); err != nil {
		return nil, err
	}
	return ret, nil
}

// NSNOptions is an 8-bit flags value describing the Native Security Negotiation
// options (TODO: details).
type NSNOptions uint8

// TNSDataNSN represents the decoded body of a TNSData packet for a Native
// Security Negotiation payload.
type TNSDataNSN struct {
	// ID is the TNSData identifier for NSN (0xdeadbeef)
	ID uint32

	// Version is the ReleaseVersion, which seems to often be 0 in practice.
	Version ReleaseVersion

	// Options is an 8-bit flags value giving options for the connection (TODO:
	// details).
	Options NSNOptions

	// Services is an array of NSNService values, giving the configuration for
	// that service type.
	Services []NSNService
}

// GetSize returns the encoded size of the TNSDataNSN body. Returns an error if
// the data length would be longer than 16 bits.
func (packet *TNSDataNSN) GetSize() (uint16, error) {
	ret := uint32(13) // uint32(ID) + uint16(len) + uint32(version) + uint16(#services) + uint8(options)
	for _, v := range packet.Services {
		subSize, err := v.GetSize()
		if err != nil {
			return 0, err
		}
		ret += uint32(subSize)
	}
	if ret > 0xffff {
		return 0, ErrInvalidInput
	}
	return uint16(ret), nil
}

// Encode returns the encoded TNSDataNSN data in a newly-allocated buffer.
func (packet *TNSDataNSN) Encode() ([]byte, error) {
	size, err := packet.GetSize()
	if err != nil {
		return nil, err
	}
	ret := make([]byte, size)
	next := outputBuffer(ret)
	next.pushU32(uint32(packet.ID))
	next.pushU16(size)
	next.pushU32(uint32(packet.Version))
	next.pushU16(uint16(len(packet.Services)))
	next.pushU8(uint8(packet.Options))
	for _, v := range packet.Services {
		enc, err := v.Encode()
		if err != nil {
			return nil, err
		}
		next.push(enc)
	}
	return ret, nil
}

// DecodeTNSDataNSN reads a TNSDataNSN packet from a TNSData body.
func DecodeTNSDataNSN(data []byte) (*TNSDataNSN, error) {
	reader := getSliceReader(data)

	ret, err := ReadTNSDataNSN(reader)
	if err != nil {
		return nil, err
	}
	if len(reader.Data) > 0 {
		// there should be no leftover data
		return nil, ErrInvalidData
	}
	return ret, nil
}

// ReadTNSDataNSN reads a TNSDataNSN packet from a stream pointing to the start
// of the NSN data.
func ReadTNSDataNSN(reader io.Reader) (*TNSDataNSN, error) {
	ret := TNSDataNSN{}
	next := startReading(reader)

	next.read(&ret.ID)
	if ret.ID != DataIDNSN {
		return nil, ErrUnexpectedResponse
	}

	length, err := next.readU16()
	if err != nil {
		return nil, err
	}

	if length < 4+2+4+2 {
		// length covers the entire data field, so it should cover 0xdeadbeef,
		// the length, the version and the number of services, at a minimum.
		return nil, ErrInvalidData
	}
	next.read(&ret.Version)
	n, err := next.readU16()
	if err != nil {
		return nil, err
	}
	if n >= 0x0100 {
		// arbitrary but certainly sufficiently-high value -- n here is the
		// number of "services", which is typically 4.
		return nil, ErrInvalidData
	}
	next.read(&ret.Options)
	// TODO: Check for valid options?

	if err := next.Error(); err != nil {
		return nil, err
	}

	ret.Services = make([]NSNService, n)
	for i := 0; i < int(n); i++ {
		_, err := ReadNSNService(reader, &ret.Services[i])
		if err != nil {
			return nil, err
		}
	}
	calculatedSize, err := ret.GetSize()
	if err != nil {
		return nil, err
	}
	if length != calculatedSize {
		return nil, ErrInvalidData
	}
	return &ret, nil
}

// TNSPacketBody is the interface for the "body" of a TNSPacket (that is,
// everything after the header).
type TNSPacketBody interface {
	GetType() PacketType
	Encode() ([]byte, error)
}

// TNSPacket is a TNSHeader + a body.
type TNSPacket struct {
	Header *TNSHeader
	Body   TNSPacketBody
}

// ReadTNSPacket reads a TNSPacket from the stream, or returns nil + an error
// if one cannot be read.
func (driver *TNSDriver) ReadTNSPacket(reader io.Reader) (*TNSPacket, error) {
	var body TNSPacketBody
	var err error
	header, err := driver.ReadTNSHeader(reader)
	if err != nil {
		return nil, err
	}
	switch header.Type {
	case PacketTypeConnect:
		body, err = ReadTNSConnect(reader, header)
	case PacketTypeAccept:
		body, err = ReadTNSAccept(reader, header)
	case PacketTypeRefuse:
		body, err = ReadTNSRefuse(reader, header)
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

// DescriptorEntry is a simple key-value pair representing a single primitive
// value in the descriptor string. The key is a dotted string representation
// of the path to the value, e.g. for "(A=(B=(C=ABC1)(C=ABC2)(D=ABD1))(E=AE1))", the
// DescriptorEntries would be
// {"A.B.C", "ABC1"}, {"A.B.C", "ABC2"}, {"A.B.D", "ABD1" }, {"A.E", "AE1"}.
type DescriptorEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Descriptor is a nested series of parens, used for e.g. connect descriptors
// and for error responses. To simplify their usage in searches, they are stored
// in a flattened form.
// Since duplicate keys are allowed, a simple map will not work, so instead
// it stores an list of key/value pairs, in the order they appear in the string.
// NOTE: This is insufficient to re-construct the input (since there is no way
// to tell "array elements" stop), so there is no Encode method.
type Descriptor []DescriptorEntry

// GetValues returns an array containing all Values in the descriptor that
// exactly match the given Key (key is in dotted string format).
func (descriptor Descriptor) GetValues(key string) []string {
	ret := []string{}
	for _, kvp := range descriptor {
		if kvp.Key == key {
			ret = append(ret, kvp.Value)
		}
	}
	return ret
}

// GetValue gets the unique Value for the given Key (in dotted string format).
// If a unique Value cannot be found (that is, there are no matches, or there is
// more than one match), returns "", ErrUnexpectedResponse.
func (descriptor *Descriptor) GetValue(key string) (string, error) {
	ret := descriptor.GetValues(key)
	if len(ret) != 1 {
		return "", ErrUnexpectedResponse
	}
	return ret[0], nil
}

// DecodeDescriptor takes a descriptor in native Oracle format and returns a
// flattened map.
func DecodeDescriptor(descriptor string) (Descriptor, error) {
	ret := make(Descriptor, 0)
	path := make([]string, 0)
	rest := strings.TrimSpace(descriptor)

	// Each case consumes at least one character
	for len(rest) > 0 {
		v := rest[0]
		switch v {
		case '(':
			// Open paren: start a new 'object' whose key name precedes the '='
			eq := strings.Index(rest, "=")
			if eq == -1 {
				return nil, ErrInvalidData
			}
			path = append(path, strings.TrimSpace(rest[1:eq]))
			// Consume the key (everything prior to the '=')
			rest = strings.TrimSpace(rest[eq:])
		case ')':
			// Close paren: pop off the last 'object' suffix
			path = path[0 : len(path)-1]
			// Consume the ')'
			rest = strings.TrimSpace(rest[1:])
		case '=':
			rest = strings.TrimSpace(rest[1:])
			if rest[0] != '(' {
				// What follows is a primitive
				closer := -1
				if rest[0] == '\'' || rest[0] == '"' {
					// If the primitive is quoted, it ends after the first
					// unescaped closing quote
					for i := 1; i < len(rest); i++ {
						if rest[i] == rest[0] && rest[i-1] != '\\' {
							closer = i + 1
							break
						}
					}
				} else {
					// Otherwise, it ends with the ')'
					closer = strings.Index(rest, ")")
				}
				if closer == -1 {
					return nil, ErrInvalidData
				}
				value := rest[0:closer]
				key := strings.Join(path, ".")
				// Store the primitive at the key for the current path
				ret = append(ret, DescriptorEntry{key, value})
				// Consume the value
				rest = strings.TrimSpace(rest[closer:])
			} else {
				// What follows is a list -- already consumed the =
			}
		default:
			return nil, ErrInvalidData
		}
	}
	return ret, nil
}

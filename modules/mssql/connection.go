package mssql

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
	logrus "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

var (
	ErrTooLarge                 error = fmt.Errorf("Data too large")
	ErrBufferTooSmall                 = fmt.Errorf("Buffer too small")
	ErrInvalidData                    = fmt.Errorf("The data does not have the expected format")
	ErrNoServerEncryption             = fmt.Errorf("The server does not support encryption.")
	ErrServerRequiresEncryption       = fmt.Errorf("The server requires encryption.")
	ErrInvalidState                   = fmt.Errorf("Operation cannot be performed in this state")
)

// https://msdn.microsoft.com/en-us/library/dd358342.aspx
const (
	TDSStatusNormal                  uint8 = 0x00
	TDSStatusEOM                           = 0x01
	TDSStatusIgnore                        = 0x02
	TDSStatusResetConnection               = 0x08
	TDSStatusResetConnectionSkipTran       = 0x10
)

type TDSPacketType uint8

// https://msdn.microsoft.com/en-us/library/dd304214.aspx
const (
	TDSPacketTypeSQLBatch                  TDSPacketType = 0x01
	TDSPacketTypePreTDS7Login                            = 0x02
	TDSPacketTypeRPC                                     = 0x03
	TDSPacketTypeTabularResult                           = 0x04
	TDSPacketTypeAttentionSignal                         = 0x06
	TDSPacketTypeBulkLoadData                            = 0x07
	TDSPacketTypeFederatedAuthToken                      = 0x08
	TDSPacketTypeTransactionManagerRequest               = 0x0E
	TDSPacketTypeTDS7Login                               = 0x10
	TDSPacketTypeSSPI                                    = 0x11
	TDSPacketTypePrelogin                                = 0x12
)

// From https://msdn.microsoft.com/en-us/library/dd357559.aspx - PL_OPTION_TOKEN values
type PreloginOptionToken uint8

const (
	PreloginVersion         PreloginOptionToken = 0x00
	PreloginEncryption                          = 0x01
	PreloginInstance                            = 0x02
	PreloginThreadID                            = 0x03
	PreloginMARS                                = 0x04
	PreloginTraceID                             = 0x05
	PreloginFedAuthRequired                     = 0x06
	PreloginNonce                               = 0x07
	PreloginTerminator                          = 0xFF
)

// Mapping to documented names, also serves to identify unknown values for JSON marshalling
var knownPreloginOptionTokens map[PreloginOptionToken]string = map[PreloginOptionToken]string{
	PreloginVersion:         "VERSION",
	PreloginEncryption:      "ENCRYPTION",
	PreloginInstance:        "INSTOPT",
	PreloginThreadID:        "THREADID",
	PreloginMARS:            "MARS",
	PreloginTraceID:         "TRACEID",
	PreloginFedAuthRequired: "FEDAUTHREQUIRED",
	PreloginNonce:           "NONCE",
}

// PreloginOption values are stored as byte arrays; actual types are specified in the docs
type PreloginOption []byte

// PreloginOptions maps the token to the value for that option
type PreloginOptions map[PreloginOptionToken]PreloginOption

// EncryptMode is defined at https://msdn.microsoft.com/en-us/library/dd357559.aspx
type EncryptMode byte

const (
	// EncryptModeUnknown is not a valid ENCRYPTION value
	EncryptModeUnknown EncryptMode = 0xff
	// EncryptModeOff means that encryption will only be used for login
	EncryptModeOff EncryptMode = 0x00
	// EncryptModeOn means that encryption will be used for the entire session
	EncryptModeOn EncryptMode = 0x01
	// EncryptModeNotSupported means that the client/server does not support encryption
	EncryptModeNotSupported EncryptMode = 0x02
	// EncryptModeRequired is sent by the server when the client sends EncryptModNotSupported but the server requires it
	EncryptModeRequired EncryptMode = 0x03
)

// These are the macro values defined in the MSDN docs
var stringToEncryptMode map[string]EncryptMode = map[string]EncryptMode{
	"UNKNOWN":         0xff,
	"ENCRYPT_OFF":     0x00,
	"ENCRYPT_ON":      0x01,
	"ENCRYPT_NOT_SUP": 0x02,
	"ENCRYPT_REQ":     0x03,
}

var encryptModeToString map[EncryptMode]string = map[EncryptMode]string{
	EncryptModeOff:          "ENCRYPT_OFF",
	EncryptModeOn:           "ENCRYPT_ON",
	EncryptModeNotSupported: "ENCRYPT_NOT_SUP",
	EncryptModeRequired:     "ENCRYPT_REQ",
	EncryptModeUnknown:      "UNKNOWN",
}

// Direct representation of the VERSION PRELOGIN token value.
type ServerVersion struct {
	Major       uint8  `json:"major"`
	Minor       uint8  `json:"minor"`
	BuildNumber uint16 `json:"build_number"`
}

// Decode a VERSION response and return the parsed ServerVersion struct
// As defined in the MSDN docs, these come from token 0: VERSION -- UL_VERSION =   ((US_BUILD<<16)|(VER_SQL_MINOR<<8)|( VER_SQL_MAJOR))
func DecodeServerVersion(buf []byte) *ServerVersion {
	if len(buf) != 6 {
		return nil
	}
	return &ServerVersion{
		Major:       buf[0],
		Minor:       buf[1],
		BuildNumber: binary.BigEndian.Uint16(buf[2:4]),
	}
}

// TDSHeader: an 8-byte structure prepended to all TDS packets. See https://msdn.microsoft.com/en-us/library/dd340948.aspx for details.
type TDSHeader struct {
	Type           uint8
	Status         uint8  // "Status is a bit field used to indicate the message state. Status is a 1-byte unsigned char. The following Status bit flags are defined."
	Length         uint16 // "Length is the size of the packet including the 8 bytes in the packet header. It is the number of bytes from the start of this header to the start of the next packet header. Length is a 2-byte, unsigned short int and is represented in network byte order (big-endian). Starting with TDS 7.3, the Length MUST be the negotiated packet size when sending a packet from client to server, unless it is the last packet of a request (that is, the EOM bit in Status is ON), or the client has not logged in."
	SPID           uint16 // "Spid is the process ID on the server, corresponding to the current connection. This information is sent by the server to the client and is useful for identifying which thread on the server sent the TDS packet. It is provided for debugging purposes. The client MAY send the SPID value to the server. If the client does not, then a value of 0x0000 SHOULD be sent to the server. This is a 2-byte value and is represented in network byte order (big-endian)."
	SequenceNumber uint8  // "PacketID is used for numbering message packets that contain data in addition to the packet header. PacketID is a 1-byte, unsigned char. Each time packet data is sent, the value of PacketID is incremented by 1, modulo 256. This allows the receiver to track the sequence of TDS packets for a given message. This value is currently ignored."
	Window         uint8  // "This 1 byte is currently not used. This byte SHOULD be set to 0x00 and SHOULD be ignored by the receiver."
}

// DecodeTDSHeader interprets the first 8 bytes of buf as a TDSHeader.
func DecodeTDSHeader(buf []byte) (*TDSHeader, error) {
	if len(buf) < 8 {
		return nil, ErrBufferTooSmall
	}
	return &TDSHeader{
		Type:           buf[0],
		Status:         buf[1],
		Length:         binary.BigEndian.Uint16(buf[2:4]),
		SPID:           binary.BigEndian.Uint16(buf[4:6]),
		SequenceNumber: buf[6],
		Window:         buf[7],
	}, nil
}

// ReadTDSHeader attempts to read 8 bytes from conn using io.ReadFull, and decodes the result as a TDSHeader.
func ReadTDSHeader(conn io.Reader) (*TDSHeader, error) {
	buf := make([]byte, 8)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	return DecodeTDSHeader(buf)
}

// TDSHeader.Encode() returns the encoding of the header as a byte slice.
func (self *TDSHeader) Encode() []byte {
	ret := make([]byte, 8)
	ret[0] = self.Type
	ret[1] = self.Status
	binary.BigEndian.PutUint16(ret[2:4], self.Length)
	binary.BigEndian.PutUint16(ret[4:6], self.SPID)
	ret[6] = self.SequenceNumber
	ret[7] = self.Window
	return ret
}

// PreloginOptions.HeaderSize() calculates the length of the PRELOGIN_OPTIONs / the number of bytes before the payload starts.
// Each PRELOGIN_OPTION is a 1-byte token, a 2-byte length and a 2-byte offset, and all of them are followed by a single-byte TERMINATOR, giving 5 * len(*self) + 1.
func (self *PreloginOptions) HeaderSize() int {
	return 5*len(*self) + 1
}

// PreloginOptions.Size() returns the total size of the PRELOGIN packet body (so, not including the TDSPacket header)
// Namely, the header size + the size of all of the values.
func (self *PreloginOptions) Size() int {
	// 5 bytes per option for token/offset/length + 1 byte for terminator
	ret := self.HeaderSize()
	// + actual sizes of each option
	for _, option := range *self {
		ret += len(option)
	}
	return ret
}

// PreloginOptions.GetByteOption() returns a single-byte PRELOGIN option for the given token.
// If there is no value for that token present, or if the value is not exactly one byte long, returns an ErrInvalidData.
func (self *PreloginOptions) GetByteOption(token PreloginOptionToken) (byte, error) {
	ret, ok := (*self)[token]
	if !ok || len(ret) != 1 {
		return 0, ErrInvalidData
	}
	return ret[0], nil
}

// PreloginOptions.GetByteOption() returns a big-endian uint16 PRELOGIN option for the given token.
// If there is no value for that token present, or if the value is not exactly two bytes long, returns an ErrInvalidData.
func (self *PreloginOptions) GetUint16Option(token PreloginOptionToken) (uint16, error) {
	ret, ok := (*self)[token]
	if !ok || len(ret) != 2 {
		return 0, ErrInvalidData
	}
	return binary.BigEndian.Uint16(ret[0:2]), nil
}

// PreloginOptions.GetVersion() decodes the VERSION response value if present; if not (or invalid), returns nil
func (self *PreloginOptions) GetVersion() *ServerVersion {
	version, hasVersion := (*self)[PreloginVersion]
	if !hasVersion {
		return nil
	}
	return DecodeServerVersion(version)
}

// PreloginOptions.Encode() returns the encoding of the PRELOGIN body as described in https://msdn.microsoft.com/en-us/library/dd357559.aspx
func (self *PreloginOptions) Encode() ([]byte, error) {
	size := self.Size()
	if size > 0xffff {
		return nil, ErrTooLarge
	}
	ret := make([]byte, size)
	// cursor always points to the location for the next PL_OPTION header value
	cursor := ret[0:]
	// offset always points to the next-available location for values in body, starting just after the TERMINATOR token
	offset := self.HeaderSize()
	// Ensure that the tokens are encoded in ascending order
	var sortedKeys []int
	for k, _ := range *self {
		sortedKeys = append(sortedKeys, int(k))
	}
	sort.Ints(sortedKeys)
	for _, ik := range sortedKeys {
		k := PreloginOptionToken(ik)
		v := (*self)[k]
		cursor[0] = byte(k)
		if offset > 0xffff {
			return nil, ErrTooLarge
		}
		binary.BigEndian.PutUint16(cursor[1:3], uint16(offset))
		binary.BigEndian.PutUint16(cursor[3:5], uint16(len(v)))
		copy(ret[offset:offset+len(v)], v)
		offset += len(v)
		cursor = cursor[5:]
	}
	// Write the terminator after the last PL_OPTION header (and just before the first value)
	cursor[0] = 0xff
	return ret, nil
}

// Decode a PreloginOptions object from the given body. Any extra bytes are returned in rest.
// If body cannot be decoded as a PRELOGIN body, returns nil, nil, ErrInvalidData.
func DecodePreloginOptions(body []byte) (result *PreloginOptions, rest []byte, err error) {
	cursor := body[:]
	options := make(PreloginOptions)
	max := 0
	for cursor[0] != 0xff {
		if len(cursor) < 6 {
			// if the cursor is not pointing to the terminator, and we do not have 5 bytes + terminator remaining, it's a bad packet
			return nil, nil, ErrInvalidData
		}
		token := PreloginOptionToken(cursor[0])
		offset := binary.BigEndian.Uint16(cursor[1:3])
		length := binary.BigEndian.Uint16(cursor[3:5])
		if len(body) < int(offset+length) {
			return nil, nil, ErrInvalidData
		}
		options[token] = body[offset : offset+length]

		if int(offset+length) > max {
			// max points to the byte after the last offset in body that was consumed
			max = int(offset + length)
		}
		cursor = cursor[5:]
	}
	return &options, body[max:], nil
}

// preloginOptionsJSON is an auxiliary struct that holds the output format of the PreloginOptions
type preloginOptionsJSON struct {
	Version *ServerVersion `json:"version,omitempty"`

	Encryption *EncryptMode `json:"encrypt_mode,omitempty"`
	Instance   string       `json:"instance,omitempty"`
	ThreadID   *uint32      `json:"thread_id,omitempty"`
	// Using a *uint8 to distinguish 0 from undefined
	MARS            *uint8                      `json:"mars,omitempty"`
	TraceID         []byte                      `json:"trace_id,omitempty"`
	FedAuthRequired *uint8                      `json:"fed_auth_required,omitempty"`
	Nonce           []byte                      `json:"nonce,omitempty"`
	Unknown         []unknownPreloginOptionJSON `json:"unknown,omitempty"`
}

// unknownPreloginOptionJSON holds the raw PRELOGIN token and value for unknown tokens.
type unknownPreloginOptionJSON struct {
	Token uint8  `json:"token"`
	Value []byte `json:"value"`
}

// PreloginOptions.MarshalJSON() puts the map[PreloginOptionToken]PreloginOption into a more database-friendly format
func (self *PreloginOptions) MarshalJSON() ([]byte, error) {
	opts := *self
	aux := preloginOptionsJSON{}
	aux.Version = self.GetVersion()

	encryptMode, hasEncrypt := opts[PreloginEncryption]
	if hasEncrypt && len(encryptMode) == 1 {
		temp := EncryptMode(encryptMode[0])
		aux.Encryption = &temp
	}

	instance, hasInstance := opts[PreloginInstance]
	if hasInstance {
		aux.Instance = strings.Trim(string(instance), "\x00")
	}

	threadID, hasThreadID := opts[PreloginThreadID]
	if hasThreadID && len(threadID) == 4 {
		temp := binary.BigEndian.Uint32(threadID[:])
		aux.ThreadID = &temp
	}

	mars, hasMars := opts[PreloginMARS]
	if hasMars && len(mars) == 1 {
		aux.MARS = &mars[0]
	}

	traceID, hasTraceID := opts[PreloginTraceID]
	if hasTraceID {
		aux.TraceID = traceID
	}

	fedAuthRequired, hasFedAuthRequired := opts[PreloginFedAuthRequired]
	if hasFedAuthRequired {
		aux.FedAuthRequired = &fedAuthRequired[0]
	}

	nonce, hasNonce := opts[PreloginNonce]
	if hasNonce {
		aux.Nonce = nonce
	}

	for k, v := range opts {
		_, ok := knownPreloginOptionTokens[k]
		if !ok {
			aux.Unknown = append(aux.Unknown, unknownPreloginOptionJSON{
				Token: uint8(k),
				Value: v,
			})
		}
	}
	return json.Marshal(aux)
}

// TDSPacket is a header followed by the body. Length is calculated from the start of the packet, NOT the start of the body.
type TDSPacket struct {
	TDSHeader
	Body []byte
}

// DecodeTDSPacket decodes a TDSPacket from the start of buf, returning the packet and any remaining bytes following it.
func DecodeTDSPacket(buf []byte) (*TDSPacket, []byte, error) {
	header, err := DecodeTDSHeader(buf)
	if err != nil {
		return nil, nil, err
	}
	if len(buf) < int(header.Length) {
		return nil, nil, ErrBufferTooSmall
	}
	body := buf[8:header.Length]
	return &TDSPacket{
		TDSHeader: *header,
		Body:      body,
	}, buf[header.Length:], nil
}

// TDSPacket.Encode() returns the encoded packet: header + body. Updates the header's length to match the actual body length.
func (self *TDSPacket) Encode() ([]byte, error) {
	if len(self.Body)+8 > 0xffff {
		return nil, ErrTooLarge
	}
	self.TDSHeader.Length = uint16(len(self.Body) + 8)
	header := self.TDSHeader.Encode()
	ret := append(header, self.Body...)
	return ret, nil
}

// EncryptMode.String() returns a string representation of the EncryptMode.
func (self EncryptMode) String() string {
	ret, ok := encryptModeToString[self]
	if !ok {
		return encryptModeToString[EncryptModeUnknown]
	}
	return ret
}

// EncryptMode.MarshalJSON() ensures that the EncryptMode is encoded in the string format.
func (self EncryptMode) MarshalJSON() ([]byte, error) {
	return json.Marshal(self.String())
}

// GetEncryptMode returns the integer EncryptMode value for the given string label.
func GetEncryptMode(enum string) EncryptMode {
	ret, ok := stringToEncryptMode[enum]
	if !ok {
		return EncryptModeUnknown
	}
	return ret
}

// Connection wraps the state of a single MSSQL connection.
// NOT thread safe, due e.g. to the state (e.g. messageType) in the TDSWrappedConnection.
type Connection struct {
	// rawConn is the raw network connection. Both tlsConn and tdsConn wrap this.
	rawConn net.Conn

	// tlsConn is the TLS client. During the handshake, it wraps an active TDSWrappedConnection. Afterwards, the inner TDSWrappedConnection is deactivated.
	tlsConn *zgrab2.TLSConnection

	// tdsConn allows sending / receiving TDS packets through the net.Conn interface. Wraps either rawConn or tlsConn.
	// The genesis of this is the fact that MSSQL requires the TLS handshake packets to be wrapped in TDS headers.
	tdsConn *TDSWrappedConnection

	// sequenceNumber is the sequence number used for the last packet (though they are sent to the server mod 256).
	sequenceNumber int

	// PreloginOptions contains the values returned by the server in the PRELOGIN call, once it has happened.
	PreloginOptions *PreloginOptions
}

// Connection.SendTDSPacket() sends a TDS packet with the given type and body.
// NOTE - sets tdsConn.messageType to packetType and leaves it there.
func (self *Connection) SendTDSPacket(packetType uint8, body []byte) error {
	self.sequenceNumber++
	self.tdsConn.messageType = packetType
	_, err := self.tdsConn.Write(body)
	return err
}

// Connection.ReadPreloginPacket() reads an entire Prelogin packet from tdsConn and then decodes it.
func (self *Connection) ReadPreloginPacket() (*TDSPacket, *PreloginOptions, error) {
	packet, err := self.tdsConn.ReadPacket()
	if err != nil {
		// FIXME: protocol error
		return nil, nil, err
	}
	if packet.Type != TDSPacketTypeTabularResult {
		// FIXME: application error
		return packet, nil, fmt.Errorf("Received unexpected TDS packet type 0x%02x", packet.Type)
	}
	plOptions, rest, err := DecodePreloginOptions(packet.Body)
	if err != nil {
		return packet, nil, err
	}
	if len(rest) > 0 {
		return packet, nil, ErrInvalidData
	}
	return packet, plOptions, nil
}

// Connection.Prelogin() sends the Prelogin packet and reads the response from the server.
// It populates the connection's PreloginOptions field with the response, and specifically returns the ENCRYPTION value (which is used to determine whether a TLS handshake needs to be done).
func (self *Connection) Prelogin(clientEncrypt EncryptMode) (EncryptMode, error) {
	if clientEncrypt < 0 || clientEncrypt > 0xff {
		return EncryptModeUnknown, ErrInvalidData
	}
	preloginOptions := PreloginOptions{
		PreloginVersion:    {0, 0, 0, 0, 0, 0},
		PreloginEncryption: {byte(clientEncrypt)},
		PreloginInstance:   {0},
		PreloginThreadID:   {0, 0, 0, 0},
		PreloginMARS:       {0},
	}
	preloginBody, err := preloginOptions.Encode()
	if err != nil {
		return EncryptModeUnknown, err
	}
	err = self.SendTDSPacket(TDSPacketTypePrelogin, preloginBody)

	if err != nil {
		return EncryptModeUnknown, err
	}
	packet, response, err := self.ReadPreloginPacket()
	if response != nil {
		self.PreloginOptions = response
	}
	if err != nil {
		if packet != nil {
			// FIXME: debug packet info?
			logrus.Warnf("Got bad packet? type=0x%02x", packet.Type)
		}
		return EncryptModeUnknown, err
	}

	serverEncrypt := self.GetEncryptMode()

	if clientEncrypt == EncryptModeOn && serverEncrypt == EncryptModeNotSupported {
		return serverEncrypt, ErrNoServerEncryption
	}
	if clientEncrypt == EncryptModeNotSupported && serverEncrypt == EncryptModeRequired {
		return serverEncrypt, ErrServerRequiresEncryption
	}
	return serverEncrypt, nil
}

// Connection.Close() closes / resets any resources associated with the connection, and returns the first error (if any) that it encounters.
func (self *Connection) Close() error {
	self.sequenceNumber = 0
	self.tdsConn = nil
	self.tlsConn = nil
	temp := self.rawConn
	self.rawConn = nil
	return temp.Close()
}

// TDSWrappedConnection is an implementation of net.Conn that adapts raw input (e.g. from an external library like tls.Handshake()) by adding / removing TDS headers for writes / reads.
// For example, wrapped.Write("abc") will call wrapped.conn.Write(TDSHeader + "abc"), while wrapped.Read() will read TDSHeader + "def" from net.Conn, then return "def" to the caller.
// For reads, this reads entire TDS packets at a time -- blocking until it can -- and returns partial packets (or data from multiple packets) as reqested.
type TDSWrappedConnection struct {
	// The underlying conn. Traffic going over this connection is wrapped in TDS headers.
	conn net.Conn
	// If enabled == false, reads and writes to the wrapped connection pass directly through to conn.
	enabled bool
	// messageType is the header type added to written packets.
	messageType byte
	// remainder contains bytes read from net.conn that have not yet been returned to Read() calls on this instance.
	remainder []byte
}

// return the lesser of a, b
func min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

// Read a single packet from the connection and return the whole packet (this is the only way to see the packet type, sequence number, etc).
func (self *TDSWrappedConnection) ReadPacket() (*TDSPacket, error) {
	if !self.enabled {
		return nil, ErrInvalidState
	}
	header, err := ReadTDSHeader(self.conn)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, header.Length-8)
	_, err = io.ReadFull(self.conn, buf)
	if err != nil {
		return nil, err
	}
	return &TDSPacket{
		TDSHeader: *header,
		Body:      buf,
	}, nil
}

// The wrapped Read() call. If not enabled, just passes through to conn.Read(b). Otherwise...
// If it has sufficient data in remainder to satisfy the read, just return that.
// Otherwise, attempt to read a header (FIXME: with a 1s timeout), then block on reading the entire packet and add it to the remainder.
// Then, consume and repeat. If there is an error reading, return the error back to the user with the corresponding bytes read.
func (self *TDSWrappedConnection) Read(b []byte) (n int, err error) {
	if !self.enabled {
		return self.conn.Read(b)
	}
	output := b
	soFar := 0
	for len(output) > len(self.remainder) {
		copy(output, self.remainder)
		output = output[len(self.remainder):]
		soFar = soFar + len(self.remainder)
		self.remainder = make([]byte, 0)
		// BEGIN FIXME
		self.conn.SetReadDeadline(time.Now().Add(1e9))
		header, err := ReadTDSHeader(self.conn)
		if err != nil {
			return soFar, err
		}
		// END FIXME
		self.remainder = make([]byte, header.Length-8)
		n, err = io.ReadFull(self.conn, self.remainder)
		if err != nil {
			logrus.Warn("Error reading body", err)
			return soFar, err
		}
		toCopy := min(len(output), len(self.remainder))
		copy(output, self.remainder[0:toCopy])
		output = output[toCopy:]
		self.remainder = self.remainder[toCopy:]
		soFar = soFar + toCopy
	}
	// now len(output) <= len(remainder)
	copy(output, self.remainder)
	self.remainder = self.remainder[len(output):]
	return len(b), nil
}

// The wrapped Write method. If not enabled, just pass through to conn.Write.
// Otherise, wrap b in a TDSHeader with the next sequence number and packet type given by messageType, and send it in a single conn.Write().
func (self *TDSWrappedConnection) Write(b []byte) (n int, err error) {
	if !self.enabled {
		return self.conn.Write(b)
	}
	if len(b)+8 > 0xffff {
		return 0, ErrTooLarge
	}
	header := TDSHeader{
		Type:           self.messageType,
		Status:         TDSStatusEOM,
		Length:         uint16(len(b) + 8),
		SPID:           0,
		SequenceNumber: 1,
		Window:         0,
	}
	buf := header.Encode()
	output := append(buf, b...)
	ret, err := self.conn.Write(output)
	if ret > 0 {
		ret = ret - 8
		if ret < 0 {
			ret = 0
		}
	}
	return ret, err
}

// Passthrough to the underlying connection.
func (self *TDSWrappedConnection) Close() error {
	return self.conn.Close()
}

// Passthrough to the underlying connection.
func (self *TDSWrappedConnection) LocalAddr() net.Addr {
	return self.conn.LocalAddr()
}

// Passthrough to the underlying connection.
func (self *TDSWrappedConnection) RemoteAddr() net.Addr {
	return self.conn.RemoteAddr()
}

// Passthrough to the underlying connection.
func (self *TDSWrappedConnection) SetDeadline(t time.Time) error {
	return self.conn.SetDeadline(t)
}

// Passthrough to the underlying connection.
func (self *TDSWrappedConnection) SetReadDeadline(t time.Time) error {
	return self.conn.SetReadDeadline(t)
}

// Passthrough to the underlying connection.
func (self *TDSWrappedConnection) SetWriteDeadline(t time.Time) error {
	return self.conn.SetWriteDeadline(t)
}

// Create a new MSSQL connection using the given raw socket connection to the database.
func NewConnection(conn net.Conn) *Connection {
	return &Connection{rawConn: conn, tdsConn: &TDSWrappedConnection{conn: conn, enabled: true}}
}

// Not implemented.
// Send the LOGIN packet. Called after Handshake(). If self.GetEncryptMode() == EncryptModeOff, disables TLS afterwards.
func (self *Connection) Login() {
	// TODO: send login
	if self.GetEncryptMode() != EncryptModeOn {
		// Client was only using encryption for login, so switch back to the rawConn
		self.tdsConn = &TDSWrappedConnection{conn: self.rawConn, enabled: true}
		// TDSWrappedConnection.Write(rawData) -> net.Conn.Write(header + rawData)
		// net.Conn.Read() -> header + rawData -> TDSWrappedConnection.Read() -> rawData
	}
}

// Connection.GetEncryptMode() returns the EncryptMode enum returned by the server in the PRELOGIN step.
// If PRELOGIN has not yet been called or if the ENCRYPTION token was not included / was invalid, returns EncryptModeUnknown.
func (self *Connection) GetEncryptMode() EncryptMode {
	if self.PreloginOptions == nil {
		return EncryptModeUnknown
	}
	ret, err := self.PreloginOptions.GetByteOption(PreloginEncryption)
	if err != nil {
		return EncryptModeUnknown
	}
	return EncryptMode(ret)
}

// Connection.Handshake() performs the initial handshake with the MSSQL server.
// First sends the PRELOGIN packet to the server and reads the response.
// Then, if necessary, does a TLS handshake.
// Returns the ENCRYPTION value from the response to PRELOGIN.
func (self *Connection) Handshake(flags *MSSQLFlags) (EncryptMode, error) {
	encryptMode := GetEncryptMode(flags.EncryptMode)
	mode, err := self.Prelogin(encryptMode)
	if err != nil {
		return mode, err
	}
	self.tdsConn.messageType = 0x12
	if mode == EncryptModeNotSupported {
		return mode, nil
	}
	tlsClient, err := flags.TLSFlags.GetTLSConnection(self.tdsConn)
	if err != nil {
		return mode, err
	}
	// do handshake: the raw TLS frames are wrapped in a TDS packet:
	// tls.Conn.Handshake() -> TDSWrappedConnection.Write(clientHello) -> net.Conn.Write(header + clientHello)
	// net.Conn.Read() => header + serverHello -> TDSWrappedConnection.Read() => serverHello -> tls.Conn.Handshake()
	err = tlsClient.Handshake()
	if err != nil {
		return mode, err
	}
	// After the SSL handshake has been established, wrap packets before they are passed into TLS, not after
	// TDSWrappedConnection.Write(rawData) -> tls.Conn.Write(header + rawData) -> net.Conn.Write(protected[header + rawData])
	// net.Conn.Read() => protected[header + rawData] -> tls.Conn.Read() => header + rawData -> TDSWrappedClient.Read() => rawData
	self.tdsConn.enabled = false
	self.tdsConn = &TDSWrappedConnection{conn: tlsClient, enabled: true}
	self.tlsConn = tlsClient
	return mode, nil
}

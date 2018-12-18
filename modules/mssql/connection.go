package mssql

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

var (
	// ErrTooLarge is returned when a size is larger than 64k.
	ErrTooLarge = errors.New("data too large")

	// ErrBufferTooSmall is returned when a buffer is smaller than necessary.
	ErrBufferTooSmall = errors.New("buffer too small")

	// ErrInvalidData is returned when we receive data from the server that
	// cannot be interpreted as a valid packet.
	ErrInvalidData = errors.New("received invalid data")

	// ErrNoServerEncryption is returned if the client requires encryption but
	// the server does not support it.
	ErrNoServerEncryption = errors.New("server doesn't support encryption")

	// ErrServerRequiresEncryption is returned if the server requires encryption
	// but the client does not support it.
	ErrServerRequiresEncryption = errors.New("server requires encryption")

	// ErrInvalidState is returned when attempting to take an action that is not
	// allowed in the current state of the connection.
	ErrInvalidState = errors.New("operation cannot be performed in this state")
)

// https://msdn.microsoft.com/en-us/library/dd358342.aspx
const (
	// TDSStatusNormal is a "Normal" message
	TDSStatusNormal uint8 = 0x00

	// TDSStatusEOM is an End of message (EOM). The packet is the last packet in
	// the whole request.
	TDSStatusEOM = 0x01

	// TDSStatusIgnore: Ignore this event (0x01 MUST also be set).
	// Client-to-server.
	TDSStatusIgnore = 0x02

	// TDSStatusResetConnection reset this connection before processing event.
	// Only set for event types Batch, RPC, or Transaction Manager request.
	// This status bit MUST NOT be set in conjunction with
	// the RESETCONNECTIONSKIPTRAN bit.
	// Client-to-server.
	TDSStatusResetConnection = 0x08

	// Reset the connection before processing event but do not modify the
	// transaction state. This status bit MUST NOT be set in conjunction with
	// the RESETCONNECTION bit.
	// Client-to-server.
	TDSStatusResetConnectionSkipTran = 0x10
)

// TDSPacketType represents the Type entry in the TDSPacket.
// Values are defined at https://msdn.microsoft.com/en-us/library/dd304214.aspx.
type TDSPacketType uint8

const (
	// TDSPacketTypeSQLBatch identifies a SQL batch.
	TDSPacketTypeSQLBatch TDSPacketType = 0x01

	// TDSPacketTypePreTDS7Login is the packet type for clients using "legacy"
	// pre-TDS7 logins.
	TDSPacketTypePreTDS7Login = 0x02

	// TDSPacketTypeRPC identifies an RPC packet.
	TDSPacketTypeRPC = 0x03

	// TDSPacketTypeTabularResult identifies a tabular result.
	TDSPacketTypeTabularResult = 0x04

	// TDSPacketTypeAttentionSignal identifies an attention signal.
	// Packet does not contain data.
	TDSPacketTypeAttentionSignal = 0x06

	// TDSPacketTypeBulkLoadData identifies a bulk-load-data packet.
	TDSPacketTypeBulkLoadData = 0x07

	// TDSPacketTypeFederatedAuthToken identifies a federated authentication
	// token.
	TDSPacketTypeFederatedAuthToken = 0x08

	// TDSPacketTypeTransactionManagerRequest identifies a transaction manager
	// request.
	TDSPacketTypeTransactionManagerRequest = 0x0E

	// TDSPacketTypeTDS7Login identifies a TDS7 login.
	TDSPacketTypeTDS7Login = 0x10

	// TDSPacketTypeSSPI identifies an SSPI packet.
	TDSPacketTypeSSPI = 0x11

	// TDSPacketTypePrelogin identifies a PRELOGIN packet.
	TDSPacketTypePrelogin = 0x12
)

var knownTDSPacketTypes = map[TDSPacketType]bool{
	TDSPacketTypeSQLBatch:                  true,
	TDSPacketTypePreTDS7Login:              true,
	TDSPacketTypeRPC:                       true,
	TDSPacketTypeTabularResult:             true,
	TDSPacketTypeAttentionSignal:           true,
	TDSPacketTypeBulkLoadData:              true,
	TDSPacketTypeFederatedAuthToken:        true,
	TDSPacketTypeTransactionManagerRequest: true,
	TDSPacketTypeTDS7Login:                 true,
	TDSPacketTypeSSPI:                      true,
	TDSPacketTypePrelogin:                  true,
}

// PreloginOptionToken represents a PL_OPTION_TOKEN value, defined at
// https://msdn.microsoft.com/en-us/library/dd357559.aspx.
type PreloginOptionToken uint8

const (
	// PreloginVersion is the VERSION token. Its value is the concatenation of
	// { major, minor, build >> 8, build & 0xff }.
	PreloginVersion PreloginOptionToken = 0x00

	// PreloginEncryption is the ENCRYPTION token. It is a single byte that
	// specifies what encryption options the client/server support (see
	// EncryptionMode)
	PreloginEncryption = 0x01

	// PreloginInstance is the INSTOPT token. Its value is the null-terminated
	// instance name.
	PreloginInstance = 0x02

	// PreloginThreadID is the THREADID token. Its value is the server's
	// internal thread ID for the connection, an unsigned long.
	PreloginThreadID = 0x03

	// PreloginMARS is the MARS token. Its value is a single byte specifying
	// whether the sender is requesting MARS support.
	PreloginMARS = 0x04

	// PreloginTraceID is the TRACEID token. Its value is the concatenation of
	// the server's GUID for the client (16 bytes), the server's activity GUID
	// (16 bytes) and the sequence ID (unsigned long).
	PreloginTraceID = 0x05

	// PreloginFedAuthRequired is the FEDAUTHREQUIRED token. Its value is a
	// byte representing whether the sender requires federated authentication.
	PreloginFedAuthRequired = 0x06

	// PreloginNonce is the NONCEOPT token. Its value is a 32-byte nonce.
	PreloginNonce = 0x07

	// PreloginTerminator is the TERMINATOR token. It is not an actual tag, but
	// a standalone marker.
	PreloginTerminator = 0xFF
)

// Mapping to documented names, also serves to identify unknown values for JSON
// marshalling
var knownPreloginOptionTokens = map[PreloginOptionToken]string{
	PreloginVersion:         "VERSION",
	PreloginEncryption:      "ENCRYPTION",
	PreloginInstance:        "INSTOPT",
	PreloginThreadID:        "THREADID",
	PreloginMARS:            "MARS",
	PreloginTraceID:         "TRACEID",
	PreloginFedAuthRequired: "FEDAUTHREQUIRED",
	PreloginNonce:           "NONCE",
}

// PreloginOption values are stored as byte arrays; actual types are specified
// in the docs
type PreloginOption []byte

// PreloginOptions maps the token to the value for that option
type PreloginOptions map[PreloginOptionToken]PreloginOption

// EncryptMode is defined at
// https://msdn.microsoft.com/en-us/library/dd357559.aspx
type EncryptMode byte

const (
	// EncryptModeUnknown is not a valid ENCRYPTION value
	EncryptModeUnknown EncryptMode = 0xff

	// EncryptModeOff means that encryption will only be used for login
	EncryptModeOff = 0x00

	// EncryptModeOn means that encryption will be used for the entire session
	EncryptModeOn = 0x01

	// EncryptModeNotSupported means that the client/server does not support
	// encryption
	EncryptModeNotSupported = 0x02

	// EncryptModeRequired is sent by the server when the client sends
	// EncryptModNotSupported but the server requires it
	EncryptModeRequired = 0x03
)

// These are the macro values defined in the MSDN docs
var stringToEncryptMode = map[string]EncryptMode{
	"UNKNOWN":         0xff,
	"ENCRYPT_OFF":     0x00,
	"ENCRYPT_ON":      0x01,
	"ENCRYPT_NOT_SUP": 0x02,
	"ENCRYPT_REQ":     0x03,
}

var encryptModeToString = map[EncryptMode]string{
	EncryptModeOff:          "ENCRYPT_OFF",
	EncryptModeOn:           "ENCRYPT_ON",
	EncryptModeNotSupported: "ENCRYPT_NOT_SUP",
	EncryptModeRequired:     "ENCRYPT_REQ",
	EncryptModeUnknown:      "UNKNOWN",
}

// ServerVersion is a direct representation of the VERSION PRELOGIN token value.
type ServerVersion struct {
	Major       uint8  `json:"major"`
	Minor       uint8  `json:"minor"`
	BuildNumber uint16 `json:"build_number"`
}

// Decode a VERSION response and return the parsed ServerVersion struct
// As defined in the MSDN docs, these come from token 0:
//	VERSION -- UL_VERSION = ((US_BUILD<<16)|(VER_SQL_MINOR<<8)|( VER_SQL_MAJOR))
func decodeServerVersion(buf []byte) *ServerVersion {
	if len(buf) != 6 {
		return nil
	}
	return &ServerVersion{
		Major:       buf[0],
		Minor:       buf[1],
		BuildNumber: binary.BigEndian.Uint16(buf[2:4]),
	}
}

// String returns the dotted-decimal representation of the ServerVersion:
// "MAJOR.MINOR.BUILD_NUMBER".
func (version *ServerVersion) String() string {
	if version == nil {
		return "<nil version>"
	}
	return fmt.Sprintf("%d.%d.%d", version.Major, version.Minor, version.BuildNumber)
}

// TDSHeader is an 8-byte structure prepended to all TDS packets.
// See https://msdn.microsoft.com/en-us/library/dd340948.aspx for details.
type TDSHeader struct {
	// Type is the TDSPacketType.
	Type uint8

	// Status is a bit field indicating message state.
	Status uint8

	// "Length is the size of the packet including the 8 bytes in the packet
	// header. It is the number of bytes from the start of this header to the
	// start of the next packet header. Length is a 2-byte, unsigned short int
	// and is represented in network byte order (big-endian). Starting with TDS
	// 7.3, the Length MUST be the negotiated packet size when sending a packet
	// from client to server, unless it is the last packet of a request (that
	// is, the EOM bit in Status is ON), or the client has not logged in."
	Length uint16

	// SPID is the process ID on the server for the current connection.
	// Provided for debugging purposes (e.g. identify which server thread sent
	// the packet).
	SPID uint16

	// Called PacketID in the docs. Incremented (modulo 256) each time a packet
	// is sent. Allegedly ignored by the server.
	SequenceNumber uint8

	// "This 1 byte is currently not used. This byte SHOULD be set to 0x00 and
	// SHOULD be ignored by the receiver."
	Window uint8
}

// decodeTDSHeader interprets the first 8 bytes of buf as a TDSHeader.
func decodeTDSHeader(buf []byte) (*TDSHeader, error) {
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

// readTDSHeader attempts to read 8 bytes from conn using io.ReadFull, and
// decodes the result as a TDSHeader.
func readTDSHeader(conn io.Reader) (*TDSHeader, error) {
	buf := make([]byte, 8)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	return decodeTDSHeader(buf)
}

// Encode returns the encoding of the header as a byte slice.
func (header *TDSHeader) Encode() []byte {
	ret := make([]byte, 8)
	ret[0] = header.Type
	ret[1] = header.Status
	binary.BigEndian.PutUint16(ret[2:4], header.Length)
	binary.BigEndian.PutUint16(ret[4:6], header.SPID)
	ret[6] = header.SequenceNumber
	ret[7] = header.Window
	return ret
}

// HeaderSize calculates the length of the PRELOGIN_OPTIONs, i.e. the number of
// bytes before the payload starts.
// Each PRELOGIN_OPTION is a 1-byte token, a 2-byte length and a 2-byte offset,
// and each is followed by a single-byte TERMINATOR, giving 5 * len(*self) + 1.
func (options PreloginOptions) HeaderSize() int {
	return 5*len(options) + 1
}

// Size returns the total size of the PRELOGIN packet body (so not including the
// TDSPacket header).
// Specifically, it is the header size + the size of all of the values.
func (options PreloginOptions) Size() int {
	// 5 bytes per option for token/offset/length + 1 byte for terminator
	ret := options.HeaderSize()
	// + actual sizes of each option
	for _, option := range options {
		ret += len(option)
	}
	return ret
}

// GetByteOption returns a single-byte PRELOGIN option for the given token. If
// there is no value for that token present, or if the value is not exactly one
// byte long, returns an ErrInvalidData.
func (options PreloginOptions) GetByteOption(token PreloginOptionToken) (byte, error) {
	ret, ok := options[token]
	if !ok || len(ret) != 1 {
		return 0, ErrInvalidData
	}
	return ret[0], nil
}

// GetUint16Option returns a big-endian uint16 PRELOGIN option for the given
// token. If there is no value for that token present, or if the value is not
// exactly two bytes long, returns an ErrInvalidData.
func (options PreloginOptions) GetUint16Option(token PreloginOptionToken) (uint16, error) {
	ret, ok := options[token]
	if !ok || len(ret) != 2 {
		return 0, ErrInvalidData
	}
	return binary.BigEndian.Uint16(ret[0:2]), nil
}

// GetVersion decodes the VERSION response value if present; if not (or it is
// invalid), returns nil.
func (options PreloginOptions) GetVersion() *ServerVersion {
	version, hasVersion := options[PreloginVersion]
	if !hasVersion {
		return nil
	}
	return decodeServerVersion(version)
}

// Encode returns the encoding of the PRELOGIN body as described in
// https://msdn.microsoft.com/en-us/library/dd357559.aspx.
func (options PreloginOptions) Encode() ([]byte, error) {
	size := options.Size()
	if size > 0xffff {
		return nil, ErrTooLarge
	}
	ret := make([]byte, size)
	// cursor always points to the location for the next PL_OPTION header value
	cursor := ret[0:]
	// offset always points to the next-available location for values in body,
	// starting just after the TERMINATOR token
	offset := options.HeaderSize()
	// Ensure that the tokens are encoded in ascending order
	var sortedKeys []int
	for k := range options {
		sortedKeys = append(sortedKeys, int(k))
	}
	sort.Ints(sortedKeys)
	for _, ik := range sortedKeys {
		k := PreloginOptionToken(ik)
		v := options[k]
		if len(cursor) < 5 {
			return nil, fmt.Errorf("encode: size mismatch (options.Size()=%d)", options.Size())
		}
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
	if len(cursor) < 1 {
		return nil, fmt.Errorf("encode: size mismatch (options.Size()=%d, len(sortedKeys)=%d)", options.Size(), len(sortedKeys))
	}
	// Write the terminator after the last PL_OPTION header
	// (and just before the first value)
	cursor[0] = 0xff
	return ret, nil
}

// Decode a PreloginOptions object from the given body. Any extra bytes are
// returned in rest.
// If body can't be decoded as a PRELOGIN body, returns nil, nil, ErrInvalidData
func decodePreloginOptions(body []byte) (result *PreloginOptions, rest []byte, err error) {
	if len(body) < 1 {
		return nil, nil, ErrInvalidData
	}
	cursor := body[:]
	options := make(PreloginOptions)
	max := 0
	for cursor[0] != 0xff {
		if len(cursor) < 6 {
			// if the cursor is not pointing to the terminator, and we do not
			// have 5 bytes + terminator remaining, it's a bad packet
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
			// max points to the byte after the last byte consumed in body
			max = int(offset + length)
		}
		cursor = cursor[5:]
	}
	return &options, body[max:], nil
}

// preloginOptionsJSON is an auxiliary struct that holds the output format of
// the PreloginOptions
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

// unknownPreloginOptionJSON holds the raw PRELOGIN token and value for unknown
// tokens.
type unknownPreloginOptionJSON struct {
	Token uint8  `json:"token"`
	Value []byte `json:"value"`
}

// MarshalJSON puts the map[PreloginOptionToken]PreloginOption into a more
// database-friendly format.
func (options PreloginOptions) MarshalJSON() ([]byte, error) {
	opts := options
	aux := preloginOptionsJSON{}
	aux.Version = options.GetVersion()

	theEncryptMode, hasEncrypt := opts[PreloginEncryption]
	if hasEncrypt && len(theEncryptMode) == 1 {
		temp := EncryptMode(theEncryptMode[0])
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
		temp := uint8(0)
		if len(fedAuthRequired) > 0 {
			temp = fedAuthRequired[0]
		} else {
			logrus.Debugf("fedAuthRequired was present but empty (options=%#v)", options)
		}
		aux.FedAuthRequired = &temp
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

// TDSPacket is a header followed by the body. Length is calculated from the
// start of the packet, NOT the start of the body.
type TDSPacket struct {
	TDSHeader
	Body []byte
}

// decodeTDSPacket decodes a TDSPacket from the start of buf, returning the
// packet and any remaining bytes following it.
func decodeTDSPacket(buf []byte) (*TDSPacket, []byte, error) {
	header, err := decodeTDSHeader(buf)
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

// Encode returns the encoded packet: header + body. Updates the header's length
// to match the actual body length.
func (packet *TDSPacket) Encode() ([]byte, error) {
	if len(packet.Body)+8 > 0xffff {
		return nil, ErrTooLarge
	}
	packet.TDSHeader.Length = uint16(len(packet.Body) + 8)
	header := packet.TDSHeader.Encode()
	ret := append(header, packet.Body...)
	return ret, nil
}

// String returns a string representation of the EncryptMode.
func (mode EncryptMode) String() string {
	ret, ok := encryptModeToString[mode]
	if !ok {
		return encryptModeToString[EncryptModeUnknown]
	}
	return ret
}

// MarshalJSON ensures that the EncryptMode is encoded in the string format.
func (mode EncryptMode) MarshalJSON() ([]byte, error) {
	return json.Marshal(mode.String())
}

// getEncryptMode returns the EncryptMode value for the given string label.
func getEncryptMode(enum string) EncryptMode {
	ret, ok := stringToEncryptMode[enum]
	if !ok {
		return EncryptModeUnknown
	}
	return ret
}

// Connection wraps the state of a single MSSQL connection.
// NOT thread safe, due e.g. to the state (e.g. messageType) in tdsConnection.
type Connection struct {
	// rawConn is the raw network connection. Both tlsConn and tdsConn wrap this
	rawConn net.Conn

	// tlsConn is the TLS client. During the handshake, it wraps an active
	// tdsConnection. Afterwards, the inner tdsConnection is deactivated.
	tlsConn *zgrab2.TLSConnection

	// tdsConn allows sending / receiving TDS packets through the net.Conn
	// interface. Wraps either rawConn or tlsConn.
	// The genesis of this is the fact that MSSQL requires the TLS handshake
	// packets to be wrapped in TDS headers.
	tdsConn *tdsConnection

	// sequenceNumber is the sequence number used for the last packet (though
	// they are sent to the server mod 256).
	sequenceNumber int

	// readValidTDSPacket gets set to true once we have read a valid TDS packet
	// on any TDSConnection.
	readValidTDSPacket bool

	// PreloginOptions contains the values returned by the server in the
	// PRELOGIN call, once it has happened.
	PreloginOptions *PreloginOptions
}

// SendTDSPacket sends a TDS packet with the given type and body.
// NOTE - sets tdsConn.messageType to packetType and leaves it there.
func (connection *Connection) SendTDSPacket(packetType uint8, body []byte) error {
	connection.sequenceNumber++
	connection.tdsConn.messageType = packetType
	_, err := connection.tdsConn.Write(body)
	return err
}

// readPreloginPacket reads and decodes an entire Prelogin packet from tdsConn
func (connection *Connection) readPreloginPacket() (*TDSPacket, *PreloginOptions, error) {
	packet, err := connection.tdsConn.ReadPacket()
	if err != nil {
		return nil, nil, err
	}
	if packet.Type != TDSPacketTypeTabularResult {
		return packet, nil, &zgrab2.ScanError{Status: zgrab2.SCAN_APPLICATION_ERROR, Err: err}
	}
	defer zgrab2.LogPanic("Error decoding Prelogin packet %#v", packet.Body)
	plOptions, rest, err := decodePreloginOptions(packet.Body)
	if err != nil {
		return packet, nil, err
	}
	if len(rest) > 0 {
		return packet, nil, ErrInvalidData
	}
	return packet, plOptions, nil
}

// Prelogin sends the Prelogin packet and reads the response from the server.
// It populates the connection's PreloginOptions field with the response, and
// specifically returns the ENCRYPTION value (which is used to determine whether
// a TLS handshake needs to be done).
func (connection *Connection) prelogin(clientEncrypt EncryptMode) (EncryptMode, error) {
	if clientEncrypt < 0 || clientEncrypt > 0xff {
		return EncryptModeUnknown, ErrInvalidData
	}
	clientOptions := PreloginOptions{
		PreloginVersion:    {0, 0, 0, 0, 0, 0},
		PreloginEncryption: {byte(clientEncrypt)},
		PreloginInstance:   {0},
		PreloginThreadID:   {0, 0, 0, 0},
		PreloginMARS:       {0},
	}
	preloginBody, err := clientOptions.Encode()
	if err != nil {
		return EncryptModeUnknown, err
	}
	err = connection.SendTDSPacket(TDSPacketTypePrelogin, preloginBody)

	if err != nil {
		return EncryptModeUnknown, err
	}
	packet, response, err := connection.readPreloginPacket()
	if response != nil {
		connection.PreloginOptions = response
	}
	if err != nil {
		if packet != nil {
			// FIXME: debug packet info?
			logrus.Debugf("Got bad packet? type=0x%02x", packet.Type)
		}
		return EncryptModeUnknown, err
	}

	serverEncrypt := connection.getEncryptMode()

	if clientEncrypt == EncryptModeOn && serverEncrypt == EncryptModeNotSupported {
		return serverEncrypt, ErrNoServerEncryption
	}
	if clientEncrypt == EncryptModeNotSupported && serverEncrypt == EncryptModeRequired {
		return serverEncrypt, ErrServerRequiresEncryption
	}
	return serverEncrypt, nil
}

// Close closes / resets any resources associated with the connection, and
// returns the first error (if any) that it encounters.
func (connection *Connection) Close() error {
	connection.sequenceNumber = 0
	connection.tdsConn = nil
	connection.tlsConn = nil
	temp := connection.rawConn
	connection.rawConn = nil
	return temp.Close()
}

// tdsConnection is an implementation of net.Conn that adapts raw input (e.g.
// from an external library like tls.Handshake()) by adding / removing TDS
// headers for writes / reads.
// For example, wrapped.Write("abc") will call
// wrapped.conn.Write(TDSHeader + "abc"), while wrapped.Read() will read
// TDSHeader + "def" from net.Conn, then return "def" to the caller.
// For reads, this reads entire TDS packets at a time -- blocking until it
// can -- and returns partial packets (or data from multiple packets) as needed.
type tdsConnection struct {
	// The underlying conn. Traffic sent to this conn is sent as-is, but when
	// using the higher-level APIs, this sends and receives TDS-wrapped packets.
	conn net.Conn

	// The connection this wrapper is attached to.
	session *Connection

	// If enabled == false, reads and writes to the wrapped connection pass
	// directly through to conn.
	enabled bool

	// messageType is the header type added to written packets.
	messageType byte

	// remainder contains bytes read from net.conn that have not yet been
	// returned to Read() calls on this instance.
	remainder []byte
}

// return the lesser of a, b
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Check if the given header is likely to be a valid TDS header (for detection
// purposes).
func isValidTDSHeader(header *TDSHeader) bool {
	if header == nil {
		logrus.Debug("nil header")
		return false
	}

	if header.Status != TDSStatusEOM {
		// The only valid/recognized values for the server status are 0x00 and
		// 0x01 -- the rest of the bits are either client-to-server flags or
		// undefined.
		// We don't say we've read a packet until we've received the final
		// packet in a sequence, so 0x00 is also out.
		return false
	}

	if header.Window != 0 {
		// "This 1 byte is currently not used. This byte SHOULD be set to 0x00
		//  and SHOULD be ignored by the receiver."
		return false
	}
	_, ok := knownTDSPacketTypes[TDSPacketType(header.Type)]
	if !ok {
		return false
	}
	return true
}

// Read a single packet from the connection and return the whole packet (this is
// the only way to see the packet type, sequence number, etc).
func (connection *tdsConnection) ReadPacket() (*TDSPacket, error) {
	if !connection.enabled {
		return nil, ErrInvalidState
	}
	header, err := readTDSHeader(connection.conn)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, header.Length-8)
	_, err = io.ReadFull(connection.conn, buf)
	if err != nil {
		return nil, err
	}
	if isValidTDSHeader(header) {
		connection.session.readValidTDSPacket = true
	}
	return &TDSPacket{
		TDSHeader: *header,
		Body:      buf,
	}, nil
}

// The wrapped Read() call. If not enabled, just passes through to conn.Read(b).
// If it has sufficient data in remainder to satisfy the read, just return that.
// Otherwise, attempt to read a header (FIXME: with a 1s timeout), then block
// oreading the entire packet and add it to the remainder.
// Then, consume and repeat. If there is an error reading, return the error back
// to the user with the corresponding bytes read.
func (connection *tdsConnection) Read(b []byte) (n int, err error) {
	if !connection.enabled {
		return connection.conn.Read(b)
	}
	output := b
	soFar := 0
	for len(output) > len(connection.remainder) {
		copy(output, connection.remainder)
		output = output[len(connection.remainder):]
		soFar = soFar + len(connection.remainder)
		connection.remainder = make([]byte, 0)
		// BEGIN FIXME
		connection.conn.SetReadDeadline(time.Now().Add(1e9))
		header, err := readTDSHeader(connection.conn)
		if err != nil {
			return soFar, err
		}
		// END FIXME
		connection.remainder = make([]byte, header.Length-8)
		_, err = io.ReadFull(connection.conn, connection.remainder)
		if err != nil {
			logrus.Debugf("Error reading body: %v", err)
			return soFar, err
		}
		toCopy := min(len(output), len(connection.remainder))
		copy(output, connection.remainder[0:toCopy])
		output = output[toCopy:]
		connection.remainder = connection.remainder[toCopy:]
		soFar = soFar + toCopy
	}
	// now len(output) <= len(remainder)
	copy(output, connection.remainder)
	connection.remainder = connection.remainder[len(output):]
	return len(b), nil
}

// The wrapped Write method. If not enabled, just pass through to conn.Write.
// Otherise, wrap b in a TDSHeader with the next sequence number and packet type
// given by messageType, and send it in a single conn.Write().
func (connection *tdsConnection) Write(b []byte) (n int, err error) {
	if !connection.enabled {
		return connection.conn.Write(b)
	}
	if len(b)+8 > 0xffff {
		return 0, ErrTooLarge
	}
	connection.session.sequenceNumber++
	header := TDSHeader{
		Type:           connection.messageType,
		Status:         TDSStatusEOM,
		Length:         uint16(len(b) + 8),
		SPID:           0,
		SequenceNumber: uint8(connection.session.sequenceNumber % 0x100),
		Window:         0,
	}
	buf := header.Encode()
	output := append(buf, b...)
	ret, err := connection.conn.Write(output)
	if ret > 0 {
		ret = ret - 8
		if ret < 0 {
			ret = 0
		}
	}
	return ret, err
}

// Passthrough to the underlying connection.
func (connection *tdsConnection) Close() error {
	return connection.conn.Close()
}

// Passthrough to the underlying connection.
func (connection *tdsConnection) LocalAddr() net.Addr {
	return connection.conn.LocalAddr()
}

// Passthrough to the underlying connection.
func (connection *tdsConnection) RemoteAddr() net.Addr {
	return connection.conn.RemoteAddr()
}

// Passthrough to the underlying connection.
func (connection *tdsConnection) SetDeadline(t time.Time) error {
	return connection.conn.SetDeadline(t)
}

// Passthrough to the underlying connection.
func (connection *tdsConnection) SetReadDeadline(t time.Time) error {
	return connection.conn.SetReadDeadline(t)
}

// Passthrough to the underlying connection.
func (connection *tdsConnection) SetWriteDeadline(t time.Time) error {
	return connection.conn.SetWriteDeadline(t)
}

// NewConnection creates a new MSSQL connection using the given raw socket
// connection to the database.
func NewConnection(conn net.Conn) *Connection {
	ret := &Connection{rawConn: conn}
	ret.tdsConn = &tdsConnection{conn: conn, session: ret, enabled: true}
	return ret
}

// Login sends the LOGIN packet. Called after Handshake(). If
// self.getEncryptMode() == EncryptModeOff, disables TLS afterwards.
// NOTE: Not currently implemented.
func (connection *Connection) Login() {
	panic("unimplemented")
	// TODO: send login
	if connection.getEncryptMode() != EncryptModeOn {
		// Client was only using encryption for login, so switch back to rawConn
		connection.tdsConn = &tdsConnection{conn: connection.rawConn, enabled: true, session: connection}
		// tdsConnection.Write(rawData) -> net.Conn.Write(header + rawData)
		// conn.Read() -> header + rawData -> tdsConnection.Read() -> rawData
	}
}

// getEncryptMode returns the EncryptMode enum returned by the server in the
// PRELOGIN step. If PRELOGIN has not yet been called or if the ENCRYPTION token
// was not included / was invalid, returns EncryptModeUnknown.
func (connection *Connection) getEncryptMode() EncryptMode {
	if connection.PreloginOptions == nil {
		return EncryptModeUnknown
	}

	ret, err := connection.PreloginOptions.GetByteOption(PreloginEncryption)
	if err != nil {
		return EncryptModeUnknown
	}
	return EncryptMode(ret)
}

// Handshake performs the initial handshake with the MSSQL server.
// First sends the PRELOGIN packet to the server and reads the response.
// Then, if necessary, does a TLS handshake.
// Returns the ENCRYPTION value from the response to PRELOGIN.
func (connection *Connection) Handshake(flags *Flags) (EncryptMode, error) {
	encryptMode := getEncryptMode(flags.EncryptMode)
	mode, err := connection.prelogin(encryptMode)
	if err != nil {
		return mode, err
	}
	connection.tdsConn.messageType = 0x12
	if mode == EncryptModeNotSupported {
		return mode, nil
	}
	tlsClient, err := flags.TLSFlags.GetTLSConnection(connection.tdsConn)
	if err != nil {
		return mode, err
	}
	// do handshake: the raw TLS frames are wrapped in a TDS packet:
	// tls.Conn.Handshake() ->
	// -> tdsConnection.Write(clientHello) ->
	// -> net.Conn.Write(header + clientHello)
	//
	// net.Conn.Read() => header + serverHello ->
	// -> tdsConnection.Read() => serverHello ->
	// -> tls.Conn.Handshake()
	err = tlsClient.Handshake()
	if err != nil {
		return mode, err
	}
	// After the SSL handshake has been established, wrap packets before they
	// are passed into TLS, not after.

	// tdsConnection.Write(rawData) ->
	// -> tls.Conn.Write(header + rawData) ->
	// -> net.Conn.Write(protected[header + rawData])
	//
	// net.Conn.Read() => protected[header + rawData] ->
	// -> tls.Conn.Read() => header + rawData ->
	// -> TDSWrappedClient.Read() => rawData
	connection.tdsConn.enabled = false
	connection.tdsConn = &tdsConnection{conn: tlsClient, enabled: true, session: connection}
	connection.tlsConn = tlsClient
	return mode, nil
}

package mssql

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	logrus "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

var (
	errTooLarge                 	  = errors.New("data too large")
	errBufferTooSmall                 = errors.New("buffer too small")
	errInvalidData                    = errors.New("data does not have the expected format")
	errNoServerEncryption             = errors.New("server does not support encryption")
	errServerRequiresEncryption       = errors.New("server requires encryption")
	errInvalidState                   = errors.New("operation cannot be performed in this state")
)

// https://msdn.microsoft.com/en-us/library/dd358342.aspx
const (
	tdsStatusNormal                  uint8 = 0x00
	tdsStatusEOM                           = 0x01
	tdsStatusIgnore                        = 0x02
	tdsStatusResetConnection               = 0x08
	tdsStatusResetConnectionSkipTran       = 0x10
)

type TDSPacketType uint8

// https://msdn.microsoft.com/en-us/library/dd304214.aspx
const (
	tdsPacketTypeSQLBatch                  TDSPacketType = 0x01
	tdsPacketTypePreTDS7Login                            = 0x02
	tdsPacketTypeRPC                                     = 0x03
	tdsPacketTypeTabularResult                           = 0x04
	tdsPacketTypeAttentionSignal                         = 0x06
	tdsPacketTypeBulkLoadData                            = 0x07
	tdsPacketTypeFederatedAuthToken                      = 0x08
	tdsPacketTypeTransactionManagerRequest               = 0x0E
	tdsPacketTypeTDS7Login                               = 0x10
	tdsPacketTypeSSPI                                    = 0x11
	tdsPacketTypePrelogin                                = 0x12
)

// From https://msdn.microsoft.com/en-us/library/dd357559.aspx - PL_OPTION_TOKEN values
type preloginOptionToken uint8

const (
	preloginVersion         preloginOptionToken = 0x00
	preloginEncryption                          = 0x01
	preloginInstance                            = 0x02
	preloginThreadID                            = 0x03
	preloginMARS                                = 0x04
	preloginTraceID                             = 0x05
	preloginFedAuthRequired                     = 0x06
	preloginNonce                               = 0x07
	preloginTerminator                          = 0xFF
)

// Mapping to documented names, also serves to identify unknown values for JSON marshalling
var knownPreloginOptionTokens map[preloginOptionToken]string = map[preloginOptionToken]string{
	preloginVersion:         "VERSION",
	preloginEncryption:      "ENCRYPTION",
	preloginInstance:        "INSTOPT",
	preloginThreadID:        "THREADID",
	preloginMARS:            "MARS",
	preloginTraceID:         "TRACEID",
	preloginFedAuthRequired: "FEDAUTHREQUIRED",
	preloginNonce:           "NONCE",
}

// preloginOption values are stored as byte arrays; actual types are specified in the docs
type preloginOption []byte

// preloginOptions maps the token to the value for that option
type preloginOptions map[preloginOptionToken]preloginOption

// encryptMode is defined at https://msdn.microsoft.com/en-us/library/dd357559.aspx
type encryptMode byte

const (
	// encryptModeUnknown is not a valid ENCRYPTION value
	encryptModeUnknown encryptMode = 0xff
	// encryptModeOff means that encryption will only be used for login
	encryptModeOff encryptMode = 0x00
	// encryptModeOn means that encryption will be used for the entire session
	encryptModeOn encryptMode = 0x01
	// encryptModeNotSupported means that the client/server does not support encryption
	encryptModeNotSupported encryptMode = 0x02
	// encryptModeRequired is sent by the server when the client sends EncryptModNotSupported but the server requires it
	encryptModeRequired encryptMode = 0x03
)

// These are the macro values defined in the MSDN docs
var stringToEncryptMode map[string]encryptMode = map[string]encryptMode{
	"UNKNOWN":         0xff,
	"ENCRYPT_OFF":     0x00,
	"ENCRYPT_ON":      0x01,
	"ENCRYPT_NOT_SUP": 0x02,
	"ENCRYPT_REQ":     0x03,
}

var encryptModeToString map[encryptMode]string = map[encryptMode]string{
	encryptModeOff:          "ENCRYPT_OFF",
	encryptModeOn:           "ENCRYPT_ON",
	encryptModeNotSupported: "ENCRYPT_NOT_SUP",
	encryptModeRequired:     "ENCRYPT_REQ",
	encryptModeUnknown:      "UNKNOWN",
}

// Direct representation of the VERSION PRELOGIN token value.
type serverVersion struct {
	Major       uint8  `json:"major"`
	Minor       uint8  `json:"minor"`
	BuildNumber uint16 `json:"build_number"`
}

// Decode a VERSION response and return the parsed serverVersion struct
// As defined in the MSDN docs, these come from token 0: VERSION -- UL_VERSION =   ((US_BUILD<<16)|(VER_SQL_MINOR<<8)|( VER_SQL_MAJOR))
func decodeServerVersion(buf []byte) *serverVersion {
	if len(buf) != 6 {
		return nil
	}
	return &serverVersion{
		Major:       buf[0],
		Minor:       buf[1],
		BuildNumber: binary.BigEndian.Uint16(buf[2:4]),
	}
}

// tdsHeader: an 8-byte structure prepended to all TDS packets. See https://msdn.microsoft.com/en-us/library/dd340948.aspx for details.
type tdsHeader struct {
	Type           uint8
	Status         uint8  // "Status is a bit field used to indicate the message state. Status is a 1-byte unsigned char. The following Status bit flags are defined."
	Length         uint16 // "Length is the size of the packet including the 8 bytes in the packet header. It is the number of bytes from the start of this header to the start of the next packet header. Length is a 2-byte, unsigned short int and is represented in network byte order (big-endian). Starting with TDS 7.3, the Length MUST be the negotiated packet size when sending a packet from client to server, unless it is the last packet of a request (that is, the EOM bit in Status is ON), or the client has not logged in."
	SPID           uint16 // "Spid is the process ID on the server, corresponding to the current connection. This information is sent by the server to the client and is useful for identifying which thread on the server sent the TDS packet. It is provided for debugging purposes. The client MAY send the SPID value to the server. If the client does not, then a value of 0x0000 SHOULD be sent to the server. This is a 2-byte value and is represented in network byte order (big-endian)."
	SequenceNumber uint8  // "PacketID is used for numbering message packets that contain data in addition to the packet header. PacketID is a 1-byte, unsigned char. Each time packet data is sent, the value of PacketID is incremented by 1, modulo 256. This allows the receiver to track the sequence of TDS packets for a given message. This value is currently ignored."
	Window         uint8  // "This 1 byte is currently not used. This byte SHOULD be set to 0x00 and SHOULD be ignored by the receiver."
}

// decodeTDSHeader interprets the first 8 bytes of buf as a tdsHeader.
func decodeTDSHeader(buf []byte) (*tdsHeader, error) {
	if len(buf) < 8 {
		return nil, errBufferTooSmall
	}
	return &tdsHeader{
		Type:           buf[0],
		Status:         buf[1],
		Length:         binary.BigEndian.Uint16(buf[2:4]),
		SPID:           binary.BigEndian.Uint16(buf[4:6]),
		SequenceNumber: buf[6],
		Window:         buf[7],
	}, nil
}

// readTDSHeader attempts to read 8 bytes from conn using io.ReadFull, and decodes the result as a tdsHeader.
func readTDSHeader(conn io.Reader) (*tdsHeader, error) {
	buf := make([]byte, 8)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	return decodeTDSHeader(buf)
}

// tdsHeader.Encode() returns the encoding of the header as a byte slice.
func (header *tdsHeader) Encode() []byte {
	ret := make([]byte, 8)
	ret[0] = header.Type
	ret[1] = header.Status
	binary.BigEndian.PutUint16(ret[2:4], header.Length)
	binary.BigEndian.PutUint16(ret[4:6], header.SPID)
	ret[6] = header.SequenceNumber
	ret[7] = header.Window
	return ret
}

// preloginOptions.HeaderSize() calculates the length of the PRELOGIN_OPTIONs / the number of bytes before the payload starts.
// Each PRELOGIN_OPTION is a 1-byte token, a 2-byte length and a 2-byte offset, and all of them are followed by a single-byte TERMINATOR, giving 5 * len(*self) + 1.
func (options *preloginOptions) HeaderSize() int {
	return 5*len(*options) + 1
}

// preloginOptions.Size() returns the total size of the PRELOGIN packet body (so, not including the tdsPacket header)
// Namely, the header size + the size of all of the values.
func (options *preloginOptions) Size() int {
	// 5 bytes per option for token/offset/length + 1 byte for terminator
	ret := options.HeaderSize()
	// + actual sizes of each option
	for _, option := range *options {
		ret += len(option)
	}
	return ret
}

// preloginOptions.GetByteOption() returns a single-byte PRELOGIN option for the given token.
// If there is no value for that token present, or if the value is not exactly one byte long, returns an errInvalidData.
func (options *preloginOptions) GetByteOption(token preloginOptionToken) (byte, error) {
	ret, ok := (*options)[token]
	if !ok || len(ret) != 1 {
		return 0, errInvalidData
	}
	return ret[0], nil
}

// preloginOptions.GetByteOption() returns a big-endian uint16 PRELOGIN option for the given token.
// If there is no value for that token present, or if the value is not exactly two bytes long, returns an errInvalidData.
func (options *preloginOptions) GetUint16Option(token preloginOptionToken) (uint16, error) {
	ret, ok := (*options)[token]
	if !ok || len(ret) != 2 {
		return 0, errInvalidData
	}
	return binary.BigEndian.Uint16(ret[0:2]), nil
}

// preloginOptions.GetVersion() decodes the VERSION response value if present; if not (or invalid), returns nil
func (options *preloginOptions) GetVersion() *serverVersion {
	version, hasVersion := (*options)[preloginVersion]
	if !hasVersion {
		return nil
	}
	return decodeServerVersion(version)
}

// preloginOptions.Encode() returns the encoding of the PRELOGIN body as described in https://msdn.microsoft.com/en-us/library/dd357559.aspx
func (options *preloginOptions) Encode() ([]byte, error) {
	size := options.Size()
	if size > 0xffff {
		return nil, errTooLarge
	}
	ret := make([]byte, size)
	// cursor always points to the location for the next PL_OPTION header value
	cursor := ret[0:]
	// offset always points to the next-available location for values in body, starting just after the TERMINATOR token
	offset := options.HeaderSize()
	// Ensure that the tokens are encoded in ascending order
	var sortedKeys []int
	for k, _ := range *options {
		sortedKeys = append(sortedKeys, int(k))
	}
	sort.Ints(sortedKeys)
	for _, ik := range sortedKeys {
		k := preloginOptionToken(ik)
		v := (*options)[k]
		cursor[0] = byte(k)
		if offset > 0xffff {
			return nil, errTooLarge
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

// Decode a preloginOptions object from the given body. Any extra bytes are returned in rest.
// If body cannot be decoded as a PRELOGIN body, returns nil, nil, errInvalidData.
func decodePreloginOptions(body []byte) (result *preloginOptions, rest []byte, err error) {
	cursor := body[:]
	options := make(preloginOptions)
	max := 0
	for cursor[0] != 0xff {
		if len(cursor) < 6 {
			// if the cursor is not pointing to the terminator, and we do not have 5 bytes + terminator remaining, it's a bad packet
			return nil, nil, errInvalidData
		}
		token := preloginOptionToken(cursor[0])
		offset := binary.BigEndian.Uint16(cursor[1:3])
		length := binary.BigEndian.Uint16(cursor[3:5])
		if len(body) < int(offset+length) {
			return nil, nil, errInvalidData
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

// preloginOptionsJSON is an auxiliary struct that holds the output format of the preloginOptions
type preloginOptionsJSON struct {
	Version *serverVersion `json:"version,omitempty"`

	Encryption *encryptMode `json:"encrypt_mode,omitempty"`
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

// preloginOptions.MarshalJSON() puts the map[preloginOptionToken]preloginOption into a more database-friendly format
func (options *preloginOptions) MarshalJSON() ([]byte, error) {
	opts := *options
	aux := preloginOptionsJSON{}
	aux.Version = options.GetVersion()

	theEncryptMode, hasEncrypt := opts[preloginEncryption]
	if hasEncrypt && len(theEncryptMode) == 1 {
		temp := encryptMode(theEncryptMode[0])
		aux.Encryption = &temp
	}

	instance, hasInstance := opts[preloginInstance]
	if hasInstance {
		aux.Instance = strings.Trim(string(instance), "\x00")
	}

	threadID, hasThreadID := opts[preloginThreadID]
	if hasThreadID && len(threadID) == 4 {
		temp := binary.BigEndian.Uint32(threadID[:])
		aux.ThreadID = &temp
	}

	mars, hasMars := opts[preloginMARS]
	if hasMars && len(mars) == 1 {
		aux.MARS = &mars[0]
	}

	traceID, hasTraceID := opts[preloginTraceID]
	if hasTraceID {
		aux.TraceID = traceID
	}

	fedAuthRequired, hasFedAuthRequired := opts[preloginFedAuthRequired]
	if hasFedAuthRequired {
		aux.FedAuthRequired = &fedAuthRequired[0]
	}

	nonce, hasNonce := opts[preloginNonce]
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

// tdsPacket is a header followed by the body. Length is calculated from the start of the packet, NOT the start of the body.
type tdsPacket struct {
	tdsHeader
	Body []byte
}

// decodeTDSPacket decodes a tdsPacket from the start of buf, returning the packet and any remaining bytes following it.
func decodeTDSPacket(buf []byte) (*tdsPacket, []byte, error) {
	header, err := decodeTDSHeader(buf)
	if err != nil {
		return nil, nil, err
	}
	if len(buf) < int(header.Length) {
		return nil, nil, errBufferTooSmall
	}
	body := buf[8:header.Length]
	return &tdsPacket{
		tdsHeader: *header,
		Body:      body,
	}, buf[header.Length:], nil
}

// tdsPacket.Encode() returns the encoded packet: header + body. Updates the header's length to match the actual body length.
func (packet *tdsPacket) Encode() ([]byte, error) {
	if len(packet.Body)+8 > 0xffff {
		return nil, errTooLarge
	}
	packet.tdsHeader.Length = uint16(len(packet.Body) + 8)
	header := packet.tdsHeader.Encode()
	ret := append(header, packet.Body...)
	return ret, nil
}

// encryptMode.String() returns a string representation of the encryptMode.
func (mode encryptMode) String() string {
	ret, ok := encryptModeToString[mode]
	if !ok {
		return encryptModeToString[encryptModeUnknown]
	}
	return ret
}

// encryptMode.MarshalJSON() ensures that the encryptMode is encoded in the string format.
func (mode encryptMode) MarshalJSON() ([]byte, error) {
	return json.Marshal(mode.String())
}

// getEncryptMode returns the integer encryptMode value for the given string label.
func getEncryptMode(enum string) encryptMode {
	ret, ok := stringToEncryptMode[enum]
	if !ok {
		return encryptModeUnknown
	}
	return ret
}

// Connection wraps the state of a single MSSQL connection.
// NOT thread safe, due e.g. to the state (e.g. messageType) in the tdsWrappedConnection.
type Connection struct {
	// rawConn is the raw network connection. Both tlsConn and tdsConn wrap this.
	rawConn net.Conn

	// tlsConn is the TLS client. During the handshake, it wraps an active tdsWrappedConnection. Afterwards, the inner tdsWrappedConnection is deactivated.
	tlsConn *zgrab2.TLSConnection

	// tdsConn allows sending / receiving TDS packets through the net.Conn interface. Wraps either rawConn or tlsConn.
	// The genesis of this is the fact that MSSQL requires the TLS handshake packets to be wrapped in TDS headers.
	tdsConn *tdsWrappedConnection

	// sequenceNumber is the sequence number used for the last packet (though they are sent to the server mod 256).
	sequenceNumber int

	// preloginOptions contains the values returned by the server in the PRELOGIN call, once it has happened.
	preloginOptions *preloginOptions
}

// Connection.SendTDSPacket() sends a TDS packet with the given type and body.
// NOTE - sets tdsConn.messageType to packetType and leaves it there.
func (connection *Connection) SendTDSPacket(packetType uint8, body []byte) error {
	connection.sequenceNumber++
	connection.tdsConn.messageType = packetType
	_, err := connection.tdsConn.Write(body)
	return err
}

// Connection.ReadPreloginPacket() reads an entire Prelogin packet from tdsConn and then decodes it.
func (connection *Connection) ReadPreloginPacket() (*tdsPacket, *preloginOptions, error) {
	packet, err := connection.tdsConn.ReadPacket()
	if err != nil {
		return nil, nil, err
	}
	if packet.Type != tdsPacketTypeTabularResult {
		return packet, nil, &zgrab2.ScanError{Status: zgrab2.SCAN_APPLICATION_ERROR, Err: err}
	}
	plOptions, rest, err := decodePreloginOptions(packet.Body)
	if err != nil {
		return packet, nil, err
	}
	if len(rest) > 0 {
		return packet, nil, errInvalidData
	}
	return packet, plOptions, nil
}

// Connection.Prelogin() sends the Prelogin packet and reads the response from the server.
// It populates the connection's preloginOptions field with the response, and specifically returns the ENCRYPTION value (which is used to determine whether a TLS handshake needs to be done).
func (connection *Connection) Prelogin(clientEncrypt encryptMode) (encryptMode, error) {
	if clientEncrypt < 0 || clientEncrypt > 0xff {
		return encryptModeUnknown, errInvalidData
	}
	preloginOptions := preloginOptions{
		preloginVersion:    {0, 0, 0, 0, 0, 0},
		preloginEncryption: {byte(clientEncrypt)},
		preloginInstance:   {0},
		preloginThreadID:   {0, 0, 0, 0},
		preloginMARS:       {0},
	}
	preloginBody, err := preloginOptions.Encode()
	if err != nil {
		return encryptModeUnknown, err
	}
	err = connection.SendTDSPacket(tdsPacketTypePrelogin, preloginBody)

	if err != nil {
		return encryptModeUnknown, err
	}
	packet, response, err := connection.ReadPreloginPacket()
	if response != nil {
		connection.preloginOptions = response
	}
	if err != nil {
		if packet != nil {
			// FIXME: debug packet info?
			logrus.Warnf("Got bad packet? type=0x%02x", packet.Type)
		}
		return encryptModeUnknown, err
	}

	serverEncrypt := connection.getEncryptMode()

	if clientEncrypt == encryptModeOn && serverEncrypt == encryptModeNotSupported {
		return serverEncrypt, errNoServerEncryption
	}
	if clientEncrypt == encryptModeNotSupported && serverEncrypt == encryptModeRequired {
		return serverEncrypt, errServerRequiresEncryption
	}
	return serverEncrypt, nil
}

// Connection.Close() closes / resets any resources associated with the connection, and returns the first error (if any) that it encounters.
func (connection *Connection) Close() error {
	connection.sequenceNumber = 0
	connection.tdsConn = nil
	connection.tlsConn = nil
	temp := connection.rawConn
	connection.rawConn = nil
	return temp.Close()
}

// tdsWrappedConnection is an implementation of net.Conn that adapts raw input (e.g. from an external library like tls.Handshake()) by adding / removing TDS headers for writes / reads.
// For example, wrapped.Write("abc") will call wrapped.conn.Write(tdsHeader + "abc"), while wrapped.Read() will read tdsHeader + "def" from net.Conn, then return "def" to the caller.
// For reads, this reads entire TDS packets at a time -- blocking until it can -- and returns partial packets (or data from multiple packets) as reqested.
type tdsWrappedConnection struct {
	// The underlying conn. Traffic going over this connection is wrapped in TDS headers.
	conn net.Conn
	// The connection this wrapper is attached to.
	session *Connection
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
func (connection *tdsWrappedConnection) ReadPacket() (*tdsPacket, error) {
	if !connection.enabled {
		return nil, errInvalidState
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
	return &tdsPacket{
		tdsHeader: *header,
		Body:      buf,
	}, nil
}

// The wrapped Read() call. If not enabled, just passes through to conn.Read(b). Otherwise...
// If it has sufficient data in remainder to satisfy the read, just return that.
// Otherwise, attempt to read a header (FIXME: with a 1s timeout), then block on reading the entire packet and add it to the remainder.
// Then, consume and repeat. If there is an error reading, return the error back to the user with the corresponding bytes read.
func (connection *tdsWrappedConnection) Read(b []byte) (n int, err error) {
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
		n, err = io.ReadFull(connection.conn, connection.remainder)
		if err != nil {
			logrus.Warn("Error reading body", err)
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
// Otherise, wrap b in a tdsHeader with the next sequence number and packet type given by messageType, and send it in a single conn.Write().
func (connection *tdsWrappedConnection) Write(b []byte) (n int, err error) {
	if !connection.enabled {
		return connection.conn.Write(b)
	}
	if len(b)+8 > 0xffff {
		return 0, errTooLarge
	}
	connection.session.sequenceNumber++
	header := tdsHeader{
		Type:           connection.messageType,
		Status:         tdsStatusEOM,
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
func (connection *tdsWrappedConnection) Close() error {
	return connection.conn.Close()
}

// Passthrough to the underlying connection.
func (connection *tdsWrappedConnection) LocalAddr() net.Addr {
	return connection.conn.LocalAddr()
}

// Passthrough to the underlying connection.
func (connection *tdsWrappedConnection) RemoteAddr() net.Addr {
	return connection.conn.RemoteAddr()
}

// Passthrough to the underlying connection.
func (connection *tdsWrappedConnection) SetDeadline(t time.Time) error {
	return connection.conn.SetDeadline(t)
}

// Passthrough to the underlying connection.
func (connection *tdsWrappedConnection) SetReadDeadline(t time.Time) error {
	return connection.conn.SetReadDeadline(t)
}

// Passthrough to the underlying connection.
func (connection *tdsWrappedConnection) SetWriteDeadline(t time.Time) error {
	return connection.conn.SetWriteDeadline(t)
}

// Create a new MSSQL connection using the given raw socket connection to the database.
func NewConnection(conn net.Conn) *Connection {
	ret := &Connection{rawConn: conn}
	ret.tdsConn = &tdsWrappedConnection{conn: conn, session: ret, enabled: true}
	return ret
}

// Not implemented.
// Send the LOGIN packet. Called after Handshake(). If self.getEncryptMode() == encryptModeOff, disables TLS afterwards.
func (connection *Connection) Login() {
	// TODO: send login
	if connection.getEncryptMode() != encryptModeOn {
		// Client was only using encryption for login, so switch back to the rawConn
		connection.tdsConn = &tdsWrappedConnection{conn: connection.rawConn, enabled: true, session: connection}
		// tdsWrappedConnection.Write(rawData) -> net.Conn.Write(header + rawData)
		// net.Conn.Read() -> header + rawData -> tdsWrappedConnection.Read() -> rawData
	}
}

// Connection.getEncryptMode() returns the encryptMode enum returned by the server in the PRELOGIN step.
// If PRELOGIN has not yet been called or if the ENCRYPTION token was not included / was invalid, returns encryptModeUnknown.
func (connection *Connection) getEncryptMode() encryptMode {
	if connection.preloginOptions == nil {
		return encryptModeUnknown
	}
	ret, err := connection.preloginOptions.GetByteOption(preloginEncryption)
	if err != nil {
		return encryptModeUnknown
	}
	return encryptMode(ret)
}

// Connection.Handshake() performs the initial handshake with the MSSQL server.
// First sends the PRELOGIN packet to the server and reads the response.
// Then, if necessary, does a TLS handshake.
// Returns the ENCRYPTION value from the response to PRELOGIN.
func (connection *Connection) Handshake(flags *mssqlFlags) (encryptMode, error) {
	encryptMode := getEncryptMode(flags.EncryptMode)
	mode, err := connection.Prelogin(encryptMode)
	if err != nil {
		return mode, err
	}
	connection.tdsConn.messageType = 0x12
	if mode == encryptModeNotSupported {
		return mode, nil
	}
	tlsClient, err := flags.TLSFlags.GetTLSConnection(connection.tdsConn)
	if err != nil {
		return mode, err
	}
	// do handshake: the raw TLS frames are wrapped in a TDS packet:
	// tls.Conn.Handshake() -> tdsWrappedConnection.Write(clientHello) -> net.Conn.Write(header + clientHello)
	// net.Conn.Read() => header + serverHello -> tdsWrappedConnection.Read() => serverHello -> tls.Conn.Handshake()
	err = tlsClient.Handshake()
	if err != nil {
		return mode, err
	}
	// After the SSL handshake has been established, wrap packets before they are passed into TLS, not after
	// tdsWrappedConnection.Write(rawData) -> tls.Conn.Write(header + rawData) -> net.Conn.Write(protected[header + rawData])
	// net.Conn.Read() => protected[header + rawData] -> tls.Conn.Read() => header + rawData -> TDSWrappedClient.Read() => rawData
	connection.tdsConn.enabled = false
	connection.tdsConn = &tdsWrappedConnection{conn: tlsClient, enabled: true, session: connection}
	connection.tlsConn = tlsClient
	return mode, nil
}

/**
 * @TODO @FIXME: copyright info
 * Very basic MySQL connection library.
 * Usage:
 *	var sql *mysql.Connection := mysql.NewConnection(&mysql.Config{
 *		Host: targetHost,
 *		Port: targetPort,
 *	})
 *	err := sql.Connect()
 *	defer sql.Disconnect()
 * The Connection exports the connection details via the ConnectionLog.
 */
package mysql

import (
	"bufio"

	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/zmap/zcrypto/tls"

	log "github.com/sirupsen/logrus"
)

const (
	// Start state
	STATE_NOT_CONNECTED = "NOT_CONNECTED"

	// After the TCP connection is completed
	STATE_CONNECTED = "CONNECTED"

	// After reading a HandshakePacket with SSL capabilities, before sending the SSLRequest packet
	STATE_SSL_REQUEST = "SSL_REQUEST"

	// After sending an SSLRequest packet, before peforming an SSL handshake
	STATE_SSL_HANDSHAKE = "SSL_HANDSHAKE"

	// After connection has been negotiated (from either CONNECTED or SSL_HANDSHAKE)
	STATE_FINISHED = "STATE_FINISHED"
)

type ConnectionState string

const (
	PACKET_TYPE_OK          = "OK"
	PACKET_TYPE_ERROR       = "ERROR"
	PACKET_TYPE_HANDSHAKE   = "HANDSHAKE"
	PACKET_TYPE_EOF         = "EOF"
	PACKET_TYPE_SSL_REQUEST = "SSL_REQUEST"
)

// Capability flags: See https://dev.mysql.com/doc/dev/mysql-server/8.0.1/group__group__cs__capabilities__flags.html
const (
	CLIENT_LONG_PASSWORD uint32 = (1 << iota)
	CLIENT_FOUND_ROWS
	CLIENT_LONG_FLAG
	CLIENT_CONNECT_WITH_DB
	CLIENT_NO_SCHEMA
	CLIENT_COMPRESS
	CLIENT_ODBC
	CLIENT_LOCAL_FILES
	CLIENT_IGNORE_SPACE
	CLIENT_PROTOCOL_41
	CLIENT_INTERACTIVE
	// CLIENT_SSL = (1<<11)
	CLIENT_SSL
	CLIENT_IGNORE_SIGPIPE
	CLIENT_TRANSACTIONS
	CLIENT_RESERVED
	// CLIENT_SECURE_CONNECTION = (1 << 15)
	CLIENT_SECURE_CONNECTION
	CLIENT_MULTI_STATEMENTS
	CLIENT_MULTI_RESULTS
	CLIENT_PS_MULTI_RESULTS
	// CLIENT_PLUGIN_AUTH = ( 1 << 19 )
	CLIENT_PLUGIN_AUTH
	CLIENT_CONNECT_ATTRS
	CLIENT_PLUGIN_AUTH_LEN_ENC_CLIENT_DATA
	CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS
	CLIENT_SESSION_TRACK
	CLIENT_DEPRECATED_EOF
)

// Config defaults
const (
	DEFAULT_TIMEOUT_SECS        = 3
	DEFAULT_PORT                = 3306
	DEFAULT_CLIENT_CAPABILITIES = CLIENT_SSL
	DEFAULT_RESERVED_DATA_HEX   = "0000000000000000000000000000000000000000000000"
)

type Config struct {
	// @TODO: Does it make sense to make Host/Port connection fields, so that Config can be shared across connections?
	Host string
	Port uint16

	TLSConfig          *tls.Config
	Timeout            time.Duration
	ClientCapabilities uint32
	MaxPacketSize      uint32
	CharSet            byte
	ReservedData       []byte
}

// Fill in a (possibly newly-created) Config instance with the default values
func InitConfig(base *Config) *Config {
	if base == nil {
		base = &Config{}
	}
	if base.TLSConfig == nil {
		// @TODO @FIXME Can this be pulled from a global zgrab config module?
		base.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if base.Port == 0 {
		base.Port = DEFAULT_PORT
	}
	if base.Timeout == 0 {
		base.Timeout = DEFAULT_TIMEOUT_SECS * time.Second
	}
	if base.ClientCapabilities == 0 {
		base.ClientCapabilities = DEFAULT_CLIENT_CAPABILITIES
	}
	if base.ReservedData == nil {
		bin, err := hex.DecodeString(DEFAULT_RESERVED_DATA_HEX)
		if err != nil {
			log.Fatalf("Invalid constant")
		}
		base.ReservedData = bin
	}
	return base
}

// Log of the packets sent/received during the connection.
type ConnectionLog struct {
	Handshake  *ConnectionLogEntry `json:"handshake,omitempty"`
	Error      *ConnectionLogEntry `json:"error,omitempty"`
	SSLRequest *ConnectionLogEntry `json:"ssl_request,omitempty"`
}

// Struct holding state for a single connection
type Connection struct {
	// Configuration for this connection
	Config *Config

	// Enum to track connection status
	State ConnectionState
	// TCP or TLS-wrapped Connection pointer (IsSecure() will tell which)
	Connection *net.Conn
	// The sequence number used with the server to number packets
	SequenceNumber uint8

	// Log of MySQL packets received/sent
	ConnectionLog ConnectionLog
}

// Constructor, filling in defaults where needed
func NewConnection(config *Config) *Connection {
	return &Connection{
		Config:         InitConfig(config),
		State:          STATE_NOT_CONNECTED,
		Connection:     nil,
		SequenceNumber: 0}
}

// Top-level interface for all packets
type PacketInfo interface {
}

// Most packets are read from the server; for packets that need to be sent, they need an encoding function
type WritablePacket interface {
	PacketInfo
	EncodeBody() []byte
}

// Entry in the ConnectionLog. Raw is the base64-encoded body, Parsed is the parsed packet.
// Either may be nil if there was an error reading/decoding the packet.
type ConnectionLogEntry struct {
	Length         uint32     `json:"length"`
	SequenceNumber uint8      `json:"sequence_number"`
	Raw            string     `json:"raw"`
	Parsed         PacketInfo `json:"parsed,omitempty"`
}

// HandshakePacket defined at https://web.archive.org/web/20160316105725/https://dev.mysql.com/doc/internals/en/connection-phase-packets.html
// @TODO @FIXME: This is protocol version 10 handle previous / future versions
// Protocol version 9 was 3.22 and prior (1998?).
type HandshakePacket struct {
	// protocol_version: int<1>
	ProtocolVersion byte `json:"protocol_version"`
	// server_version: string<NUL>
	ServerVersion string `json:"server_version"`
	// connection_id: int<4>
	ConnectionID uint32 `json:"connection_id"` // [4]
	// auth_plugin_data_part_1: string<8>
	AuthPluginData1 string `json:"auth_plugin_data_part_1"`
	// fillter_1: byte<1>
	Filler1 byte `json:"filler_1,omitempty"`
	// capability_flag_1: int<2> -- Stored as lower 16 bits of capability_flags
	// character_set: int<1> (optional?)
	CharacterSet byte `json:"character_set"`

	// Synthetic field: if true, none of the following fields are present.
	ShortHandshake bool `json:"short_handshake"`

	// status_flags: int<> (optional?)
	StatusFlags uint16 `json:"status_flags"`
	// capability_flag_2: int<2> -- Stored as upper 16 bits of capability_flags

	// auth_plugin_data_len: int<1>
	AuthPluginDataLen byte `json:"auth_plugin_data_len"`
	// if (capabilities & CLIENT_SECURE_CONNECTION) {
	// reserved:  string<10> all 0: custom marshaler will omit this if it is all \x00s.
	Reserved []byte `json:"reserved,omitempty"`
	// auth_plugin_data_part_2: string<MAX(13, auth_plugin_data_len - 8)>
	AuthPluginData2 string `json:"auth_plugin_data_part_2,omitempty"`
	// auth_plugin_name: string<NUL>, but old versions lacked null terminator, so returning string<EOF>
	AuthPluginName string `json:"auth_plugin_name,omitempty"`
	// }
	// Synthetic field built from capability_flags_1 || capability_flags_2 << 16
	CapabilityFlags uint32 `json:"capability_flags"`
}

// Omit reserved from encoded packet if it is the default value (ten bytes of 0s)
func (p *HandshakePacket) MarshalJSON() ([]byte, error) {
	reserved := p.Reserved
	if base64.StdEncoding.EncodeToString(reserved) == "AAAAAAAAAAAAAA==" {
		reserved = []byte{}
	}
	// 	Hack around infinite MarshalJSON loop by aliasing parent type (http://choly.ca/post/go-json-marshalling/)
	type Alias HandshakePacket
	return json.Marshal(&struct {
		ReservedOmitted []byte `json:"reserved,omitempty"`
		*Alias
	}{
		ReservedOmitted: reserved,
		Alias:           (*Alias)(p),
	})
}

func (c *Connection) readHandshakePacket(body []byte) (*HandshakePacket, error) {
	var rest []byte
	ret := new(HandshakePacket)
	ret.ProtocolVersion = body[0]
	ret.ServerVersion, rest = readNulString(body[1:])
	ret.ConnectionID = binary.LittleEndian.Uint32(rest[0:4])
	ret.AuthPluginData1 = string(rest[4:12])
	ret.Filler1 = rest[12]
	ret.CapabilityFlags = uint32(binary.LittleEndian.Uint16(rest[13:15]))

	// Unlike the ERRPacket case, the docs explicitly say to go by the body length here
	if len(body) > 8 {
		ret.ShortHandshake = false
		ret.CharacterSet = rest[15]
		ret.StatusFlags = binary.LittleEndian.Uint16(rest[16:18])
		ret.CapabilityFlags |= (uint32(binary.LittleEndian.Uint16(rest[18:20])) << 16)
		ret.AuthPluginDataLen = rest[20]
		if (ret.CapabilityFlags & CLIENT_PLUGIN_AUTH) != 0 {
			ret.Reserved = rest[21:31]
			part2Len := ret.AuthPluginDataLen - 8
			// part-2-len = MAX(13, auth_plugin_data_len - 8)
			if part2Len < 13 {
				part2Len = 13
			}
			ret.AuthPluginData2 = string(rest[31 : 31+part2Len])
			if ret.CapabilityFlags&CLIENT_SECURE_CONNECTION != 0 {
				ret.AuthPluginName = string(rest[31+part2Len:])
			}
		}
	} else {
		ret.ShortHandshake = true
	}
	return ret, nil
}

type OKPacket struct {
	// header: 0xfe or 0x00
	Header byte `json:"header"`
	// affected_rows: int<lenenc>
	AffectedRows uint64 `json:"affected_rows"`
	// last_insert_rowid: int<lenenc>
	LastInsertId uint64 `json:"last_insert_id"`
	// if (CLIENT_PROTOCOL_41 || CLIENT_TRANSACTIONS) {
	// status_flags: int<2>
	StatusFlags uint16 `json:"status_flags"`
	// if CLIENT_PROTOCOL_41 {
	// warning_flags: int<2>
	WarningFlags uint16 `json:"warning_flags"`
	// warnings: int<2>
	Warnings uint16 `json:"warnings"`
	// }
	// }
	// info: string<lenenc> || string<EOF>
	Info string `json:"info"`
	// if CLIENT_SESSION_TRACK && status_flags && SERVER_SESSION_STATE_CHANGED {
	// session_state_changes: string<lenenc>
	SessionStateChanges string `json:"session_state_changes"`
	// }
}

func (c *Connection) readOKPacket(body []byte) (*OKPacket, error) {
	var rest []byte
	var err error
	ret := new(OKPacket)
	ret.Header = body[0]
	ret.AffectedRows, rest, err = readLenInt(body[1:])
	if err != nil {
		return nil, fmt.Errorf("Error reading OKPacket.AffectedRows: %s", err)
	}
	ret.LastInsertId, rest, err = readLenInt(rest)
	if err != nil {
		return nil, fmt.Errorf("Error reading OKPacket.LastInsertId: %s", err)
	}
	flags := uint32(0)
	if handshake := c.GetHandshake(); handshake != nil {
		flags = handshake.CapabilityFlags
	} else {
		log.Warnf("readOKPacket: Received OKPacket before Handshake")
	}
	if flags&(CLIENT_PROTOCOL_41|CLIENT_TRANSACTIONS) != 0 {
		log.Debugf("readOKPacket: CapabilityFlags = 0x%x, so reading status flags", flags)
		ret.StatusFlags = binary.LittleEndian.Uint16(rest[0:2])
		rest = rest[2:]
		if flags&CLIENT_PROTOCOL_41 != 0 {
			log.Debugf("readOKPacket: CapabilityFlags = 0x%x, so reading WarningFlags / Warnings")
			ret.WarningFlags = binary.LittleEndian.Uint16(rest[0:2])
			ret.Warnings = binary.LittleEndian.Uint16(rest[2:4])
			rest = rest[4:]
		}
	}
	ret.Info, rest, err = readLenString(rest[:])
	if err != nil {
		return nil, fmt.Errorf("Error reading OKPacket.Info: %s", err)
	}
	if len(rest) > 0 {
		log.Debugf("readOKPacket: %d bytes left after Info, reading SessionStateChanges", len(rest))
		ret.SessionStateChanges, rest, err = readLenString(rest)
		if err != nil {
			return nil, fmt.Errorf("Error reading OKPacket.SessionStateChanges: %s", err)
		}
	}
	if len(rest) > 0 {
		log.Debugf("readOKPacket: decode failure: body = %s", base64.StdEncoding.EncodeToString(body))
		return nil, fmt.Errorf("Error reading OKPacket: %d bytes left in body (CapabilityFlags = 0x%x)", len(rest), flags)
	}
	return ret, nil
}

// ERRPacket defined at https://web.archive.org/web/20160316124241/https://dev.mysql.com/doc/internals/en/packet-ERRPacket.html
type ERRPacket struct {
	// header: int<1>
	Header byte `json:"header"`
	// error_code: int<2>
	ErrorCode uint16 `json:"error_code"`
	// if CLIENT_PROTOCOL_41 {
	// sql_state_marker string<1>
	SQLStateMarker string `json:"sql_state_marker"`
	// sql_state string<5>
	SQLState string `json:"sql_state"`
	// }
	// error_messagestring<eof>
	ErrorMessage string `json:"error_message"`
}

func (c *Connection) readERRPacket(body []byte) (*ERRPacket, error) {
	ret := new(ERRPacket)
	ret.Header = body[0]
	ret.ErrorCode = binary.LittleEndian.Uint16(body[1:3])
	rest := body[3:]
	flags := uint32(0)
	if handshake := c.GetHandshake(); handshake != nil {
		flags = handshake.CapabilityFlags
	} else {
		// This is a valid case -- e.g. client hostname not allowed
	}
	if flags&CLIENT_PROTOCOL_41 != 0 {
		ret.SQLStateMarker = string(rest[0:1])
		ret.SQLState = string(rest[1:6])
		rest = rest[6:]
	}
	ret.ErrorMessage = string(rest[:])
	return ret, nil
}

// SSLRequest packet type defined at https://web.archive.org/web/20160316105725/https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::SSLRequest
type SSLRequestPacket struct {
	// capability_flags int<4>: Would be weird to not set CLIENT_SSL (0x0800) in your SSLRequest packet
	CapabilityFlags uint32 `json:"capability_flags"`
	// max_packet_size int<4>
	MaxPacketSize uint32 `json:"max_packet_size"`
	// character_set int<1>
	CharacterSet byte `json:"character_set"`
	// reserved string<23>: all \x00
	Reserved []byte `json:"reserved"`
}

func (p *SSLRequestPacket) EncodeBody() []byte {
	var ret [32]byte
	binary.LittleEndian.PutUint32(ret[0:], p.CapabilityFlags)
	binary.LittleEndian.PutUint32(ret[4:], p.MaxPacketSize)
	ret[8] = p.CharacterSet
	// @FIXME seems pedantic to actually require the caller to supply all 23 null bytes, but it's always possible different implementations/versions could respond to nonzero reserved data differently
	copy(ret[9:32], p.Reserved[0:23])
	return ret[:]
}

// Get the next sequence number for this connection, and increment the internal counter.
func (c *Connection) getNextSequenceNumber() byte {
	ret := c.SequenceNumber
	c.SequenceNumber = c.SequenceNumber + 1
	return ret
}

// Given a WritablePacket, prefix it with the length+sequence number header and send it to the server.
func (c *Connection) sendPacket(packet WritablePacket) (*ConnectionLogEntry, error) {
	body := packet.EncodeBody()
	if len(body) > 0xffffff {
		log.Fatalf("Body longer than 24 bits (0x%x bytes)", len(body))
	}
	toSend := make([]byte, len(body)+4)
	binary.LittleEndian.PutUint32(toSend[0:], uint32(len(body))) // The fourth (high) byte will be overwritten by the sequence number.
	seq := c.getNextSequenceNumber()
	toSend[3] = seq
	copy(toSend[4:], body)

	logPacket := ConnectionLogEntry{
		Length:         uint32(len(body)),
		SequenceNumber: seq,
		Raw:            base64.StdEncoding.EncodeToString(body),
		Parsed:         packet,
	}

	// @TODO: Buffered send?
	_, err := (*c.Connection).Write(toSend)
	return &logPacket, err
}

// Decode a packet from the pre-separated body
func (c *Connection) decodePacket(body []byte) (PacketInfo, error) {
	header := body[0]
	switch header {
	case 0xff:
		return c.readERRPacket(body)
	case 0x0a:
		return c.readHandshakePacket(body)
	case 0x00:
		return c.readOKPacket(body)
	case 0xfe:
		return c.readOKPacket(body)
	default:
		return nil, fmt.Errorf("Unrecognized packet type 0x%02x", header)
	}
}

// Read a packet and sequence identifier off of the given connection
func (c *Connection) readPacket() (*ConnectionLogEntry, error) {
	// @TODO @FIXME Find/use conventional buffered packet-reading functions, handle timeouts / connection reset / etc
	conn := *c.Connection
	reader := bufio.NewReader(conn)
	if terr := conn.SetReadDeadline(time.Now().Add(c.Config.Timeout)); terr != nil {
		return nil, fmt.Errorf("Error calling SetReadTimeout(): %s", terr)
	}
	var header [4]byte
	n, err := reader.Read(header[:])
	if err != nil {
		return nil, fmt.Errorf("Error reading packet header (timeout=%s): %s", err, c.Config.Timeout)
	}
	if n != 4 {
		return nil, fmt.Errorf("Wrong number of bytes returned (got %d, expected 4)", n)
	}
	seq := header[3]
	// length is actually Uint24; clear the bogus MSB before decoding
	header[3] = 0
	len := binary.LittleEndian.Uint32(header[:])
	packet := ConnectionLogEntry{
		Length:         len,
		SequenceNumber: seq,
	}

	var body = make([]byte, len, len)
	n, err = reader.Read(body)
	if err != nil {
		return nil, fmt.Errorf("Error reading %d bytes: %s", len, err)
	}
	// Log the raw body, even if the parsing fails
	packet.Raw = base64.StdEncoding.EncodeToString(body)

	if seq != c.SequenceNumber {
		log.Debugf("Sequence number mismatch: got 0x%x, expected 0x%x", seq, c.SequenceNumber+1)
	}
	// Update sequence number
	c.SequenceNumber = seq + 1
	ret, err := c.decodePacket(body)
	if err != nil {
		return nil, fmt.Errorf("Error decoding packet body (length = %d, sequence number = %d): %s", len, seq, err)
	}
	packet.Parsed = ret

	return &packet, nil
}

// Get the server HandshakePacket if present, or otherwise, nil
func (c *Connection) GetHandshake() *HandshakePacket {
	if entry := c.ConnectionLog.Handshake; entry != nil {
		return entry.Parsed.(*HandshakePacket)
	}
	return nil
}

// Perform a TLS handshake using the configured TLSConfig on the current connection
func (c *Connection) StartTLS() error {

	client := tls.Client(*c.Connection, c.Config.TLSConfig)
	err := client.Handshake()
	if err != nil {
		return fmt.Errorf("TLS Handshake error: %s", err)
	}
	*(c.Connection) = client
	return nil
}

// Check if both the input client flags and the server capability flags support TLS
func (c *Connection) SupportsTLS() bool {
	if handshake := c.GetHandshake(); handshake != nil {
		return (handshake.CapabilityFlags & c.Config.ClientCapabilities & CLIENT_SSL) != 0
	}
	// Vacuously false if you are not connected
	return false
}

// Send the SSL_REQUEST packet (the client should begin the TLS handshake immediately after this returns successfully)
func (c *Connection) NegotiateTLS() error {
	c.State = STATE_SSL_REQUEST
	sslRequest := SSLRequestPacket{
		CapabilityFlags: c.Config.ClientCapabilities,
		MaxPacketSize:   c.Config.MaxPacketSize,
		CharacterSet:    c.Config.CharSet,
		Reserved:        c.Config.ReservedData,
	}
	sentPacket, err := c.sendPacket(&sslRequest)
	if err != nil {
		return fmt.Errorf("Error sending SSLRequest packet: %s", err)
	}
	c.ConnectionLog.SSLRequest = sentPacket

	c.State = STATE_SSL_HANDSHAKE
	return nil
}

// Connect to the configured server and perform the initial handshake
func (c *Connection) Connect() error {
	// Allow Scan on pre-connected / user-supplied connections?
	dialer := net.Dialer{Timeout: c.Config.Timeout}
	log.Debugf("Connecting to %s:%d", c.Config.Host, c.Config.Port)
	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", c.Config.Host, c.Config.Port))
	if err != nil {
		log.Debugf("Error connecting: %v", err)
		return fmt.Errorf("Connect error: %s", err)
	}
	c.Connection = &conn
	c.State = STATE_CONNECTED
	c.ConnectionLog = ConnectionLog{
		Handshake:  nil,
		SSLRequest: nil,
		Error:      nil,
	}

	packet, err := c.readPacket()
	if err != nil {
		log.Debugf("Error reading handshake packet: %v", err)
		return fmt.Errorf("Error reading server handshake packet: %s", err)
	}

	switch p := packet.Parsed.(type) {
	case *HandshakePacket:
		c.ConnectionLog.Handshake = packet
	case *ERRPacket:
		c.ConnectionLog.Error = packet
		log.Debugf("Got error packet: 0x%x / %s", p.ErrorCode, p.ErrorMessage)
		return fmt.Errorf("Server returned error after connecting: error_code = 0x%x; error_message = %s", p.ErrorCode, p.ErrorMessage)
	default:
		// Drop unrecgnized packets -- including those with packet.Parsed == nil -- into the "Error" slot
		c.ConnectionLog.Error = packet
		jsonStr, err := json.Marshal(p)
		if err != nil {
			return fmt.Errorf("Server returned unexpected packet type, failed to marshal paclet: %s", err)
		}
		return fmt.Errorf("Server returned unexpected packet type after connecting: %s", jsonStr)
	}
	return nil
}

// Close the connection.
func (c *Connection) Disconnect() error {
	if c.Connection == nil {
		return nil
	}
	c.State = STATE_NOT_CONNECTED
	// Change state even if close fails
	return (*c.Connection).Close()
}

// NUL STRING type from https://web.archive.org/web/20160316113745/https://dev.mysql.com/doc/internals/en/string.html
func readNulString(body []byte) (string, []byte) {
	nul := strings.Index(string(body), "\x00")
	return string(body[:nul]), body[nul+1:]
}

// LEN INT type from https://web.archive.org/web/20160316122921/https://dev.mysql.com/doc/internals/en/integer.html
func readLenInt(body []byte) (uint64, []byte, error) {
	v := body[0]
	if v < 0xfb {
		return uint64(v), body[1:], nil
	}
	switch v {
	case 0xfb:
		// single byte greater than 0xFA
		return 0, body[1:], nil
	case 0xfc:
		// two little-endian bytes
		return uint64(binary.LittleEndian.Uint16(body[1:3])), body[3:], nil
	case 0xfd:
		// three little-endian bytes (ignore fourth) @TODO @FIXME check that there is actually a fourth byte!
		return uint64(binary.LittleEndian.Uint32(body[1:5]) & 0x00ffffff), body[4:], nil
	case 0xfe:
		// eight little-endian bytes
		return binary.LittleEndian.Uint64(body[1:9]), body[9:], nil
	default:
		return 0, nil, fmt.Errorf("Invalid length field for variable-length integer 0x%x", v)
	}
}

// Read LEN STRING type from https://web.archive.org/web/20160316113745/https://dev.mysql.com/doc/internals/en/string.html
func readLenString(body []byte) (string, []byte, error) {
	length, rest, err := readLenInt(body)
	if err != nil {
		return "", nil, fmt.Errorf("Error reading string length: %s", err)
	}
	if uint64(len(rest)) < length {
		return "", nil, fmt.Errorf("String length 0x%x longer than remaining body size 0x%x", length, len(rest))
	}
	return string(rest[:length]), rest[length+1:], nil
}

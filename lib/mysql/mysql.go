// Package mysql is a very basic MySQL connection library.
// Usage:
//
//	  var sql *mysql.Connection := mysql.NewConnection(&mysql.Config{
//	  Host: targetHost,
//	  Port: targetPort,
//	})
//	err := sql.Connect()
//	defer sql.Disconnect()
//
// The Connection exports the connection details via the ConnectionLog.
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

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"io"
	"time"
)

const (
	// STATE_NOT_CONNECTED is the start state.
	STATE_NOT_CONNECTED = "NOT_CONNECTED"

	// STATE_CONNECTED is the state after the TCP connection is completed.
	STATE_CONNECTED = "CONNECTED"

	// STATE_SSL_REQUEST is the state after reading a HandshakePacket with
	// SSL capabilities, before sending the SSLRequest packet.
	STATE_SSL_REQUEST = "SSL_REQUEST"

	// STATE_SSL_HANDSHAKE is the state after sending an SSLRequest
	// packet, before peforming an SSL handshake.
	STATE_SSL_HANDSHAKE = "SSL_HANDSHAKE"

	// STATE_FINISHED is the state after the connection has been
	// negotiated (from either CONNECTED or SSL_HANDSHAKE).
	STATE_FINISHED = "STATE_FINISHED"
)

// ConnectionState tracks the state of the Connection instance.
type ConnectionState string

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
	CLIENT_SSL
	CLIENT_IGNORE_SIGPIPE
	CLIENT_TRANSACTIONS
	CLIENT_RESERVED
	CLIENT_SECURE_CONNECTION
	CLIENT_MULTI_STATEMENTS
	CLIENT_MULTI_RESULTS
	CLIENT_PS_MULTI_RESULTS
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

// Config specifies the client settings for the connection.
type Config struct {
	ClientCapabilities uint32
	MaxPacketSize      uint32
	CharSet            byte
	ReservedData       []byte
}

// GetServerStatusFlags returns a map[string]bool representation of the
// given flags. The keys are the constant names defined in the MySQL
// docs, and the values are true (flags that are not set have no
// corresponding map entry).
func GetServerStatusFlags(flags uint16) map[string]bool {
	consts := []string{
		"SERVER_STATUS_IN_TRANS",
		"SERVER_STATUS_AUTOCOMMIT",
		"SERVER_MORE_RESULTS_EXISTS",
		"SERVER_QUERY_NO_GOOD_INDEX_USED",
		"SERVER_QUERY_NO_INDEX_USED",
		"SERVER_STATUS_CURSOR_EXISTS",
		"SERVER_STATUS_LAST_ROW_SENT",
		"SERVER_STATUS_DB_DROPPED",
		"SERVER_STATUS_NO_BACKSLASH_ESCAPES",
		"SERVER_STATUS_METADATA_CHANGED",
		"SERVER_QUERY_WAS_SLOW",
		"SERVER_PS_OUT_PARAMS",
		"SERVER_STATUS_IN_TRANS_READONLY",
		"SERVER_SESSION_STATE_CHANGED",
	}
	ret, _ := zgrab2.ListFlagsToSet(uint64(flags), consts)
	return ret
}

// GetClientCapabilityFlags returns a map[string]bool representation of
// the given flags. The keys are the constant names defined in the MySQL
// docs, and the values are true (flags that are not set have no
// corresponding map entry).
func GetClientCapabilityFlags(flags uint32) map[string]bool {
	consts := []string{
		"CLIENT_LONG_PASSWORD",
		"CLIENT_FOUND_ROWS",
		"CLIENT_LONG_FLAG",
		"CLIENT_CONNECT_WITH_DB",
		"CLIENT_NO_SCHEMA",
		"CLIENT_COMPRESS",
		"CLIENT_ODBC",
		"CLIENT_LOCAL_FILES",
		"CLIENT_IGNORE_SPACE",
		"CLIENT_PROTOCOL_41",
		"CLIENT_INTERACTIVE",
		"CLIENT_SSL",
		"CLIENT_IGNORE_SIGPIPE",
		"CLIENT_TRANSACTIONS",
		"CLIENT_RESERVED",
		"CLIENT_SECURE_CONNECTION",
		"CLIENT_MULTI_STATEMENTS",
		"CLIENT_MULTI_RESULTS",
		"CLIENT_PS_MULTI_RESULTS",
		"CLIENT_PLUGIN_AUTH",
		"CLIENT_CONNECT_ATTRS",
		"CLIENT_PLUGIN_AUTH_LEN_ENC_CLIENT_DATA",
		"CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS",
		"CLIENT_SESSION_TRACK",
		"CLIENT_DEPRECATED_EOF",
	}
	ret, _ := zgrab2.ListFlagsToSet(uint64(flags), consts)
	return ret
}

// InitConfig fills in a (possibly newly-created) Config instance with
// the default values where values are not present.
func InitConfig(base *Config) *Config {
	if base == nil {
		base = &Config{}
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

// ConnectionLog is a log of packets sent/received during the connection.
type ConnectionLog struct {
	Handshake  *ConnectionLogEntry `json:"handshake,omitempty"`
	Error      *ConnectionLogEntry `json:"error,omitempty"`
	SSLRequest *ConnectionLogEntry `json:"ssl_request,omitempty"`
}

// Connection holds the state of a single connection.
type Connection struct {
	// Config is the client configuration for this connection.
	Config *Config

	// ConnectionState tracks how far along along the client is in
	// negotiating the connection.
	State ConnectionState

	// Connection is the TCP or TLS-wrapped Connection (IsSecure() will
	// tell which)
	Connection net.Conn

	// SequenceNumber is used to number packets to / from the server.
	SequenceNumber uint8

	// ConnectionLog is a log of MySQL packets received/sent.
	ConnectionLog ConnectionLog
}

// NewConnection creates a new connection object with the given config
// (using defaults where none is specified).
func NewConnection(config *Config) *Connection {
	return &Connection{
		Config:         InitConfig(config),
		State:          STATE_NOT_CONNECTED,
		Connection:     nil,
		SequenceNumber: 0,
	}
}

// PacketInfo is the top-level interface for all packets.
type PacketInfo interface {
}

// WritablePacket is a sub-interface for those packets that must be
// sent by the client to the server, and not just read.
type WritablePacket interface {
	PacketInfo
	EncodeBody() []byte
}

// ConnectionLogEntry is an entry in the ConnectionLog.Entry in the ConnectionLog.
type ConnectionLogEntry struct {
	// Length is the actual length of the packet body.
	Length uint32 `zgrab:"debug" json:"length"`

	// SequenceNumber is the sequence number included in the packet.
	SequenceNumber uint8 `zgrab:"debug" json:"sequence_number"`

	// Raw is the raw packet body, base64-encoded. May be nil on a read
	// error.
	Raw string `zgrab:"debug" json:"raw"`

	// Parsed is the parsed packet body. May be nil on a decode error.
	Parsed PacketInfo `json:"parsed,omitempty"`
}

// HandshakePacket is the packet the server sends immediately upon a
// client connecting (unless there is an error, like there are no users
// allowed to connect from the client's host).
// The packet format is defined at https://web.archive.org/web/20160316105725/https://dev.mysql.com/doc/internals/en/connection-phase-packets.html
// This is compatible with at least protocol version 10.
// Protocol version 9 was 3.22 and prior (1998?).
type HandshakePacket struct {
	// ProtocolVersion is the version of the protocol being used.
	ProtocolVersion byte `json:"protocol_version"`

	// ServerVersion is a human-readable server version.
	ServerVersion string `json:"server_version,omitempty"`

	// ConnectionID is the ID used by the server to identify this client.
	ConnectionID uint32 `zgrab:"debug" json:"connection_id,omitempty"`

	// AuthPluginData1 is the first part of the auth-plugin-specific data.
	AuthPluginData1 []byte `zgrab:"debug" json:"auth_plugin_data_part_1,omitempty"`

	// Filler1 is an unused byte, defined to be 0.
	Filler1 byte `zgrab:"debug" json:"filler_1,omitempty"`

	// At this point in the struct, the lower 16 bits of the
	// CapabilityFlags appear.

	// CharacterSet is the low 8 bits of the default server character-set
	CharacterSet byte `zgrab:"debug" json:"character_set,omitempty"`

	// ShortHandshake is a synthetic field: if true, none of the following
	// fields are present.
	ShortHandshake bool `zgrab:"debug" json:"short_handshake"`

	// StatusFlags is a bit field giving the server's status.
	StatusFlags uint16 `json:"status_flags,omitempty"`

	// At this point in the struct, the upper 16 bits of the
	// CapabilityFlags appear.

	// CapabilityFlags the combined capability flags, which tell what
	// the server can do (e.g. whether it supports SSL).
	CapabilityFlags uint32 `json:"capability_flags,omitempty"`

	// AuthPluginDataLen is the length of the full auth-plugin-specific
	// data (so len(AuthPluginData1) + len(AuthPluginData2) =
	// AuthPluginDataLen)
	AuthPluginDataLen byte `zgrab:"debug" json:"auth_plugin_data_len,omitempty"`

	// The following field are only present if the CLIENT_SECURE_CONNECTION
	// capability flag is set:

	// Reserved is defined to be ten bytes of 0x00s.
	Reserved []byte `zgrab:"debug" json:"reserved,omitempty"`

	// AuthPluginData2 is the remainder of the auth-plugin-specific data.
	// Its length is MAX(13, auth_plugin_data_len - 8).
	AuthPluginData2 []byte `zgrab:"debug" json:"auth_plugin_data_part_2,omitempty"`

	// AuthPluginName is the name of the auth plugin. This determines the
	// format / interpretation of AuthPluginData.
	AuthPluginName string `zgrab:"debug" json:"auth_plugin_name,omitempty"`
}

// MarshalJSON omits reserved from encoded packet if it is the default
// value (ten bytes of 0s).
func (p *HandshakePacket) MarshalJSON() ([]byte, error) {
	reserved := p.Reserved
	if base64.StdEncoding.EncodeToString(reserved) == "AAAAAAAAAAAAAA==" {
		reserved = []byte{}
	}
	// 	Hack around infinite MarshalJSON loop by aliasing parent type (http://choly.ca/post/go-json-marshalling/)
	type Alias HandshakePacket
	return json.Marshal(&struct {
		ReservedOmitted []byte          `zgrab:"debug" json:"reserved,omitempty"`
		CapabilityFlags map[string]bool `json:"capability_flags,omitempty"`
		StatusFlags     map[string]bool `json:"status_flags,omitempty"`
		*Alias
	}{
		ReservedOmitted: reserved,
		CapabilityFlags: GetClientCapabilityFlags(p.CapabilityFlags),
		StatusFlags:     GetServerStatusFlags(p.StatusFlags),
		Alias:           (*Alias)(p),
	})
}

func (c *Connection) readHandshakePacket(body []byte) (*HandshakePacket, error) {
	var rest []byte
	ret := new(HandshakePacket)
	ret.ProtocolVersion = body[0]
	ret.ServerVersion, rest = readNulString(body[1:])
	ret.ConnectionID = binary.LittleEndian.Uint32(rest[0:4])
	ret.AuthPluginData1 = rest[4:12]
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
			ret.AuthPluginData2 = rest[31 : 31+part2Len]
			if ret.CapabilityFlags&CLIENT_SECURE_CONNECTION != 0 {
				// If AuthPluginName does include a NUL terminator, strip it.
				ret.AuthPluginName = strings.Trim(string(rest[31+part2Len:]), "\u0000")
			}
		}
	} else {
		ret.ShortHandshake = true
	}
	return ret, nil
}

// OKPacket is sent by the server in response to a successful command.
// See e.g. https://dev.mysql.com/doc/internals/en/packet-OK_Packet.html
type OKPacket struct {
	// Header identifies the packet as an OK_Packet. Either 0x01 or 0xFE.
	Header byte `zgrab:"debug" json:"header"`

	// AffectedRows gives the number of rows affected by the command.
	AffectedRows uint64 `zgrab:"debug" json:"affected_rows"`

	// LastInsertId gives the ID of the last-inserted row.
	LastInsertId uint64 `json:"last_insert_id"`

	// The following fields are only present if the ClientCapabilities
	// returned by the server contain the flag CLIENT_TRANSACTIONS:

	// StatusFlags give the server's status (see e.g. https://dev.mysql.com/doc/internals/en/status-flags.html)
	StatusFlags uint16 `json:"status_flags,omitempty"`

	// Warnings is only present if the ClientCapabilities returned by the
	// server contain the flag CLIENT_PROTOCOL_41.
	// Warnings gives the number of warnings.
	Warnings uint16 `json:"warnings,omitempty"`

	// Info gives human readable status information.
	Info string `json:"info,omitempty"`

	// SessionStateChanges is only present if the server has the
	// CLIENT_SESSION_TRACK ClientCapability and the StatusFlags contain
	// SERVER_SESSION_STATE_CHANGED.
	// SessionStateChanges gives state information on the session.
	SessionStateChanges string `zgrab:"debug" json:"session_state_changes,omitempty"`
}

// MarshalJSON convert the StatusFlags to an set of consts.
func (p *OKPacket) MarshalJSON() ([]byte, error) {
	// 	Hack around infinite MarshalJSON loop by aliasing parent type (http://choly.ca/post/go-json-marshalling/)
	type Alias OKPacket
	return json.Marshal(&struct {
		StatusFlags map[string]bool `json:"status_flags"`
		*Alias
	}{
		StatusFlags: GetServerStatusFlags(p.StatusFlags),
		Alias:       (*Alias)(p),
	})
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
		log.Debugf("readOKPacket: Received OKPacket before Handshake")
	}
	if flags&(CLIENT_PROTOCOL_41|CLIENT_TRANSACTIONS) != 0 {
		log.Debugf("readOKPacket: CapabilityFlags = 0x%x, so reading status flags", flags)
		ret.StatusFlags = binary.LittleEndian.Uint16(rest[0:2])
		rest = rest[2:]
		if flags&CLIENT_PROTOCOL_41 != 0 {
			log.Debugf("readOKPacket: CapabilityFlags = 0x%x, so reading Warnings")
			ret.Warnings = binary.LittleEndian.Uint16(rest[0:2])
			rest = rest[2:]
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

// ERRPacket is returned by the server when there is an error.
// It is defined at https://web.archive.org/web/20160316124241/https://dev.mysql.com/doc/internals/en/packet-ERRPacket.html
type ERRPacket struct {
	// Header identifies the packet as an ERR_Packet; its value is 0xFF.
	Header byte `zgrab:"debug" json:"header"`

	// ErrorCode identifies the error.
	ErrorCode uint16 `json:"error_code"`

	// SQLStateMarker and SQLState are only present if the server has
	// ClientCapability CLIENT_PROTOCOL_41:

	// SQLStateMarker is a numeric marker of the SQL state.
	SQLStateMarker string `zgrab:"debug" json:"sql_state_marker,omitempty"`

	// SQLStateString is a five-character string representation of the SQL state.
	SQLState string `zgrab:"debug" json:"sql_state,omitempty"`

	// ErrorMessage is a human-readable error message.
	ErrorMessage string `json:"error_message,omitempty"`
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

// Error implements the error interface. Return the code and message.
func (e *ERRPacket) Error() string {
	return fmt.Sprintf("MySQL Error: code = %s (%d / 0x%04x); message=%s", e.GetErrorID(), e.ErrorCode, e.ErrorCode, e.ErrorMessage)
}

// GetErrorID returns the error ID associated with this packet's error code.
func (e *ERRPacket) GetErrorID() string {
	ret, ok := ErrorCodes[e.ErrorCode]
	if !ok {
		return "UNKNOWN"
	}
	return ret
}

// Get the ScanError for this packet (wrap the error + application error status)
func (e *ERRPacket) GetScanError() *zgrab2.ScanError {
	return &zgrab2.ScanError{
		Status: zgrab2.SCAN_APPLICATION_ERROR,
		Err:    e,
	}
}

// SSLRequestPacket is the packet sent by the client to inform the
// server that a TLS handshake follows.
// It is defined at type defined at https://web.archive.org/web/20160316105725/https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::SSLRequest
type SSLRequestPacket struct {
	// CapabilityFlags is a bit field of flags that the client supports.
	// CLIENT_SSL (0x0800) must always be set.
	CapabilityFlags uint32 `json:"capability_flags"`

	// MaxPacketSize specifies the maximum size packets the client expects
	// to receive.
	MaxPacketSize uint32 `zgrab:"debug" json:"max_packet_size"`

	// CharacterSet specifies the client's expected character set.
	CharacterSet byte `zgrab:"debug" json:"character_set"`

	// Reserved is a 23-byte string of null characters.
	Reserved []byte `zgrab:"debug" json:"reserved,omitempty"`
}

// MarshalJSON omits reserved from encoded packet if it is the default
// value (ten bytes of 0s).
func (p *SSLRequestPacket) MarshalJSON() ([]byte, error) {
	reserved := p.Reserved
	if base64.StdEncoding.EncodeToString(reserved) == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		reserved = []byte{}
	}
	// 	Hack around infinite MarshalJSON loop by aliasing parent type (http://choly.ca/post/go-json-marshalling/)
	type Alias SSLRequestPacket
	return json.Marshal(&struct {
		ReservedOmitted []byte          `zgrab:"debug" json:"reserved,omitempty"`
		CapabilityFlags map[string]bool `json:"capability_flags"`
		*Alias
	}{
		ReservedOmitted: reserved,
		CapabilityFlags: GetClientCapabilityFlags(p.CapabilityFlags),
		Alias:           (*Alias)(p),
	})
}

// EncodeBody encodes the SSLRequestPacket for transport to the server.
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
	_, err := c.Connection.Write(toSend)
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

// with n and body as if `n, _ := io.Read(body)`, trunc(body, n) returns a hex representation of
// body[:n] that is at most 96 characters long (longer strings are returned as
// "<first 16 bytes>...[n - 32] bytes remaining<last 16 bytes>").
func trunc(body []byte, n int) (result string) {
	defer func() {
		if len(result) > 96 {
			// Failsafe -- never return more than 96 chars.
			result = result[:96]
		}
	}()
	if body == nil {
		return "<nil>"
	}
	if n > len(body) {
		n = len(body)
	}
	if n < 1 {
		return "<empty>"
	}
	if n < 48 {
		return fmt.Sprintf("%x", body[:n])
	}
	// 16 bytes = 32 bytes hex * 2 + ellipses = 3 * 2 + len("[%d bytes]") = 8 + log10(len - 32)
	// max len = 24 bits ~= 16 million = 8 digits
	// = 64 + 6 + 8 + 8 <= 96
	return fmt.Sprintf("%x...[%d bytes]...%x", body[:16], n-32, body[n-16:])
}

// Read a packet and sequence identifier off of the given connection
func (c *Connection) readPacket() (*ConnectionLogEntry, error) {
	reader := bufio.NewReader(c.Connection)
	var header [4]byte
	n, err := io.ReadFull(reader, header[:])
	if err != nil {
		return nil, fmt.Errorf("error reading packet header: %s", err)
	}
	if n != 4 {
		// Note -- because of ReadFull, this should be unreachable
		return nil, fmt.Errorf("wrong number of bytes returned (got %d, expected 4)", n)
	}
	seq := header[3]
	// packetSize is actually uint24; clear the bogus MSB before decoding
	header[3] = 0
	packetSize := binary.LittleEndian.Uint32(header[:])
	// While packets can be up to 24 bits (16MB), we cut them off at 19 bits (512kb) -- which should
	// be more than enough for any legitimate handshake packet.
	if packetSize > 0x00080000 {
		var temp [32]byte
		// try to read up to 32 bytes, or whatever we can in 5ms, to give context for the error.
		c.Connection.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
		n, _ := reader.Read(temp[:])
		err := fmt.Errorf("packet too large (0x%08x bytes): header=%x, next %d bytes=%x", packetSize, header, n, temp[:n])
		log.Debugf("Received suspiciously large packet: %s", err.Error())
		status := zgrab2.SCAN_UNKNOWN_ERROR
		if n > 1 && temp[0] == 0xff {
			// it looks like an ERRPacket: return SCAN_APPLICATION_ERROR
			status = zgrab2.SCAN_APPLICATION_ERROR
		}
		return nil, zgrab2.NewScanError(status, err)
	}
	packet := ConnectionLogEntry{
		Length:         packetSize,
		SequenceNumber: seq,
	}

	var body = make([]byte, packetSize, packetSize)
	n, err = io.ReadFull(reader, body)
	if err != nil {
		return nil, fmt.Errorf("error reading %d bytes (sequence number = %d, partial body=%s): %s", packetSize, c.SequenceNumber, trunc(body, n), err)
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
		return nil, fmt.Errorf("error decoding packet body (length = %d, sequence number = %d, body=%s): %s", packetSize, seq, trunc(body, n), err)
	}
	packet.Parsed = ret

	return &packet, nil
}

// GetHandshake attempts to get the Handshake packet from the
// ConnectionLog; if none is present, returns nil.
func (c *Connection) GetHandshake() *HandshakePacket {
	if entry := c.ConnectionLog.Handshake; entry != nil {
		return entry.Parsed.(*HandshakePacket)
	}
	return nil
}

// SupportsTLS checks if both the input client flags and the server
// capability flags support TLS.
func (c *Connection) SupportsTLS() bool {
	if handshake := c.GetHandshake(); handshake != nil {
		return (handshake.CapabilityFlags & c.Config.ClientCapabilities & CLIENT_SSL) != 0
	}
	// Vacuously false if you are not connected
	return false
}

// NegotiateTLS sends the SSL_REQUEST packet (the client should begin
// the TLS handshake immediately after this returns successfully).
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
func (c *Connection) Connect(conn net.Conn) error {
	c.Connection = conn
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
		log.Debugf("Got error packet: %s", p.Error())
		return p.GetScanError()
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

// Disconnect from the server and close any underlying connections.
func (c *Connection) Disconnect() error {
	if c.Connection == nil {
		return nil
	}
	c.State = STATE_NOT_CONNECTED
	// Change state even if close fails
	return c.Connection.Close()
}

// NUL STRING type from https://web.archive.org/web/20160316113745/https://dev.mysql.com/doc/internals/en/string.html
func readNulString(body []byte) (string, []byte) {
	nul := strings.Index(string(body), "\x00")
	return string(body[:nul]), body[nul+1:]
}

// LEN INT type from https://web.archive.org/web/20160316122921/https://dev.mysql.com/doc/internals/en/integer.html
func readLenInt(body []byte) (uint64, []byte, error) {
	bodyLen := len(body)
	if bodyLen == 0 {
		return 0, nil, fmt.Errorf("invalid data: empty LEN INT")
	}
	v := body[0]
	if v < 0xfb {
		return uint64(v), body[1:], nil
	}
	size := int(v - 0xfa)
	if bodyLen-1 < size {
		return 0, nil, fmt.Errorf("invalid data: first byte=0x%02x, required size=%d, got %d", v, size, bodyLen-1)
	}
	switch v {
	case 0xfb:
		// 0xfb can represent the "null result", but since we are not doing queries, treat it as 0
		return 0, body[1:], nil
	case 0xfc:
		// two little-endian bytes
		return uint64(binary.LittleEndian.Uint16(body[1:3])), body[3:], nil
	case 0xfd:
		// three little-endian bytes (ignore fourth)
		return uint64(binary.LittleEndian.Uint32(body[1:5]) & 0x00ffffff), body[4:], nil
	case 0xfe:
		if bodyLen < 9 {
			return 0, nil, fmt.Errorf("invalid data: first byte=0xfe, required size=8, got %d", bodyLen-1)
		}
		// eight little-endian bytes
		return binary.LittleEndian.Uint64(body[1:9]), body[9:], nil
	default:
		return 0, nil, fmt.Errorf("invalid data: first byte=0x%02x is not valid for LEN INT", v)
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

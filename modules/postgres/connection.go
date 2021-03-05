package postgres

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

// Don't allow unbounded reads
const maxPacketSize = 512 * 1024

const maxOutputSize = 1024

// Don't read an unlimited number of tag/value pairs from the server
const maxReadAllPackets = 64

const uint32Len = 4

// Connection wraps the state of a given connection to a server.
type Connection struct {
	// Target is the requested scan target.
	Target *zgrab2.ScanTarget

	// Connection is the underlying TCP (or TLS) stream.
	Connection net.Conn

	// Config contains the flags from the command line.
	Config *Flags

	// IsSSL is true if Connection is a TLS connection.
	IsSSL bool
}

// ServerPacket is a direct representation of the response packet
// returned by the server.
// See e.g. https://www.postgresql.org/docs/9.6/static/protocol-message-formats.html
// The first byte is a message type, an alphanumeric character.
// The following four bytes are the length of the message body.
// The following <length> bytes are the message itself.
// In certain special cases, the Length can be 0; for instance, a
// response to an SSLRequest is only a S/N Type with no length / body,
// while pre-startup errors can be a E Type followed by a \n\0-
// terminated string.
type ServerPacket struct {
	Type   byte
	Length uint32
	Body   []byte
}

// ToString is used in logging, to get a human-readable representation
// of the packet.
func (p *ServerPacket) ToString() string {
	// TODO: Don't hex-encode human-readable bodies?
	return fmt.Sprintf("{ ServerPacket(%p): { Type: '%c', Length: %d, Body: [[%d bytes]] } }", &p, p.Type, p.Length, len(p.Body))
}

// OutputValue is the value that is stored for unexpected / unrecognized data.
func (p *ServerPacket) OutputValue() string {
	l := len(p.Body)
	if len(p.Body) > maxOutputSize {
		l = maxOutputSize
	}
	body := hex.EncodeToString(p.Body[:l])
	if p.Length - 4 > uint32(l) {
		body = body + "..."
	}
	return fmt.Sprintf("%c: 0x%08x: %s", p.Type, p.Length, body)
}

// ToError gets a PostgresError version of OutputValue.
func (p *ServerPacket) ToError() *PostgresError {
	return &PostgresError{
		"severity": "unexpected",
		"code": "unexpected error format",
		"detail": p.OutputValue(),
	}
}


// Send a client packet: a big-endian uint32 length followed by a body.
func (c *Connection) Send(body []byte) error {
	toSend := make([]byte, len(body)+4)
	copy(toSend[4:], body)
	// The length contains the length of the length, hence the +4.
	binary.BigEndian.PutUint32(toSend[0:], uint32(len(body)+4))

	// @TODO: Buffered send?
	_, err := c.Connection.Write(toSend)
	return err
}

// SendU32 sends an uint32 packet to the server.
func (c *Connection) SendU32(val uint32) error {
	toSend := make([]byte, 8)
	binary.BigEndian.PutUint32(toSend[0:], uint32(8))
	binary.BigEndian.PutUint32(toSend[4:], val)
	// @TODO: Buffered send?
	_, err := c.Connection.Write(toSend)
	return err
}

// Close out the underlying TCP connection to the server.
func (c *Connection) Close() error {
	return c.Connection.Close()
}

// tryReadPacket tries to read a length + body from the connection.
func (c *Connection) tryReadPacket(header byte) (*ServerPacket, *zgrab2.ScanError) {
	var length [4]byte
	_, err := io.ReadFull(c.Connection, length[:])
	if err != nil && err != io.EOF {
		return nil, zgrab2.DetectScanError(err)
	}
	bodyLen := binary.BigEndian.Uint32(length[:])
	if length[0] > 0x00 {
		// For scanning purposes, there is no reason we want to read more than 2^24 bytes
		// But in practice, it probably means we have a null-terminated error string
		var buf [1024]byte
		n, err := c.Connection.Read(buf[:])
		if err != nil && err != io.EOF {
			return nil, zgrab2.DetectScanError(err)
		}
		if n < 2 {
			return nil, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("Server returned too little data (%d bytes: %s)", n, hex.EncodeToString(buf[:n])))
		}
		if string(buf[n-2:n]) == "\x0a\x00" {
			return &ServerPacket{
				Type: header,
				Length: 0,
				Body: append(length[:], buf[:n]...),
			}, nil
		}
		return nil, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("Server returned too much data: length = 0x%x; first %d bytes = %s", bodyLen, n, hex.EncodeToString(buf[:n])))
	}
	sizeToRead := bodyLen
	if sizeToRead > maxPacketSize {
		log.Debugf("postgres server %s reported packet size of %d bytes; only reading %d bytes.", c.Target.String(), bodyLen, maxPacketSize)
		sizeToRead = maxPacketSize
	}
	if sizeToRead < uint32Len {
		sizeToRead = uint32Len
	}
	body := make([]byte, sizeToRead - uint32Len) // Length includes the length of the Length uint32
	_, err = io.ReadFull(c.Connection, body)
	if err != nil && err != io.EOF {
		return nil, zgrab2.DetectScanError(err)
	}
	if sizeToRead < bodyLen && len(body) + 4 >= maxPacketSize {
		// Warn if we actually truncate (as opposed getting a huge length but only a few bytes are actually available)
		log.Warnf("Truncated postgres packet from %s: advertised size = %d bytes, read size = %d bytes", c.Target.String(), bodyLen, len(body))
	}

	return &ServerPacket{
		Type: header,
		Length: bodyLen,
		Body: body,
	}, nil
}

// RequestSSL sends an SSLRequest packet to the server, and returns true
// if and only if the server reports that it is SSL-capable. Otherwise
// it returns false and possibly an error.
func (c *Connection) RequestSSL() (bool, *zgrab2.ScanError) {
	// NOTE: The SSLRequest request type was introduced in version 7.2, released in 2002 (though the oldest supported version is 9.3, released 2013-09-09)
	if err := c.SendU32(postgresSSLRequest); err != nil {
		return false, zgrab2.DetectScanError(err)
	}
	var header [1]byte
	_, err := io.ReadFull(c.Connection, header[0:1])
	if err != nil {
		return false, zgrab2.DetectScanError(err)
	}
	if header[0] < '0' || header[0] > 'z' {
		// Back-end messages always start with the alphanumeric Byte1 value
		// We could further constrain this to currently-valid message types, but then we may incorrectly reject future versions
		return false, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("Response message type 0x%02x was not an alphanumeric character", header[0]))
	}
	switch header[0] {
	case 'N':
		return false, nil
	case 'S':
		return true, nil
	}
	// It was neither a single 'N' / 'S', so it's a failure -- at this point it's just a question of determining if it's an application error (valid packet) or a protocol error
	packet, scanError := c.tryReadPacket(header[0])
	if scanError != nil {
		return false, scanError
	}
	switch packet.Type {
	case 'E':
		return false, zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, fmt.Errorf("Application rejected SSLRequest packet -- response = %s", packet.ToString()))
	default:
		// Returning PROTOCOL_ERROR here since any garbage data that starts with a small-ish u32 could be a valid packet, and no known server versions return anything beyond S/N/E.
		return false, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("Unexpected response type '%c' from server (full response = %s)", packet.Type, packet.ToString()))

	}
}

// ReadPacket reads a ServerPacket from the server.
func (c *Connection) ReadPacket() (*ServerPacket, *zgrab2.ScanError) {
	var header [1]byte
	_, err := io.ReadFull(c.Connection, header[0:1])
	if err != nil {
		return nil, zgrab2.DetectScanError(err)
	}
	if header[0] < '0' || header[0] > 'z' {
		// Back-end messages always start with the alphanumeric Byte1 value
		// We could further constrain this to currently-valid message types, but then we may incorrectly reject future versions
		return nil, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("Response message type 0x%02x was not an alphanumeric character", header[0]))
	}
	return c.tryReadPacket(header[0])
}

// GetTLSLog gets the connection's TLSLog, or nil if the connection has
// not yet been set up as TLS.
func (c *Connection) GetTLSLog() *zgrab2.TLSLog {
	if !c.IsSSL {
		return nil
	}
	return c.Connection.(*zgrab2.TLSConnection).GetLog()
}

// encodeMap encodes a map into a byte array of the form
// "key0\0value\0key1\0value1\0...keyN\0valueN\0\0"
func encodeMap(dict map[string]string) []byte {
	var strs []string
	for k, v := range dict {
		strs = append(strs, k)
		strs = append(strs, v)
	}
	return append([]byte(strings.Join(strs, "\x00")), 0x00, 0x00)
}

// SendStartupMessage creates and sends a StartupMessage.
// The format is uint16 Major + uint16 Minor + (key/value pairs).
func (c *Connection) SendStartupMessage(version string, kvps map[string]string) error {
	dict := encodeMap(kvps)
	ret := make([]byte, len(dict)+4)
	parts := strings.Split(version, ".")
	if len(parts) == 1 {
		parts = []string{parts[0], "0"}
	}
	major, err := strconv.ParseUint(parts[0], 0, 16)
	if err != nil {
		log.Fatalf("Error parsing major version %s as a uint16: %v", parts[0], err)
	}
	minor, err := strconv.ParseUint(parts[1], 0, 16)
	if err != nil {
		log.Fatalf("Error parsing minor version %s as a uint16: %v", parts[1], err)
	}
	binary.BigEndian.PutUint16(ret[0:2], uint16(major))
	binary.BigEndian.PutUint16(ret[2:4], uint16(minor))
	copy(ret[4:], dict)

	return c.Send(ret)
}

// ReadAll reads packets from the given connection until it hits a
// timeout, EOF, or a 'Z' packet.
func (c *Connection) ReadAll() ([]*ServerPacket, *zgrab2.ScanError) {
	var ret []*ServerPacket
	for {
		response, readError := c.ReadPacket()
		if readError != nil {
			if readError.Status == zgrab2.SCAN_IO_TIMEOUT || readError.Err == io.EOF {
				return ret, nil
			}
			return ret, readError
		}
		ret = append(ret, response)
		if response.Type == 'Z' {
			return ret, nil
		}
		if len(ret) > maxReadAllPackets {
			log.Warnf("Server %s returned more than %d packets -- truncating.", c.Target.String(), maxReadAllPackets)
			return ret, nil
		}
	}
}

// connectionManager is a utility for getting connections and ensuring
// that they all get closed.
// TODO: Is there something like this in the standard libraries?
type connectionManager struct {
	connections map[io.Closer]bool
}

// addConnection adds a managed connection.
func (m *connectionManager) addConnection(c io.Closer) {
	m.connections[c] = true
}

func (m *connectionManager) closeConnection(c io.Closer) {
	if m.connections[c] {
		m.connections[c] = false
		err := c.Close()
		if err != nil {
			log.Debugf("Got error closing connection: %v", err)
		}
	}
}

// cleanUp closes all managed connections.
func (m *connectionManager) cleanUp() {
	// first in, last out: empty out the map
	defer func() {
		for conn, _ := range m.connections {
			delete(m.connections, conn)
		}
	}()
	for connection, _ := range m.connections {
		// Close them all even if there is a panic with one
		defer func(c io.Closer) {
			m.closeConnection(c)
		}(connection)
	}
}

// Get a new connectionmanager instance.
func newConnectionManager() *connectionManager {
	return &connectionManager{
		connections: make(map[io.Closer]bool),
	}
}

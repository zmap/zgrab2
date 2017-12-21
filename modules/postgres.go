package modules

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// PostgresResults is the information returned to the caller.
type PostgresResults struct {
	TLSLog            *zgrab2.TLSLog `json:"tls,omitempty"`
	SupportedVersions string         `json:"supported_versions,omitempty"`
	StartupResponse   string         `json:"startup_response,omitempty"`
	IsSSL             bool           `json:"is_ssl"`
}

// PostgresFlags sets the module-specific flags that can be passed in from the command line
type PostgresFlags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	SkipSSL         bool   `long:"skip-ssl" description:"If set, do not attempt to negotiate an SSL connection"`
	Verbose         bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
	ProtocolVersion string `long:"protocol_version" description:"The protocol to use in the StartupPacket" default:"3.0"`
}

// PostgresScanner is the zgrab2 scanner type for the postgres protocol
type PostgresScanner struct {
	Config *PostgresFlags
}

// PostgresModule is the zgrab2 module for the postgres protocol
type PostgresModule struct {
}

// Connection wraps the state of a given connection to a server
type Connection struct {
	Connection net.Conn
	Config     *PostgresFlags
	IsSSL      bool
}

// ServerPacket is a direct representation of the response packet returned by the server (See e.g. https://www.postgresql.org/docs/9.6/static/protocol-message-formats.html)
// The first byte is a message type, an alphanumeric character.
// The following four bytes are the length of the message body.
// The following <length> bytes are the message itself.
// In certain special cases, the Length can be 0; for instance, a response to an SSLRequest is only a S/N Type with no length / body, while pre-startup errors can be a E Type followed by a \n\0-terminated string.
type ServerPacket struct {
	Type   byte
	Length uint32
	Body   []byte
}

// ServerPacket.ToString() is used in logging, to get a human-readable representation of the packet.
func (p *ServerPacket) ToString() string {
	// TODO: Don't hex-encode human-readable bodies?
	return fmt.Sprintf("{ ServerPacket(%p): { Type: '%c', Length: %d, Body: hex(%s) } }", &p, p.Type, p.Length, hex.EncodeToString(p.Body))
}

// Connection.Send() sends a client packet: a big-endian uint32 length followed by the body.
func (c *Connection) Send(body []byte) error {
	toSend := make([]byte, len(body)+4)
	copy(toSend[4:], body)
	// The length contains the length of the length, hence the +4.
	binary.BigEndian.PutUint32(toSend[0:], uint32(len(body)+4))

	// @TODO: Buffered send?
	_, err := c.Connection.Write(toSend)
	return err
}

// Connection.SendU32() sends an uint32 packet to the server.
func (c *Connection) SendU32(val uint32) error {
	toSend := make([]byte, 8)
	binary.BigEndian.PutUint32(toSend[0:], uint32(8))
	binary.BigEndian.PutUint32(toSend[4:], val)
	// @TODO: Buffered send?
	_, err := c.Connection.Write(toSend)
	return err
}

// Connection.Close() closes out the underlying TCP connection to the server.
func (c *Connection) Close() error {
	return c.Connection.Close()
}

// Connection.Read() reads a ServerPacket from the server.
func (c *Connection) Read() (*ServerPacket, *zgrab2.ScanError) {
	ret := ServerPacket{}
	if err := c.Connection.SetReadDeadline(time.Now().Add(time.Duration(c.Config.Timeout) * time.Second)); err != nil {
		// Error *setting* the timeout?
		return nil, zgrab2.DetectScanError(err)
	}
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
	ret.Type = header[0]
	switch ret.Type {
	case 'N':
		return &ret, nil
	case 'S':
		return &ret, nil
	}
	var length [4]byte
	_, err = io.ReadFull(c.Connection, length[:])
	if err != nil && err != io.EOF {
		return nil, zgrab2.DetectScanError(err)
	}
	ret.Length = binary.BigEndian.Uint32(length[:])
	if length[0] > 0x00 {
		// For scanning purposes, there is no reason we want to read more than 2^24 bytes
		// But in practice, it probably means we have a null-terminated error string
		var buf [1024]byte
		n, err := c.Connection.Read(buf[:])
		if err != nil && err != io.EOF {
			return nil, zgrab2.DetectScanError(err)
		}
		ret.Body = buf[:n]
		if string(buf[n-2:n]) == "\x0a\x00" {
			ret.Length = 0
			ret.Body = append(length[:], ret.Body...)
			return &ret, zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, fmt.Errorf("Server error: %s", string(ret.Body[0:len(ret.Body)-2])))
		} else {
			return &ret, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("Server returned too much data: length = 0x%x; first %d bytes = %s", ret.Length, n, hex.EncodeToString(buf[:n])))
		}
	}
	ret.Body = make([]byte, ret.Length-4) // Length includes the length of the Length uint32
	_, err = io.ReadFull(c.Connection, ret.Body)
	if err != nil && err != io.EOF {
		return &ret, zgrab2.DetectScanError(err)
	}
	return &ret, nil
}

// DecodeMap() decodes a map encoded as a aequence of "key1\0value1\0key2\0value2\0...keyN\0valueN\0\0"
func DecodeMap(buf []byte) map[string]string {
	ret := make(map[string]string)
	parts := strings.Split(string(buf), "\x00")
	for i := 0; i < len(parts)-1; i += 2 {
		k := parts[i]
		v := parts[i+1]
		ret[k] = v
	}
	return ret
}

// EncodeMap() encodes a map into a byte array of the form "key0\0value\0key1\0value1\0...keyN\0valueN\0\0"
func EncodeMap(dict map[string]string) []byte {
	var strs []string
	for k, v := range dict {
		strs = append(strs, k)
		strs = append(strs, v)
	}
	return append([]byte(strings.Join(strs, "\x00")), 0x00, 0x00)
}

// connectionManager is a utility for getting connections and ensuring that they all get closed
// TODO: Is there something like this in the standard libraries??
type connectionManager struct {
	connections []io.Closer
}

// Add a connection to be cleaned up
func (m *connectionManager) addConnection(c io.Closer) {
	m.connections = append(m.connections, c)
}

// Close all managed connections
func (m *connectionManager) cleanUp() {
	for _, v := range m.connections {
		// Close them all even if there is a panic with one
		defer func(c io.Closer) {
			err := c.Close()
			if err != nil {
				log.Debugf("Got error closing connection: %v", err)
			}
		}(v)
	}
}

// Get a new connectionmanager instance
func newConnectionManager() *connectionManager {
	return &connectionManager{}
}

func (m *PostgresModule) NewFlags() interface{} {
	return new(PostgresFlags)
}

func (m *PostgresModule) NewScanner() zgrab2.Scanner {
	return new(PostgresScanner)
}

func (f *PostgresFlags) Validate(args []string) error {
	return nil
}

func (f *PostgresFlags) Help() string {
	return ""
}

func (s *PostgresScanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*PostgresFlags)
	s.Config = f
	return nil
}

func (s *PostgresScanner) InitPerSender(senderID int) error {
	return nil
}

func (s *PostgresScanner) GetName() string {
	return s.Config.Name
}

func (s *PostgresScanner) GetPort() uint {
	return s.Config.Port
}

// PostgresScanner.DoSSL() attempts to upgrade the connection to SSL, returning an error on failure.
func (s *PostgresScanner) DoSSL(sql *Connection) error {
	var conn *zgrab2.TLSConnection
	var err error
	if conn, err = s.Config.TLSFlags.GetTLSConnection(sql.Connection); err != nil {
		return err
	}
	if err = conn.Handshake(); err != nil {
		return err
	}
	// Replace sql.Connection to allow hypothetical future calls to go over the secure connection
	sql.Connection = conn
	return nil
}

// EncodeStartupMessage creates a StartupMessage: uint16 Major + uint16 Minor + (key/value pairs)
func EncodeStartupMessage(version string, kvps map[string]string) []byte {
	dict := EncodeMap(kvps)
	ret := make([]byte, len(dict)+4)
	parts := strings.Split(version, ".")
	if len(parts) == 1 {
		parts = []string{parts[0], "0"}
	}
	major, err := strconv.ParseUint(parts[0], 0, 16)
	if err != nil {
		log.Fatalf("Error parsing major version %s as a uint16:", parts[0], err)
	}
	minor, err := strconv.ParseUint(parts[1], 0, 16)
	if err != nil {
		log.Fatalf("Error parsing minor version as a uint16:", parts[1], err)
	}
	binary.BigEndian.PutUint16(ret[0:2], uint16(major))
	binary.BigEndian.PutUint16(ret[2:4], uint16(minor))
	copy(ret[4:], dict)

	return ret
}

// PostgresScanner.newConnection() opens up a new connection to the ScanTarget, and if necessary, attempts to update the connection to SSL
func (s *PostgresScanner) newConnection(t *zgrab2.ScanTarget, mgr *connectionManager, nossl bool) (*Connection, *zgrab2.ScanError) {
	var conn net.Conn
	var err error
	if conn, err = t.Open(&s.Config.BaseFlags); err != nil {
		return nil, zgrab2.DetectScanError(err)
	}
	mgr.addConnection(conn)
	sql := Connection{Connection: conn, Config: s.Config}
	sql.IsSSL = false
	if !nossl && !s.Config.SkipSSL {
		if err = sql.SendU32(80877103); err != nil {
			return nil, zgrab2.DetectScanError(err)
		}
		sslResponse, readError := sql.Read()
		if readError != nil {
			return nil, readError
		}
		switch sslResponse.Type {
		case 'N':
			// No SSL
		case 'S':
			if err = s.DoSSL(&sql); err != nil {
				// This is arguably between an application error and a protocol error...
				return nil, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, err)
			}
			sql.IsSSL = true
		default:
			return nil, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("Unexpected response type '%c' from server", sslResponse.Type))
		}
	}
	return &sql, nil
}

// PostgresScanner.Scan() does the actual scanning. It opens two connections:
// With the first it sends a bogus protocol version in hopes of getting a list of supported protcols back.
// With the second, it sends a standard StartupMessage, but without the required "user" field.
func (s *PostgresScanner) Scan(t zgrab2.ScanTarget) (status zgrab2.ScanStatus, result interface{}, thrown error) {
	var err error
	var results PostgresResults

	mgr := newConnectionManager()
	defer func() {
		mgr.cleanUp()
	}()
	v0Sql, connectErr := s.newConnection(&t, mgr, false)
	if connectErr != nil {
		return connectErr.Status, nil, connectErr.Err
	}
	if v0Sql.IsSSL {
		results.IsSSL = true
	} else {
		results.IsSSL = false
	}
	defer func() {
		// Lazy fetch of TLSConnection.GetLog() -- grab it too early and some of its content may be missing
		_results, ok := result.(*PostgresResults)
		if ok {
			if _results.IsSSL {
				_results.TLSLog = v0Sql.Connection.(*zgrab2.TLSConnection).GetLog()
			}
		}
	}() // Do SSL the first round, so that if we bail, we still have the TLS logs

	// Announce a version 0.0 client
	if err = v0Sql.SendU32(0); err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, &results, err
	}
	v0Response, v0Error := v0Sql.Read()
	if v0Response == nil && v0Error != nil {
		return v0Error.Status, &results, v0Error.Err
	}

	if v0Error != nil && v0Response.Type != 'E' {
		// No server should be allowing a 0.0 client...but if it does allow it, ok?
		log.Debugf("Unexpected response from server: %s", v0Response.ToString())
		results.SupportedVersions = "0.0"
	} else {
		results.SupportedVersions = string(v0Response.Body)
	}

	v0Sql.Close()

	// Skip TLS on second/later rounds, since we already have TLS logs (though if we ever send sensitive information, this may need to change)
	startupSql, connectErr := s.newConnection(&t, mgr, true)
	if connectErr != nil {
		return connectErr.Status, &results, connectErr.Err
	}
	startupPacket := EncodeStartupMessage(s.Config.ProtocolVersion, map[string]string{
		// Intentionally omitting the required "user" field
		"client_encoding": "UTF8",
		"datestyle":       "ISO, MDY",
	})
	if err = startupSql.Send(startupPacket); err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, &results, err
	}
	if response, readError := startupSql.Read(); readError != nil {
		log.Debugf("Error reading response after StartupMessage: %v", readError)
		return readError.Status, &results, readError.Err
	} else {
		if response.Type == 'E' {
			// FIXME TODO: Better output format here
			j, e := json.Marshal(DecodeMap(response.Body))
			if e == nil {
				results.StartupResponse = string(j)
			} else {
				log.Warnf("???", e)
			}
		} else {
			// No server should allow a missing User field
			log.Debugf("Unexpected response from server: %s", response.ToString())
			results.StartupResponse = response.ToString()
		}
	}
	// TODO: Anything else to do? Could we include a dummy user value, but not send the subsequent password packet? That would give us some auth options
	startupSql.Close()
	authSql, connectErr := s.newConnection(&t, mgr, false)
	if connectErr != nil {
		return connectErr.Status, nil, connectErr.Err
	}
	authPacket := EncodeStartupMessage(s.Config.ProtocolVersion, map[string]string{
		"user":            "guest",
		"client_encoding": "UTF8",
		"datestyle":       "ISO, MDY",
	})
	if err = authSql.Send(authPacket); err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, &results, err
	}
	if response, readError := authSql.Read(); readError != nil {
		log.Debugf("Error reading response after auth StartupMessage: %v", readError)
		return readError.Status, &results, readError.Err
	} else {
		log.Warnf("Response: %s", response.ToString())
	}
	return status, &results, thrown
}

// init() registers the module with the zgrab2 framework
func init() {
	var module PostgresModule
	_, err := zgrab2.AddCommand("postgres", "Postgres", "Grab a Postgres handshake", 5432, &module)
	if err != nil {
		log.Fatal(err)
	}
}

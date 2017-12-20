package modules

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/jb/tcpwrap"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialTimeout(network, address string, timeout time.Duration) (net.Conn, error)
}

type Connection struct {
	Connection net.Conn
	Config     *PostgresFlags
	IsSSL      bool
}

type Packet struct {
	Type   byte
	Length uint32
	Body   []byte
}

func (p *Packet) ToString() string {
	return fmt.Sprintf("{ Packet(%p): { Type: '%c', Length: %d, Body: hex(%s) } }", &p, p.Type, p.Length, hex.EncodeToString(p.Body))
}

func (c *Connection) Send(data []byte) error {
	toSend := make([]byte, len(data)+4)
	copy(toSend[4:], data)
	binary.BigEndian.PutUint32(toSend[0:], uint32(len(data)+4))

	// @TODO: Buffered send?
	_, err := c.Connection.Write(toSend)
	return err
}

func (c *Connection) SendU32(val uint32) error {
	toSend := make([]byte, 8)
	binary.BigEndian.PutUint32(toSend[0:], uint32(8))
	binary.BigEndian.PutUint32(toSend[4:], val)
	// @TODO: Buffered send?
	_, err := c.Connection.Write(toSend)
	return err
}

func (c *Connection) Close() error {
	return c.Connection.Close()
}

func (c *Connection) Read() (*Packet, *zgrab2.ScanError) {
	ret := Packet{}
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

// HandshakeLog contains detailed information about each step of the
// MySQL handshake, and can be encoded to JSON.
type PostgresResults struct {
	TLSLog            *zgrab2.TLSLog `json:"tls,omitempty"`
	SupportedVersions string         `json:"supported_versions,omitempty"`
	StartupResponse   string         `json:"startup_response,omitempty"`
	IsSSL             bool           `json:"is_ssl"`
}

type PostgresFlags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	SkipSSL         bool   `long:"skip-ssl" description:"If set, do not attempt to negotiate an SSL connection"`
	Verbose         bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
	ProtocolVersion uint32 `long:"protocol_version" default:"3"`
}

type connectionManager struct {
	connections []*net.Conn
}

func (m *connectionManager) addConnection(c *net.Conn) {
	m.connections = append(m.connections, c)
}

func (m *connectionManager) cleanUp() {
	for _, v := range m.connections {
		// Close them all even if there is a panic with one
		defer func(c *net.Conn) {
			(*c).Close()
		}(v)
	}
}

func newConnectionManager() *connectionManager {
	return &connectionManager{}
}

type PostgresModule struct {
}

type PostgresScanner struct {
	Config *PostgresFlags
}

func init() {
	var module PostgresModule
	_, err := zgrab2.AddCommand("postgres", "Postgres", "Grab a Postgres handshake", 5432, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func ReadDict(buf []byte) map[string]string {
	ret := make(map[string]string)
	parts := strings.Split(string(buf), "\x00")
	for i := 0; i < len(parts)-1; i += 2 {
		k := parts[i]
		v := parts[i+1]
		ret[k] = v
	}
	return ret
}

func SerializeDict(dict map[string]string) []byte {
	var strs []string
	for k, v := range dict {
		strs = append(strs, k)
		strs = append(strs, v)
	}
	return append([]byte(strings.Join(strs, "\x00")), 0x00, 0x00)
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

func (s *PostgresScanner) DoSSL(sql *Connection) error {
	var conn *zgrab2.TLSConnection
	var err error
	if conn, err = s.Config.TLSFlags.GetTLSConnection(tcpwrap.Unwrap(sql.Connection)); err != nil {
		return err
	}
	if err = conn.Handshake(); err != nil {
		return err
	}
	// Replace sql.Connection to allow hypothetical future calls to go over the secure connection
	sql.Connection = tcpwrap.TaggedWrap(conn, "SSL")
	return nil
}

func GetStartupPacket(version uint32, kvps map[string]string) []byte {
	ret := SerializeDict(kvps)
	// FIXME: float version
	return append([]byte{0x00, byte(version), 0x00, 0x00}, ret...)
}

func (s *PostgresScanner) newConnection(t *zgrab2.ScanTarget, mgr *connectionManager, nossl bool) (*Connection, *zgrab2.ScanError) {
	var conn net.Conn
	var err error
	if conn, err = t.Open(&s.Config.BaseFlags); err != nil {
		return nil, zgrab2.DetectScanError(err)
	}
	mgr.addConnection(&conn)
	sql := Connection{Connection: tcpwrap.TaggedWrap(conn, "TCP"), Config: s.Config}
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
				_results.TLSLog = tcpwrap.Unwrap(v0Sql.Connection).(*zgrab2.TLSConnection).GetLog()
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
	startupPacket := GetStartupPacket(s.Config.ProtocolVersion, map[string]string{
		// Omitting the required "user" field
		"client_encoding": "UTF8",
		"datestyle":       "ISO, MDY",
	})
	if err = startupSql.Send(startupPacket); err != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, &results, err
	}
	if response, readError := startupSql.Read(); readError == nil {
		if response.Type == 'E' {
			j, e := json.Marshal(ReadDict(response.Body))
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
	} else {
		fmt.Printf("readError??", readError)
	}
	// Anything else to do? Could we include a dummy user value, but not send the subsequent password packet? That would give us some auth options
	startupSql.Close()
	return status, &results, thrown
}

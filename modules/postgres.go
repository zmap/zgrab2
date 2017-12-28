package modules

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

const (
	// From https://www.postgresql.org/docs/10/static/protocol-message-formats.html: "The SSL request code. The value is chosen to contain 1234 in the most significant 16 bits, and 5679 in the least significant 16 bits. (To avoid confusion, this code must not be the same as any protocol version number.)"
	postgresSSLRequest = 80877103
)

// PostgresResults is the information returned by the scanner to the caller.
// https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes uses the line number of the error response (e.g. StartupError["line"]) to infer the version number
type PostgresResults struct {
	TLSLog             *zgrab2.TLSLog      `json:"tls,omitempty"`
	SupportedVersions  string              `json:"supported_versions,omitempty"`
	ProtocolError      *PostgresError      `json:"protocol_error,omitempty"`
	StartupError       *PostgresError      `json:"startup_error,omitempty"`
	UserStartupError   *PostgresError      `json:"user_startup_error,omitempty"`
	IsSSL              bool                `json:"is_ssl"`
	AuthenticationMode *AuthenticationMode `json:"authentication_mode,omitempty"`
	ServerParameters   map[string]string   `json:"server_parameters,omitempty"`
	BackendKeyData     *BackendKeyData     `json:"backend_key_data,omitempty", zgrab:"debug"`
	TransactionStatus  string              `json:"transaction_status,omitempty"`
}

// PostgresError is parsed the payload of an 'E'-type packet, mapping the friendly names of the various fields to the values returned by the server
type PostgresError map[string]string

// BackendKeyData is the data returned by the 'K'-type packet
type BackendKeyData struct {
	ProcessID uint32 `json:"process_id"`
	SecretKey uint32 `json:"secret_key"`
}

// AuthenticationMode abstracts the various 'R'-type packets
type AuthenticationMode struct {
	Mode    string `json:"mode"`
	Payload []byte `json:"payload,omitempty"'`
}

// PostgresFlags sets the module-specific flags that can be passed in from the command line
type PostgresFlags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	SkipSSL         bool   `long:"skip-ssl" description:"If set, do not attempt to negotiate an SSL connection"`
	Verbose         bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
	ProtocolVersion string `long:"protocol_version" description:"The protocol to use in the StartupPacket" default:"3.0"`
	User            string `long:"user" description:"Username to pass to StartupMessage. If omitted, no user will be sent." default:""`
	Database        string `long:"database" description:"Database to pass to StartupMessage. If omitted, none will be sent." default:""`
	ApplicationName string `long:"application_name" description:"application_name value to pass in StartupMessage. If omitted, none will be sent." default:""`
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
	return fmt.Sprintf("{ ServerPacket(%p): { Type: '%c', Length: %d, Body: [[\n%s\n]] } }", &p, p.Type, p.Length, hex.Dump(p.Body))
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

// Connection.tryReadPacket() attempts to read a packet length + body from the given connection.
func (c *Connection) tryReadPacket(header byte) (*ServerPacket, *zgrab2.ScanError) {
	ret := ServerPacket{Type: header}
	var length [4]byte
	_, err := io.ReadFull(c.Connection, length[:])
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
			return &ret, nil
		} else {
			return nil, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, fmt.Errorf("Server returned too much data: length = 0x%x; first %d bytes = %s", ret.Length, n, hex.EncodeToString(buf[:n])))
		}
	}
	ret.Body = make([]byte, ret.Length-4) // Length includes the length of the Length uint32
	_, err = io.ReadFull(c.Connection, ret.Body)
	if err != nil && err != io.EOF {
		return nil, zgrab2.DetectScanError(err)
	}
	return &ret, nil
}

// Connection.RequestSSL() sends an SSLRequest packet to the server, and returns true iff the server reports that it is SSL-capable. Otherwise it returns false and possibly an error.
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

// Connection.ReadPacket() reads a ServerPacket from the server.
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

// Connection.GetTLSLog() gets the connection's TLSLog, or nil if the connection has not yet been set up as TLS
func (c *Connection) GetTLSLog() *zgrab2.TLSLog {
	if !c.IsSSL {
		return nil
	}
	return c.Connection.(*zgrab2.TLSConnection).GetLog()
}

// decodeAuthMode() decodes the body of an 'R'-type packet and returns a friendlier description of it
func decodeAuthMode(buf []byte) *AuthenticationMode {
	// See the 'R' messages in https://www.postgresql.org/docs/10/static/protocol-message-formats.html
	modeMap := map[uint32]string{
		2:  "kerberos_v5",
		3:  "password_cleartext",
		5:  "password_md5",
		6:  "scm_credentials",
		7:  "gss",
		9:  "sspi",
		10: "sasl",

		// The following aren't actually authentication codes, but they are valid 'R'-type messages
		0:  "ok",
		8:  "gss-continue",
		11: "sasl-continue",
		12: "sasl-final",
	}

	modeId := binary.BigEndian.Uint32(buf[0:4])
	mode, ok := modeMap[modeId]
	if !ok {
		mode = fmt.Sprintf("unknown (0x%x)", modeId)
	}
	return &AuthenticationMode{
		Mode:    mode,
		Payload: buf[4:],
	}
}

// UNKNOWN_ERROR_TAG_KEY is a key in the PostgresError object for values that are not in the list of currently-supported tags
const UNKNOWN_ERROR_TAG_KEY = "unknown_error_tag"

// decodeError() decodes an 'E'-type tag into a dict of key -> value; see https://www.postgresql.org/docs/10/static/protocol-error-fields.html
func decodeError(buf []byte) *PostgresError {
	partMap := map[byte]string{
		'S': "severity",
		// Return both severity and severity_v -- they give the same content, but severity is localized, so it can leak some information about the server
		'V': "severity_v",
		'C': "code",
		'M': "message",
		'D': "detail",
		'H': "hint",
		'P': "position",
		'p': "internal_position",
		'q': "internal_query",
		'W': "where",
		's': "schema",
		't': "table",
		'd': "data",
		'n': "constraint",
		'F': "file",
		'L': "line",
		'R': "routine",
	}

	ret := make(PostgresError)
	parts := strings.Split(string(buf), "\x00")
	for _, part := range parts {
		if len(part) > 0 {
			key, ok := partMap[part[0]]
			if !ok {
				ret[UNKNOWN_ERROR_TAG_KEY] = appendStringList(ret[UNKNOWN_ERROR_TAG_KEY], part)
			} else {
				value := part[1:]
				ret[key] = value
			}
		}
	}
	return &ret
}

// encodeMap() encodes a map into a byte array of the form "key0\0value\0key1\0value1\0...keyN\0valueN\0\0"
func encodeMap(dict map[string]string) []byte {
	var strs []string
	for k, v := range dict {
		strs = append(strs, k)
		strs = append(strs, v)
	}
	return append([]byte(strings.Join(strs, "\x00")), 0x00, 0x00)
}

// appendStringList() adds an entry to a semicolon-separated list; if the list is empty, no semicolon is added.
func appendStringList(dest string, val string) string {
	if dest == "" {
		return val
	} else {
		return dest + "; " + val
	}
}

// BAD_PARAM_KEY is a key into the ServerParameters map for those parameters that don't match the expected format
const BAD_PARAM_KEY = "_bad_parameters"

// PostgresResults.appendBadParam() adds a packet to the list of bad/unexpected parameters
func (results *PostgresResults) appendBadParam(packet *ServerPacket) {
	results.ServerParameters[BAD_PARAM_KEY] = appendStringList(results.ServerParameters[BAD_PARAM_KEY], packet.ToString())
}

// PostgresResults.decodeServerResponse() fills out the results object with the given packet list
func (results *PostgresResults) decodeServerResponse(packets []*ServerPacket) {
	// Note: The only parameters the golang library pays attention to are the server_version and the TimeZone.
	results.ServerParameters = make(map[string]string)
	for _, packet := range packets {
		switch packet.Type {
		case 'S':
			parts := strings.Split(string(packet.Body), "\x00")
			if len(parts) == 2 || (len(parts) == 3 && len(parts[2]) == 0) {
				results.ServerParameters[parts[0]] = parts[1]
			} else {
				log.Debugf("Unexpected format for ParameterStatus packet (%d parts)", len(parts))
				results.appendBadParam(packet)
			}
		case 'K':
			if packet.Length != 12 {
				log.Debugf("Bad size for BackendKeyData (%d)", packet.Length)
				results.appendBadParam(packet)
			} else {
				pid := binary.BigEndian.Uint32(packet.Body[0:4])
				key := binary.BigEndian.Uint32(packet.Body[4:8])
				results.BackendKeyData = &BackendKeyData{
					ProcessID: pid,
					SecretKey: key,
				}
			}
		case 'Z':
			if packet.Length != 5 {
				log.Debugf("Bad size for ReadyForQuery (%d)", packet.Length)
				results.appendBadParam(packet)
			} else {
				results.TransactionStatus = string(packet.Body[0])
			}
		case 'R':
			results.AuthenticationMode = decodeAuthMode(packet.Body)
		case 'E':
			results.UserStartupError = decodeError(packet.Body)
		default:
			// Ignore
		}
	}
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
	dict := encodeMap(kvps)
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
		hasSSL, sslError := sql.RequestSSL()
		if sslError != nil {
			return nil, sslError
		}
		if hasSSL {
			if err = s.DoSSL(&sql); err != nil {
				return nil, zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
			}
			sql.IsSSL = true
		}
	}
	return &sql, nil
}

// PostgresScanner.readAll() reads packets from the given connection until it hits a timeout, EOF, or a 'Z' packet.
func (s *PostgresScanner) readAll(sql *Connection) ([]*ServerPacket, *zgrab2.ScanError) {
	var ret []*ServerPacket = nil
	for {
		response, readError := sql.ReadPacket()
		if readError != nil {
			if readError.Status == zgrab2.SCAN_IO_TIMEOUT || readError.Err == io.EOF {
				return ret, nil
			} else {
				return ret, readError
			}
		}
		ret = append(ret, response)
		if response.Type == 'Z' {
			return ret, nil
		}
	}
}

// Return the default KVPs used for all Startup messages
func (s *PostgresScanner) getDefaultKVPs() map[string]string {
	return map[string]string{
		"client_encoding": "UTF8",
		"datestyle":       "ISO, MDY",
	}
}

// PostgresScanner.Scan() does the actual scanning. It opens two connections:
// With the first it sends a bogus protocol version in hopes of getting a list of supported protcols back.
// With the second, it sends a standard StartupMessage, but without the required "user" field.
func (s *PostgresScanner) Scan(t zgrab2.ScanTarget) (status zgrab2.ScanStatus, result interface{}, thrown error) {
	var results PostgresResults

	mgr := newConnectionManager()
	defer mgr.cleanUp()

	// Send too-low protocol version (0.0) StartupMessage to get a simple supported-protocols error string
	// Also do TLS handshake, if configured / supported
	{
		sql, connectErr := s.newConnection(&t, mgr, false)
		if connectErr != nil {
			return connectErr.Unpack(nil)
		}
		defer sql.Close()
		if sql.IsSSL {
			results.IsSSL = true
			// This pointer will be populated as the connection is negotiated
			results.TLSLog = sql.GetTLSLog()
		} else {
			results.IsSSL = false
			results.TLSLog = nil
		}
		// Do SSL the first round, so that if we bail, we still have the TLS logs

		// Announce a (bogus) version 0.0 client, expect an 'E'-tagged response with just the error message
		if err := sql.SendU32(0x00); err != nil {
			return zgrab2.SCAN_PROTOCOL_ERROR, &results, err
		}
		response, readErr := sql.ReadPacket()
		if readErr != nil {
			return readErr.Unpack(&results)
		}

		if response.Type != 'E' {
			// No server should be allowing a 0.0 client...but if it does allow it, don't bail out
			log.Debugf("Unexpected response from server: %s", response.ToString())
			results.SupportedVersions = response.ToString()
		} else {
			results.SupportedVersions = string(response.Body)
		}

		if _, err := s.readAll(sql); err != nil {
			return err.Unpack(&results)
		}
		sql.Close()
	}

	// Send too-high protocol version (255.255) StartupMessage to get full error message (including line numbers, useful for probing server version)
	{
		sql, connectErr := s.newConnection(&t, mgr, true)
		if connectErr != nil {
			return connectErr.Unpack(&results)
		}

		if err := sql.SendU32(0xff<<16 | 0xff); err != nil {
			return zgrab2.SCAN_PROTOCOL_ERROR, &results, err
		}
		response, readErr := sql.ReadPacket()
		if readErr != nil {
			return readErr.Unpack(&results)
		}

		if response.Type != 'E' {
			// No server should be allowing a 255.255 client...but if it does allow it, don't bail out
			log.Debugf("Unexpected response from server: %s", response.ToString())
			results.ProtocolError = nil
		} else {
			results.ProtocolError = decodeError(response.Body)
		}

		if _, err := s.readAll(sql); err != nil {
			return err.Unpack(&results)
		}
		sql.Close()
	}

	{
		// Skip TLS on second/later rounds, since we already have TLS logs (though if we ever send sensitive information, this may need to change)
		sql, connectErr := s.newConnection(&t, mgr, true)
		if connectErr != nil {
			return connectErr.Unpack(&results)
		}
		startupPacket := EncodeStartupMessage(s.Config.ProtocolVersion, s.getDefaultKVPs())
		if err := sql.Send(startupPacket); err != nil {
			return zgrab2.SCAN_PROTOCOL_ERROR, &results, err
		}
		if response, err := sql.ReadPacket(); err != nil {
			log.Debugf("Error reading response after StartupMessage: %v", err)
			return err.Unpack(&results)
		} else {
			if response.Type == 'E' {
				results.StartupError = decodeError(response.Body)
			} else {
				// No server should allow a missing User field -- but if it does, log and continue
				log.Debugf("Unexpected response from server: %s", response.ToString())
			}
		}
		// TODO: use any packets returned to fill out results? There probably won't be any, and they will probably be overwritten if Config.User etc is set...
		if _, err := s.readAll(sql); err != nil {
			return err.Unpack(&results)
		}
		sql.Close()
	}
	if s.Config.User != "" || s.Config.Database != "" || s.Config.ApplicationName != "" {
		sql, connectErr := s.newConnection(&t, mgr, false)
		if connectErr != nil {
			return connectErr.Unpack(&results)
		}
		kvps := s.getDefaultKVPs()
		if s.Config.User != "" {
			kvps["user"] = s.Config.User
		}
		if s.Config.Database != "" {
			kvps["database"] = s.Config.Database
		}
		if s.Config.ApplicationName != "" {
			kvps["application_name"] = s.Config.ApplicationName
		}
		authPacket := EncodeStartupMessage(s.Config.ProtocolVersion, kvps)
		if err := sql.Send(authPacket); err != nil {
			return zgrab2.SCAN_PROTOCOL_ERROR, &results, err
		}
		packets, err := s.readAll(sql)
		sql.Close()
		if packets != nil {
			results.decodeServerResponse(packets)
		}
		if err != nil {
			return err.Unpack(&results)
		}
	}
	return zgrab2.SCAN_SUCCESS, &results, thrown
}

// init() registers the module with the zgrab2 framework
func init() {
	var module PostgresModule
	_, err := zgrab2.AddCommand("postgres", "Postgres", "Grab a Postgres handshake", 5432, &module)
	if err != nil {
		log.Fatal(err)
	}
}

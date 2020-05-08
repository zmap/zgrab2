// Package postgres contains the postgres zgrab2 Module implementation.
// The Scan does three (or four -- see below) consecutive connections to
// the server, using different StartupMessages each time, and adds the
// server's response to each to the output.
// If any of database/user/application-name are specified on the command
// line, the fourth StartupMessage is sent with the provided data. This
// may allow additional data, such as detailed server parameters, to be
// collected. Absent these, version information must be inferred from
// the values in the results (e.g. line numbers in error strings).
package postgres

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"encoding/json"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

const (
	// From https://www.postgresql.org/docs/10/static/protocol-message-formats.html: "The SSL request code. The value is chosen to contain 1234 in the most significant 16 bits, and 5679 in the least significant 16 bits. (To avoid confusion, this code must not be the same as any protocol version number.)"
	postgresSSLRequest = 80877103
)

const (
	// KeyUnknownErrorTag is the key into the error table denoting an
	// unrecognized error type.
	KeyUnknownErrorTag = "_unknown_error_tag"
	// KeyBadParameters is the key into the ServerParameters table
	// denoting an invalid parameter.
	KeyBadParameters = "_bad_parameters"
)

// Results is the information returned by the scanner to the caller.
// https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes uses the line number of the error response (e.g. StartupError["line"]) to infer the version number
type Results struct {
	// TLSLog is the standard TLS log for the first connection.
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`

	// SupportedVersions is the string returned by the server in response
	// to a StartupMessage with ProtocolVersion = 0.0.
	SupportedVersions string `json:"supported_versions,omitempty"`

	// ProtocolError is the string returned by the server in response to
	// a StartupMessage with ProtocolVersion = 255.255.
	ProtocolError *PostgresError `json:"protocol_error,omitempty"`

	// StartupError is the error returned by the server in response to the
	// StartupMessage with no user provided.
	StartupError *PostgresError `json:"startup_error,omitempty"`

	// UserStartupError is the error returned by the server in response to
	// the final StartupMessage when the user/database/application-name is
	// set.
	UserStartupError *PostgresError `json:"user_startup_error,omitempty"`

	// IsSSL is true if the client was able to set up an SSL connection
	// with the server.
	IsSSL bool `json:"is_ssl"`

	// AuthenticationMode is the value of the R-type packet returned after
	// the final StartupMessage.
	AuthenticationMode *AuthenticationMode `json:"authentication_mode,omitempty"`

	// ServerParameters is a map of the key/value pairs returned after the
	// final StartupMessage.
	ServerParameters *ServerParameters `json:"server_parameters,omitempty"`

	// BackendKeyData is the value of the 'K'-type packet returned by the
	// server after the final StartupMessage.
	BackendKeyData *BackendKeyData `json:"backend_key_data,omitempty" zgrab:"debug"`

	// TransactionStatus is the value of the 'Z'-type packet returned by
	// the server after the final StartupMessage.
	TransactionStatus string `json:"transaction_status,omitempty"`
}

// PostgresError is parsed the payload of an 'E'-type packet, mapping
// the friendly names of the various fields to the values returned by
// the server.
type PostgresError map[string]string

// ServerParameters is a map of key/value pairs sent by the server after
// authentication. These are 'S'-type packets.
// We keep track of them all -- but the golang postgres library only stores the server_version and TimeZone.
type ServerParameters map[string]string

// MarshalJSON returns the ServerParameters as a list of name/value pairs (work
// around schema issue)
func (s *ServerParameters) MarshalJSON() ([]byte, error) {
	ret := make([]string, len(*s))
	i := 0
	for k, v := range *s {
		ret[i] = k + "=" + v
		i++
	}
	return json.Marshal(strings.Join(ret, ","))
}

// BackendKeyData is the data returned by the 'K'-type packet.
type BackendKeyData struct {
	ProcessID uint32 `json:"process_id"`
	SecretKey uint32 `json:"secret_key"`
}

// AuthenticationMode abstracts the various 'R'-type packets.
type AuthenticationMode struct {
	Mode    string `json:"mode"`
	Payload []byte `json:"payload,omitempty"`
}

// Flags sets the module-specific flags that can be passed in from the
// command line.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	SkipSSL         bool   `long:"skip-ssl" description:"If set, do not attempt to negotiate an SSL connection"`
	Verbose         bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
	ProtocolVersion string `long:"protocol-version" description:"The protocol to use in the StartupPacket" default:"3.0"`
	User            string `long:"user" description:"Username to pass to StartupMessage. If omitted, no user will be sent." default:""`
	Database        string `long:"database" description:"Database to pass to StartupMessage. If omitted, none will be sent." default:""`
	ApplicationName string `long:"application-name" description:"application_name value to pass in StartupMessage. If omitted, none will be sent." default:""`
}

// Scanner is the zgrab2 scanner type for the postgres protocol
type Scanner struct {
	Config *Flags
}

// Module is the zgrab2 module for the postgres protocol
type Module struct {
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

	modeID := binary.BigEndian.Uint32(buf[0:4])
	mode, ok := modeMap[modeID]
	if !ok {
		mode = fmt.Sprintf("unknown (0x%x)", modeID)
	}
	return &AuthenticationMode{
		Mode:    mode,
		Payload: buf[4:],
	}
}

// decodeError() decodes an 'E'-type tag into a map of friendly name -> value; see https://www.postgresql.org/docs/10/static/protocol-error-fields.html
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
				ret[KeyUnknownErrorTag] = appendStringList(ret[KeyUnknownErrorTag], part)
			} else {
				value := part[1:]
				ret[key] = value
			}
		}
	}
	return &ret
}

// appendStringList() adds an entry to a semicolon-separated list; if the list is empty, no semicolon is added.
func appendStringList(dest string, val string) string {
	if dest == "" {
		return val
	}
	return dest + "; " + val
}

// ServerParameters.appendBadParam() adds a packet to the list of bad/unexpected parameters
func (p *ServerParameters) appendBadParam(packet *ServerPacket) {
	(*p)[KeyBadParameters] = appendStringList((*p)[KeyBadParameters], packet.OutputValue())
}

// Results.decodeServerResponse() fills out the results object with packets returned by the server.
func (results *Results) decodeServerResponse(packets []*ServerPacket) {
	// Note: The only parameters the golang postgres library pays attention to are the server_version and the TimeZone.
	serverParams := make(ServerParameters)
	for _, packet := range packets {
		switch packet.Type {
		case 'S':
			parts := strings.Split(string(packet.Body), "\x00")
			if len(parts) == 2 || (len(parts) == 3 && len(parts[2]) == 0) {
				serverParams[parts[0]] = parts[1]
			} else {
				log.Debugf("Unexpected format for ParameterStatus packet (%d parts)", len(parts))
				serverParams.appendBadParam(packet)
			}
		case 'K':
			if packet.Length != 12 {
				log.Debugf("Bad size for BackendKeyData (%d)", packet.Length)
				serverParams.appendBadParam(packet)
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
				serverParams.appendBadParam(packet)
			} else {
				results.TransactionStatus = string(packet.Body[0])
			}
		case 'R':
			results.AuthenticationMode = decodeAuthMode(packet.Body)
		case 'E':
			results.UserStartupError = decodeError(packet.Body)
		default:
			// Ignore other message types
		}
	}
	// Merge the ServerParams, so that we can keep track of values across multiple connections
	if len(serverParams) > 0 {
		if results.ServerParameters == nil {
			results.ServerParameters = &serverParams
		} else {
			for k, v := range serverParams {
				(*results.ServerParameters)[k] = v
			}
		}
	}
}

// NewFlags returns a default Flags instance.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns the module's zgrab2.Scanner implementation.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "Perform a handshake with a PostgreSQL server"
}

// Validate checks the arguments; on success, returns nil.
func (f *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the scanner with the given flags.
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	s.Config = f
	if f.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	return nil
}

// InitPerSender does nothing in this module.
func (s *Scanner) InitPerSender(senderID int) error {
	return nil
}

// Protocol returns the protocol identifer for the scanner.
func (s *Scanner) Protocol() string {
	return "postgres"
}

// GetName returns the name from the parameters.
func (s *Scanner) GetName() string {
	return s.Config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (s *Scanner) GetTrigger() string {
	return s.Config.Trigger
}

// DoSSL attempts to upgrade the connection to SSL, returning an error on failure.
func (s *Scanner) DoSSL(sql *Connection) error {
	var conn *zgrab2.TLSConnection
	var err error
	if conn, err = s.Config.TLSFlags.GetTLSConnection(sql.Connection); err != nil {
		return err
	}
	if err = conn.Handshake(); err != nil {
		return err
	}
	// Replace sql.Connection to allow future calls to go over the secure connection
	sql.Connection = conn
	return nil
}

// newConnection opens up a new connection to the ScanTarget, and if necessary, attempts to update the connection to SSL
func (s *Scanner) newConnection(t *zgrab2.ScanTarget, mgr *connectionManager, nossl bool) (*Connection, *zgrab2.ScanError) {
	var conn net.Conn
	var err error
	// Open a managed connection to the ScanTarget, register it for automatic cleanup
	if conn, err = t.Open(&s.Config.BaseFlags); err != nil {
		return nil, zgrab2.DetectScanError(err)
	}
	mgr.addConnection(conn)
	sql := Connection{Target: t, Connection: conn, Config: s.Config}
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

// Return the default KVPs used for all Startup messages
func (s *Scanner) getDefaultKVPs() map[string]string {
	return map[string]string{
		"client_encoding": "UTF8",
		"datestyle":       "ISO, MDY",
	}
}

// Scan does the actual scanning. It opens up to four connections:
// 1. Sends a bogus protocol version in hopes of getting a list of
//    supported protcols back. Results here are supported_versions and
//    and tls (* if applicable).
// 2. Send a too-high protocol version (255.255) to get full error
//    message, including line numbers, which could be useful for probing
//    server version. This is where it gets the protcol_error result.
// 3. Send a StartupMessage with a valid protocol version (by default
//    3.0, but this can be overridden on the command line), but omit the
//    user field. This is where it gets the startup_error result.
// 4. Only sent if at least one of user/database/application-name
//    command line flags are provided. Does the same as #3, but includes
//    any/all of user/database/application-name. This is where it gets
//    backend_key_data, server_parameters, authentication_mode,
//    transaction_status and user_startup_error.
//
// * NOTE: TLS is only used for the first connection, and then only if
//   both client and server support it.
func (s *Scanner) Scan(t zgrab2.ScanTarget) (status zgrab2.ScanStatus, result interface{}, thrown error) {
	var results Results

	mgr := newConnectionManager()
	defer mgr.cleanUp()

	// Send too-low protocol version (0.0) StartupMessage to get a simple supported-protocols error string
	// Also do TLS handshake, if configured / supported
	{
		sql, connectErr := s.newConnection(&t, mgr, false)
		if connectErr != nil {
			return connectErr.Unpack(nil)
		}
		defer mgr.closeConnection(sql)
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
			return zgrab2.TryGetScanStatus(err), &results, err
		}
		response, readErr := sql.ReadPacket()
		if readErr != nil {
			return readErr.Unpack(&results)
		}

		if response.Type != 'E' {
			// No server should be allowing a 0.0 client...but if it does allow it, don't bail out
			log.Debugf("Unexpected response from server: %s", response.ToString())
			results.SupportedVersions = response.OutputValue()
		} else {
			results.SupportedVersions = strings.Trim(string(response.Body), "\x00\r\n ")
		}

		if _, err := sql.ReadAll(); err != nil {
			return err.Unpack(&results)
		}
		mgr.closeConnection(sql)
	}

	// Send too-high protocol version (255.255) StartupMessage to get full error message (including line numbers, useful for probing server version)
	{
		sql, connectErr := s.newConnection(&t, mgr, true)
		if connectErr != nil {
			return connectErr.Unpack(&results)
		}
		defer mgr.closeConnection(sql)

		if err := sql.SendU32(0xff<<16 | 0xff); err != nil {
			// Whatever the actual problem, a send error will be treated as a SCAN_PROTOCOL_ERROR since the scan got this far
			return zgrab2.SCAN_PROTOCOL_ERROR, &results, err
		}
		response, readErr := sql.ReadPacket()
		if readErr != nil {
			return readErr.Unpack(&results)
		}

		if response.Type != 'E' {
			// No server should be allowing a 255.255 client...but if it does allow it, don't bail out
			log.Debugf("Unexpected response from server: %s", response.ToString())
			results.ProtocolError = response.ToError()
		} else {
			results.ProtocolError = decodeError(response.Body)
		}

		if _, err := sql.ReadAll(); err != nil {
			return err.Unpack(&results)
		}
		mgr.closeConnection(sql)
	}

	// Send a StartupMessage with a valid protocol version number, but omit the user field
	{
		var err error
		var response *ServerPacket
		var readErr *zgrab2.ScanError
		sql, connectErr := s.newConnection(&t, mgr, true)
		if connectErr != nil {
			return connectErr.Unpack(&results)
		}
		defer mgr.closeConnection(sql)

		if err = sql.SendStartupMessage(s.Config.ProtocolVersion, s.getDefaultKVPs()); err != nil {
			return zgrab2.SCAN_PROTOCOL_ERROR, &results, err
		}
		if response, readErr = sql.ReadPacket(); readErr != nil {
			log.Debugf("Error reading response after StartupMessage: %v", readErr)
			return readErr.Unpack(&results)
		}
		if response.Type == 'E' {
			results.StartupError = decodeError(response.Body)
		} else {
			// No server should allow a missing User field -- but if it does, log and continue
			log.Debugf("Unexpected response from server: %s", response.ToString())
			results.StartupError = response.ToError()
		}
		// TODO: use any packets returned to fill out results? There probably won't be any, and they will probably be overwritten if Config.User etc is set...
		if _, readErr = sql.ReadAll(); readErr != nil {
			return readErr.Unpack(&results)
		}
		mgr.closeConnection(sql)
	}

	// If user / database / application_name are provided, do a final scan with those
	if s.Config.User != "" || s.Config.Database != "" || s.Config.ApplicationName != "" {
		sql, connectErr := s.newConnection(&t, mgr, false)
		if connectErr != nil {
			return connectErr.Unpack(&results)
		}
		defer mgr.closeConnection(sql)

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
		if err := sql.SendStartupMessage(s.Config.ProtocolVersion, kvps); err != nil {
			return zgrab2.SCAN_PROTOCOL_ERROR, &results, err
		}
		packets, err := sql.ReadAll()
		mgr.closeConnection(sql)
		if packets != nil {
			results.decodeServerResponse(packets)
		}
		if err != nil {
			return err.Unpack(&results)
		}
	}
	return zgrab2.SCAN_SUCCESS, &results, thrown
}

// RegisterModule is called by modules/postgres.go's init(), to register
// the postgres module with the zgrab2 framework.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("postgres", "Postgres", module.Description(), 5432, &module)
	if err != nil {
		log.Fatal(err)
	}
}

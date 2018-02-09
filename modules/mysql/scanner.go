// Package mysql provides the mysql implementation of the zgrab2.Module.
// Grabs the HandshakePacket (or ERRPacket) that the server sends
// immediately upon connecting, and then if applicable negotiate an SSL
// connection.
package mysql

import (
	"reflect"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/mysql"
)

// MySQLScanResults contains detailed information about the scan.
type MySQLScanResults struct {
	// ProtocolVersion is the 8-bit unsigned integer representing the
	// server's protocol version sent in the initial HandshakePacket from
	// the server.
	// This has been 10 for all MySQL versionssince 3.2.2 (from 1998).
	ProtocolVersion byte `json:"protocol_version"`

	// ServerVersion is a null-terminated string giving the specific
	// server version in the initial HandshakePacket. Often of the format
	// x.y.z, but not always.
	ServerVersion string `json:"server_version"`

	// ConnectionID is the server's internal identifier for this client's
	// connection, sent in the initial HandshakePacket.
	ConnectionID uint32 `json:"connection_id" zgrab:"debug"`

	// AuthPluginData is optional plugin-specific data, whose meaning
	// depends on the value of AuthPluginName. Returned in the initial
	// HandshakePacket.
	AuthPluginData []byte `json:"auth_plugin_data" zgrab:"debug"`

	// CharacterSet is the identifier for the character set the server is
	// using. Returned in the initial HandshakePacket.
	CharacterSet byte `json:"character_set" zgrab:"debug"`

	// StatusFlags is the set of status flags the server returned in the
	// initial HandshakePacket. Each true entry in the map corresponds to
	// a bit set to 1 in the flags, where the keys correspond to the
	// #defines in the MySQL docs.
	StatusFlags map[string]bool `json:"status_flags"`

	// CapabilityFlags is the set of capability flags the server returned
	// initial HandshakePacket. Each true entry in the map corresponds to
	// a bit set to 1 in the flags, where the keys correspond to the
	// #defines in the MySQL docs.
	CapabilityFlags map[string]bool `json:"capability_flags"`

	// AuthPluginName is the name of the authentication plugin, returned
	// in the initial HandshakePacket.
	AuthPluginName string `json:"auth_plugin_name,omitempty" zgrab:"debug"`

	// ErrorCode is only set if there is an error returned by the server,
	// for example if the scanner is not on the allowed hosts list.
	ErrorCode *int `json:"error_code,omitempty"`

	// ErrorMessage is an optional string describing the error. Only set
	// if there is an error.
	ErrorMessage string `json:"error_message,omitempty"`

	// RawPackets contains the base64 encoding of all packets sent and
	// received during the scan.
	RawPackets []string `json:"raw_packets,omitempty"`

	// TLSLog contains the usual shared TLS logs.
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Convert the ConnectionLog into the output format.
func readResultsFromConnectionLog(connectionLog *mysql.ConnectionLog) *MySQLScanResults {
	ret := MySQLScanResults{}
	if connectionLog == nil {
		return &ret
	}
	if connectionLog.Handshake != nil {
		ret.RawPackets = append(ret.RawPackets, connectionLog.Handshake.Raw)
		switch handshake := connectionLog.Handshake.Parsed.(type) {
		case *mysql.HandshakePacket:
			ret.ProtocolVersion = handshake.ProtocolVersion
			ret.ConnectionID = handshake.ConnectionID
			len1 := len(handshake.AuthPluginData1)
			ret.AuthPluginData = make([]byte, len1+len(handshake.AuthPluginData2))
			copy(ret.AuthPluginData[0:len1], handshake.AuthPluginData1)
			copy(ret.AuthPluginData[len1:], handshake.AuthPluginData2)
			ret.CharacterSet = handshake.CharacterSet
			ret.StatusFlags = mysql.GetServerStatusFlags(handshake.StatusFlags)
			ret.CapabilityFlags = mysql.GetClientCapabilityFlags(handshake.CapabilityFlags)
			ret.AuthPluginName = handshake.AuthPluginName
		default:
			log.Fatalf("Unreachable code -- ConnectionLog.Handshake was set to a non-handshake packet: %v / %v", connectionLog.Handshake.Parsed, reflect.TypeOf(connectionLog.Handshake.Parsed))
		}
	}
	if connectionLog.Error != nil {
		ret.RawPackets = append(ret.RawPackets, connectionLog.Error.Raw)
		switch err := connectionLog.Error.Parsed.(type) {
		case *mysql.ERRPacket:
			temp := int(err.ErrorCode)
			ret.ErrorCode = &temp
			ret.ErrorMessage = err.ErrorMessage
		default:
			temp := -1
			ret.ErrorCode = &temp
			ret.ErrorMessage = "Unexpected packet type"
		}
	}
	if connectionLog.SSLRequest != nil {
		ret.RawPackets = append(ret.RawPackets, connectionLog.SSLRequest.Raw)
	}
	return &ret
}

type MySQLFlags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

type MySQLModule struct {
}

type MySQLScanner struct {
	config *MySQLFlags
}

func RegisterModule() {
	var module MySQLModule
	_, err := zgrab2.AddCommand("mysql", "MySQL", "Grab a MySQL handshake", 3306, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *MySQLModule) NewFlags() interface{} {
	return new(MySQLFlags)
}

func (m *MySQLModule) NewScanner() zgrab2.Scanner {
	return new(MySQLScanner)
}

func (f *MySQLFlags) Validate(args []string) error {
	return nil
}

func (f *MySQLFlags) Help() string {
	return ""
}

func (s *MySQLScanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*MySQLFlags)
	s.config = f
	return nil
}

func (s *MySQLScanner) InitPerSender(senderID int) error {
	return nil
}

func (s *MySQLScanner) GetName() string {
	return s.config.Name
}

func (s *MySQLScanner) GetPort() uint {
	return s.config.Port
}

func (s *MySQLScanner) Scan(t zgrab2.ScanTarget) (status zgrab2.ScanStatus, result interface{}, thrown error) {
	sql := mysql.NewConnection(&mysql.Config{})
	defer func() {
		recovered := recover()
		if recovered != nil {
			thrown = recovered.(error)
			status = zgrab2.TryGetScanStatus(thrown)
			// TODO FIXME: do more to distinguish errors
		}
		result = readResultsFromConnectionLog(&sql.ConnectionLog)
	}()
	defer sql.Disconnect()
	var err error
	conn, err := t.Open(&s.config.BaseFlags)
	if err != nil {
		panic(err)
	}
	if err = sql.Connect(conn); err != nil {
		panic(err)
	}
	if sql.SupportsTLS() {
		if err = sql.NegotiateTLS(); err != nil {
			panic(err)
		}
		var conn *zgrab2.TLSConnection
		if conn, err = s.config.TLSFlags.GetTLSConnection(sql.Connection); err != nil {
			panic(err)
		}
		// Following the example of the SSH module, allow the possibility of failing while still returning a (perhaps incomplete) log
		result.(*MySQLScanResults).TLSLog = conn.GetLog()
		if err = conn.Handshake(); err != nil {
			panic(err)
		}
		// Replace sql.Connection to allow hypothetical future calls to go over the secure connection
		sql.Connection = conn
	}
	// If we made it this far, the scan was a success. The result will be grabbed in the defer block above.
	return zgrab2.SCAN_SUCCESS, nil, nil
}

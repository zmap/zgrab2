// package mysql provides the mysql implementation of the zgrab2.Module.
// Grabs the HandshakePacket (or ERRPacket) that the server sends
// immediately upon connecting, and then if applicable negotiate an SSL
// connection.
package mysql

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/mysql"
)

// HandshakeLog contains detailed information about each step of the
// MySQL handshake, and can be encoded to JSON.
type MySQLScanResults struct {
	ProtocolVersion byte            `json:"protocol_version"`
	ServerVersion   string          `json:"server_version"`
	ConnectionID    uint32          `json:"connection_id" zgrab:"debug"`
	AuthPluginData  []byte          `json:"auth_plugin_data" zgrab:"debug"`
	CharacterSet    byte            `json:"character_set" zgrab:"debug"`
	StatusFlags     map[string]bool `json:"status_flags"`
	CapabilityFlags map[string]bool `json:"capability_flags"`
	AuthPluginName  string          `json:"auth_plugin_name,omitempty" zgrab:"debug"`
	ErrorCode       *int             `json:"error_code,omitempty"`
	ErrorMessage    string          `json:"error_message,omitempty"`
	RawPackets      []string 				`json:"raw_packets,omitempty"`
	TLSLog          *zgrab2.TLSLog  `json:"tls,omitempty"`
}

func readResultsFromConnectionLog(connectionLog *mysql.ConnectionLog) *MySQLScanResults {
	ret := MySQLScanResults{}
	if connectionLog == nil {
		return &ret
	}
	if connectionLog.Handshake != nil {
		ret.RawPackets = append(ret.RawPackets, connectionLog.Handshake.Raw)
		switch handshake := connectionLog.Handshake.Parsed.(type) {
		case mysql.HandshakePacket:
			ret.ProtocolVersion = handshake.ProtocolVersion
			ret.ConnectionID = handshake.ConnectionID
			len1 := len(handshake.AuthPluginData1)
			ret.AuthPluginData = make([]byte, len1 + len(handshake.AuthPluginData2))
			copy(ret.AuthPluginData[0:len1], handshake.AuthPluginData1)
			copy(ret.AuthPluginData[len1:], handshake.AuthPluginData2)
			ret.CharacterSet = handshake.CharacterSet
			ret.StatusFlags = mysql.GetServerStatusFlags(handshake.StatusFlags)
			ret.CapabilityFlags = mysql.GetClientCapabilityFlags(handshake.CapabilityFlags)
			ret.AuthPluginName = handshake.AuthPluginName
		default:
			log.Fatalf("Unreachable code -- ConnectionLog.Handshake was set to a non-handshake packet")
		}
	}
	if connectionLog.Error != nil {
		ret.RawPackets = append(ret.RawPackets, connectionLog.Error.Raw)
		switch err := connectionLog.Error.Parsed.(type) {
		case mysql.ERRPacket:
			temp := int(err.ErrorCode)
			ret.ErrorCode = &temp
			ret.ErrorMessage = err.ErrorMessage
		default:
			temp := -1
			ret.ErrorCode = &temp
			ret.ErrorMessage = "Unexpected error packet type"
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

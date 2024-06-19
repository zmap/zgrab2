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

// ScanResults contains detailed information about the scan.
type ScanResults struct {
	// ProtocolVersion is the 8-bit unsigned integer representing the
	// server's protocol version sent in the initial HandshakePacket from
	// the server.
	// This has been 10 for all MySQL versionssince 3.2.2 (from 1998).
	ProtocolVersion byte `json:"protocol_version"`

	// ServerVersion is a null-terminated string giving the specific
	// server version in the initial HandshakePacket. Often of the format
	// x.y.z, but not always.
	ServerVersion string `json:"server_version,omitempty"`

	// ConnectionID is the server's internal identifier for this client's
	// connection, sent in the initial HandshakePacket.
	ConnectionID uint32 `json:"connection_id,omitempty" zgrab:"debug"`

	// AuthPluginData is optional plugin-specific data, whose meaning
	// depends on the value of AuthPluginName. Returned in the initial
	// HandshakePacket.
	AuthPluginData []byte `json:"auth_plugin_data,omitempty" zgrab:"debug"`

	// CharacterSet is the identifier for the character set the server is
	// using. Returned in the initial HandshakePacket.
	CharacterSet byte `json:"character_set,omitempty" zgrab:"debug"`

	// StatusFlags is the set of status flags the server returned in the
	// initial HandshakePacket. Each true entry in the map corresponds to
	// a bit set to 1 in the flags, where the keys correspond to the
	// #defines in the MySQL docs.
	StatusFlags map[string]bool `json:"status_flags,omitempty"`

	// CapabilityFlags is the set of capability flags the server returned
	// initial HandshakePacket. Each true entry in the map corresponds to
	// a bit set to 1 in the flags, where the keys correspond to the
	// #defines in the MySQL docs.
	CapabilityFlags map[string]bool `json:"capability_flags,omitempty"`

	// AuthPluginName is the name of the authentication plugin, returned
	// in the initial HandshakePacket.
	AuthPluginName string `json:"auth_plugin_name,omitempty" zgrab:"debug"`

	// ErrorCode is only set if there is an error returned by the server,
	// for example if the scanner is not on the allowed hosts list.
	ErrorCode *int `json:"error_code,omitempty"`

	// ErrorID is the friendly name of the error code, if recognized.
	ErrorID string `json:"error_id,omitempty"`

	// ErrorMessage is an optional string describing the error. Only set
	// if there is an error.
	ErrorMessage string `json:"error_message,omitempty"`

	// RawPackets contains the base64 encoding of all packets sent and
	// received during the scan.
	RawPackets []string `json:"raw_packets,omitempty" zgrab:"debug"`

	// TLSLog contains the usual shared TLS logs.
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Put the error into the results.
func (results *ScanResults) setError(err *mysql.ERRPacket) {
	if err != nil {
		temp := int(err.ErrorCode)
		results.ErrorCode = &temp
		results.ErrorID = err.GetErrorID()
		results.ErrorMessage = err.ErrorMessage
	}
}

// Convert the ConnectionLog into the output format.
func readResultsFromConnectionLog(connectionLog *mysql.ConnectionLog) *ScanResults {
	ret := ScanResults{}
	if connectionLog == nil {
		return nil
	}
	// If we received neither a Handshake nor an Error message, then no
	// MySQL service is detected.
	if connectionLog.Handshake == nil && connectionLog.Error == nil {
		return nil
	}
	if connectionLog.Handshake != nil {
		ret.RawPackets = append(ret.RawPackets, connectionLog.Handshake.Raw)
		switch handshake := connectionLog.Handshake.Parsed.(type) {
		case *mysql.HandshakePacket:
			ret.ProtocolVersion = handshake.ProtocolVersion
			ret.ServerVersion = handshake.ServerVersion
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
			ret.setError(err)
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

// Flags give the command-line flags for the MySQL module.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

// RegisterModule is called by modules/mysql.go to register the scanner.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("mysql", "MySQL", module.Description(), 3306, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a new default flags object.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner object.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "Perform a handshake with a MySQL database"
}

// Validate validates the flags and returns nil on success.
func (f *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the command-line flags.
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	s.config = f
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
	return "mysql"
}

// GetName returns the name from the command line flags.
func (s *Scanner) GetName() string {
	return s.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Scan probles the target for a MySQL server.
//  1. Connects and waits to receive the handshake packet.
//  2. If the server supports SSL, send an SSLRequest packet, then
//     perform the standard TLS actions.
//  3. Process and return the results.
func (s *Scanner) Scan(t zgrab2.ScanTarget) (status zgrab2.ScanStatus, result interface{}, thrown error) {
	var tlsConn *zgrab2.TLSConnection
	sql := mysql.NewConnection(&mysql.Config{})
	defer func() {
		recovered := recover()
		if recovered != nil {
			thrown = recovered.(error)
			status = zgrab2.TryGetScanStatus(thrown)
			// TODO FIXME: do more to distinguish errors
		}
		result = readResultsFromConnectionLog(&sql.ConnectionLog)
		if tlsConn != nil {
			result.(*ScanResults).TLSLog = tlsConn.GetLog()
		}
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
		if tlsConn, err = s.config.TLSFlags.GetTLSConnection(sql.Connection); err != nil {
			panic(err)
		}
		if err = tlsConn.Handshake(); err != nil {
			panic(err)
		}
		// Replace sql.Connection to allow hypothetical future calls to go over the secure connection
		sql.Connection = tlsConn
	}
	// If we made it this far, the scan was a success. The result will be grabbed in the defer block above.
	return zgrab2.SCAN_SUCCESS, nil, nil
}

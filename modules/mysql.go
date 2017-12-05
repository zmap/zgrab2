package modules

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/mysql"
)

// HandshakeLog contains detailed information about each step of the
// MySQL handshake, and can be encoded to JSON.
type MySQLScanResults struct {
	PacketLog    []*mysql.PacketLogEntry   `json:"packet_log,omitempty"`
	HandshakeLog *zgrab2.ZGrabHandshakeLog `json:"tls_handshake,omitempty"`
}

type MySQLFlags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	Verbose bool `long:"verbose" description:"Output additional information, including <TODO: including what?>."`
}

type MySQLModule struct {
}

type MySQLScanner struct {
	config *MySQLFlags
}

func init() {
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
	// @TODO @FIXME: This is never called..?
	log.WithFields(log.Fields{"scanner": s}).Info("InitPerSender", senderID)
	return nil
}

func (s *MySQLScanner) GetName() string {
	return s.config.Name
}

func (s *MySQLScanner) GetPort() uint {
	return s.config.Port
}

func (s *MySQLScanner) Scan(t zgrab2.ScanTarget) (_result interface{}, thrown error) {
	sql := mysql.NewConnection(&mysql.Config{
		Host: t.IP.String(),
		Port: uint16(s.config.Port),
	})

	result := MySQLScanResults{}
	_result = &result
	defer func() {
		recovered := recover()
		if recovered != nil {
			// Don't clobber an explicitly-thrown error message just bcause there was no panic()
			log.Infof("Got error scanning %s: %v", s.GetName(), recovered)
			thrown = recovered.(error)
		}
		result.PacketLog = sql.PacketLog
		if result.PacketLog == nil {
			if thrown == nil {
				thrown = fmt.Errorf("Unable to retrieve scan logs")
			}
		}
		// Following the example of the SSH module, allow the possibility of failing while still returning a (perhaps incomplete) log
	}()
	defer sql.Disconnect()
	if err := sql.Connect(); err != nil {
		panic(err)
	}
	if sql.SupportsTLS() {
		if nerr := sql.NegotiateTLS(); nerr != nil {
			panic(nerr)
		}
		var conn *zgrab2.ZGrabConnection
		if conn, thrown = s.config.TLSFlags.GetZGrabTLSConnection(sql.Connection); thrown != nil {
			panic(thrown)
		}
		if herr := conn.Handshake(); herr == nil {
			panic(herr)
		}
		// Replace sql.Connection to allow hypothetical future calls to go over the secure connection
		var netConn net.Conn = conn
		sql.Connection = &netConn
		// Works:
		//	var netConn net.Conn = conn
		//	sql.Connection = &netConn
		// Does not work:
		//	sql.Connection = &conn // (**ZGrabConnection is not *net.Conn)
		//  sql.Connection = &(conn.(net.Conn)) // (conn is not an interface)
		//  sql.Connection = conn.Conn // (cannot use conn.Conn (type tls.Conn) as type *net.Conn)
		//  sql.Connection = &conn.Conn // (cannot use &conn.Conn (type *tls.Conn) as type *net.Conn)
		//	sql.Connection = &(conn.Conn.conn) // (cannot refer to unexported field or method conn)
		result.HandshakeLog = conn.GetHandshakeLog()
	}
	return _result, thrown
}

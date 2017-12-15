package modules

import (
	"net"

	logrus "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/mysql"
)

var logger *logrus.Logger

// HandshakeLog contains detailed information about each step of the
// MySQL handshake, and can be encoded to JSON.
type MySQLScanResults struct {
	mysql.ConnectionLog
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
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

func init() {
	logger = logrus.New()
	var module MySQLModule
	_, err := zgrab2.AddCommand("mysql", "MySQL", "Grab a MySQL handshake", 3306, &module)
	if err != nil {
		logger.Fatal(err)
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
	if f.Verbose {
		logger.SetLevel(logrus.DebugLevel)
	}
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

func (s *MySQLScanner) Scan(t zgrab2.ScanTarget) (status zgrab2.ScanStatus, _result interface{}, thrown error) {
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
			logger.Debugf("Got error scanning %s: %v", s.GetName(), recovered)
			thrown = recovered.(error)
		}
		result.ConnectionLog = sql.ConnectionLog
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
		var conn *zgrab2.TLSConnection
		if conn, thrown = s.config.TLSFlags.GetTLSConnection(sql.Connection); thrown != nil {
			panic(thrown)
		}
		if herr := conn.Handshake(); herr != nil {
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
		result.TLSLog = conn.GetLog()
	}
	// TODO FIXME: do more to distinguish errors
	return zgrab2.TryGetScanStatus(thrown), _result, thrown
}

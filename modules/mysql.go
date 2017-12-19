package modules

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/mysql"
)

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
	sql := mysql.NewConnection(&mysql.Config{
		Host: t.IP.String(),
		Port: uint16(s.config.Port),
	})
	result = &MySQLScanResults{}
	defer func() {
		recovered := recover()
		if recovered != nil {
			thrown = recovered.(error)
			status = zgrab2.TryGetScanStatus(thrown)
			// TODO FIXME: do more to distinguish errors
		}
		result.(*MySQLScanResults).ConnectionLog = sql.ConnectionLog
	}()
	defer sql.Disconnect()
	var err error
	if err = sql.Connect(); err != nil {
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
	// If we made it this far, the scan was a success.
	return zgrab2.SCAN_SUCCESS, result, nil
}

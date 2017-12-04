package modules

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/mysql"
)

// HandshakeLog contains detailed information about each step of the
// MySQL handshake, and can be encoded to JSON.
type MySQLScanResults struct {
	PacketLog    []*mysql.PacketLogEntry `json:"packet_log"`
	TLSHandshake *tls.ServerHandshake    `json:"tls_handshake,omitempty"`
}

type MySQLFlags struct {
	zgrab2.BaseFlags
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

func (s *MySQLScanner) Scan(t zgrab2.ScanTarget) (interface{}, error) {
	sql := mysql.NewConnection(&mysql.Config{
		Host: t.IP.String(),
		Port: uint16(s.config.Port),
	})
	err := sql.Connect()
	defer sql.Disconnect()
	if err != nil {
		return nil, err
	}
	ret := MySQLScanResults{PacketLog: sql.PacketLog}
	if sql.IsSecure() {
		ret.TLSHandshake = sql.TLSHandshake
	}

	return ret, nil
}

package mssql

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// HandshakeLog contains detailed information about each step of the
// MySQL handshake, and can be encoded to JSON.
type MSSQLScanResults struct {
	Version         string           `json:"version,omitempty"`
	InstanceName    string           `json:"instance_name,omitempty"`
	TLSLog          *zgrab2.TLSLog   `json:"tls,omitempty"`
	PreloginOptions *PreloginOptions `json:"prelogin_options,omitempty" zgrab:"debug"`
}

type MSSQLFlags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	EncryptMode string `long:"encrypt-mode" description:"The type of encryption to request in the pre-login step. One of ENCRYPT_ON, ENCRYPT_OFF, ENCRYPT_NOT_SUP."`
	Verbose     bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

type MSSQLModule struct {
}

type MSSQLScanner struct {
	config *MSSQLFlags
}

func init() {
	var module MSSQLModule
	_, err := zgrab2.AddCommand("mssql", "MSSQL", "Grab a MSSQL handshake", 1433, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (self *MSSQLModule) NewFlags() interface{} {
	return new(MSSQLFlags)
}

func (self *MSSQLModule) NewScanner() zgrab2.Scanner {
	return new(MSSQLScanner)
}

func (self *MSSQLFlags) Validate(args []string) error {
	return nil
}

func (self *MSSQLFlags) Help() string {
	return ""
}

func (self *MSSQLScanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*MSSQLFlags)
	self.config = f
	return nil
}

func (self *MSSQLScanner) InitPerSender(senderID int) error {
	return nil
}

func (self *MSSQLScanner) GetName() string {
	return self.config.Name
}

func (s *MSSQLScanner) GetPort() uint {
	return s.config.Port
}

func (self *MSSQLScanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	conn, err := target.Open(&self.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	sql := NewConnection(conn)
	defer sql.Close()
	result := &MSSQLScanResults{}
	_, err = sql.Handshake(self.config)

	if sql.tlsConn != nil {
		result.TLSLog = sql.tlsConn.GetLog()
	}

	if sql.PreloginOptions != nil {
		result.PreloginOptions = sql.PreloginOptions
		version := sql.PreloginOptions.GetVersion()
		if version != nil {
			result.Version = fmt.Sprintf("%d.%d.%d", version.Major, version.Minor, version.BuildNumber)
		}
	}

	if err != nil {
		switch err {
		case ErrNoServerEncryption:
			return zgrab2.SCAN_APPLICATION_ERROR, &result, err
		case ErrServerRequiresEncryption:
			return zgrab2.SCAN_APPLICATION_ERROR, &result, err
		default:
			return zgrab2.TryGetScanStatus(err), &result, err
		}
	}
	return zgrab2.SCAN_SUCCESS, result, nil
}

// Called by modules/postgres.go's init()
func RegisterModule() {
	var module MSSQLModule
	_, err := zgrab2.AddCommand("mssql", "MSSQL", "Grab a mssql handshake", 1433, &module)
	log.SetLevel(log.DebugLevel)
	if err != nil {
		log.Fatal(err)
	}
}

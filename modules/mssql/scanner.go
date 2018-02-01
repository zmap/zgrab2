package mssql

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// HandshakeLog contains detailed information about each step of the
// MySQL handshake, and can be encoded to JSON.
type mssqlScanResults struct {
	Version         string           `json:"version,omitempty"`
	InstanceName    string           `json:"instance_name,omitempty"`
	TLSLog          *zgrab2.TLSLog   `json:"tls,omitempty"`
	PreloginOptions *preloginOptions `json:"prelogin_options,omitempty" zgrab:"debug"`
}

type mssqlFlags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	EncryptMode string `long:"encrypt-mode" description:"The type of encryption to request in the pre-login step. One of ENCRYPT_ON, ENCRYPT_OFF, ENCRYPT_NOT_SUP."`
	Verbose     bool   `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

type mssqlModule struct {
}

type mssqlScanner struct {
	config *mssqlFlags
}

func init() {
	var module mssqlModule
	_, err := zgrab2.AddCommand("mssql", "MSSQL", "Grab a MSSQL handshake", 1433, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (module *mssqlModule) NewFlags() interface{} {
	return new(mssqlFlags)
}

func (module *mssqlModule) NewScanner() zgrab2.Scanner {
	return new(mssqlScanner)
}

func (flags *mssqlFlags) Validate(args []string) error {
	return nil
}

func (flags *mssqlFlags) Help() string {
	return ""
}

func (scanner *mssqlScanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*mssqlFlags)
	scanner.config = f
	return nil
}

func (scanner *mssqlScanner) InitPerSender(senderID int) error {
	return nil
}

func (scanner *mssqlScanner) GetName() string {
	return scanner.config.Name
}

func (scanner *mssqlScanner) GetPort() uint {
	return scanner.config.Port
}

func (scanner *mssqlScanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	conn, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	sql := NewConnection(conn)
	defer sql.Close()
	result := &mssqlScanResults{}
	_, err = sql.Handshake(scanner.config)

	if sql.tlsConn != nil {
		result.TLSLog = sql.tlsConn.GetLog()
	}

	if sql.preloginOptions != nil {
		result.PreloginOptions = sql.preloginOptions
		version := sql.preloginOptions.GetVersion()
		if version != nil {
			result.Version = fmt.Sprintf("%d.%d.%d", version.Major, version.Minor, version.BuildNumber)
		}
	}

	if err != nil {
		switch err {
		case errNoServerEncryption:
			return zgrab2.SCAN_APPLICATION_ERROR, &result, err
		case errServerRequiresEncryption:
			return zgrab2.SCAN_APPLICATION_ERROR, &result, err
		default:
			return zgrab2.TryGetScanStatus(err), &result, err
		}
	}
	return zgrab2.SCAN_SUCCESS, result, nil
}

// RegisterModule is called by modules/postgres.go's init()
func RegisterModule() {
	var module mssqlModule
	_, err := zgrab2.AddCommand("mssql", "MSSQL", "Grab a mssql handshake", 1433, &module)
	log.SetLevel(log.DebugLevel)
	if err != nil {
		log.Fatal(err)
	}
}

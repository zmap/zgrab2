package modules

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type TLSFlags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
}

type TLSModule struct {
}

type TLSScanner struct {
	config *TLSFlags
}

func init() {
	var tlsModule TLSModule
	_, err := zgrab2.AddCommand("tls", "TLS Banner Grab", "Grab banner over TLS", 443, &tlsModule)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *TLSModule) NewFlags() interface{} {
	return new(TLSFlags)
}

func (m *TLSModule) NewScanner() zgrab2.Scanner {
	return new(TLSScanner)
}

func (f *TLSFlags) Validate(args []string) error {
	return nil
}

func (f *TLSFlags) Help() string {
	return ""
}

func (s *TLSScanner) Init(flags zgrab2.ScanFlags) error {
	f, ok := flags.(*TLSFlags)
	if !ok {
		return zgrab2.ErrMismatchedFlags
	}
	s.config = f
	return nil
}

func (s *TLSScanner) GetName() string {
	return s.config.Name
}

func (s *TLSScanner) InitPerSender(senderID int) error {
	return nil
}

func (s *TLSScanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	tcpConn, err := t.Open(&s.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &zgrab2.TLSLog{}, err
	}
	var conn *zgrab2.TLSConnection
	if conn, err = s.config.TLSFlags.GetTLSConnection(tcpConn); err != nil {
		return zgrab2.TryGetScanStatus(err), &zgrab2.TLSLog{}, err
	}
	result := conn.GetLog()
	if err = conn.Handshake(); err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	return zgrab2.SCAN_SUCCESS, result, nil
}

package modules

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type TLSFlags struct {
	zgrab2.BaseFlags
	Heartbleed           bool `long:"heartbleed" description:"Check if server is vulnerable to Heartbleed"`
	Version              int  `long:"version" description:"Max TLS version to use"`
	Verbose              bool `long:"verbose" description:"Add extra TLS information to JSON output (client hello, client KEX, key material, etc)" json:"verbose"`
	SessionTicket        bool `long:"session-ticket" description:"Send support for TLS Session Tickets and output ticket if presented" json:"session"`
	ExtendedMasterSecret bool `long:"extended-master-secret" description:"Offer RFC 7627 Extended Master Secret extension" json:"extended"`
	ExtendedRandom       bool `long:"extended-random" description:"Send TLS Extended Random Extension" json:"extran"`
	NoSNI                bool `long:"no-sni" description:"Do not send domain name in TLS Handshake regardless of whether known" json:"sni"`
	SCTExt               bool `long:"sct" description:"Request Signed Certificate Timestamps during TLS Handshake" json:"sct"`
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
	f, _ := flags.(*TLSFlags)
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
	return zgrab2.SCAN_SUCCESS, s, nil
}

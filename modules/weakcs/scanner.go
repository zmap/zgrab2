package weakcs

import (
	"errors"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zgrab2"
	"log"
	"slices"
)

var protocolVersions = []string{
	"SSLv3",
	"TLSv1.0",
	"TLSv1.1",
	"TLSv1.2",
	"TLSv1.3",
}

type Flags struct {
	zgrab2.BaseFlags
	ProtocolVersion string `short:"v" long:"protocol-version" default:"SSLv3" description:"protocol version"`
	zgrab2.TLSFlags
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

type Results struct {
	WeakProtocol    bool              `json:"weak_protocol"`
	WeakCipher      bool              `json:"weak_cipher"`
	ProtocolVersion string            `json:"protocol_version"`
	WeakSupportedCS []tls.CipherSuite `json:"weak_supported_cipher_list"`
}

var NoMatchError = errors.New("pattern did not match")

// RegisterModule is called by modules/banner.go to register the scanner.
func RegisterModule() {
	var m Module
	_, err := zgrab2.AddCommand("weakcs", "WeakCS", m.Description(), 443, &m)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a new default flags object.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// GetName returns the Scanner name defined in the Flags.
func (s *Scanner) GetName() string {
	return s.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (s *Scanner) GetTrigger() string {
	return s.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (s *Scanner) Protocol() string {
	return "weakcs"
}

// InitPerSender initializes the scanner for a given sender.
func (s *Scanner) InitPerSender(senderID int) error {
	return nil
}

// NewScanner returns a new Scanner object.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate validates the flags and returns nil on success.
func (f *Flags) Validate(args []string) error {
	ok := slices.Contains(protocolVersions, f.ProtocolVersion)
	if !ok {
		log.Fatalf("ProtocolVersion must be one of %v.", protocolVersions)
		return zgrab2.ErrInvalidArguments
	}
	return nil
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "Fetch a raw banner by sending a static probe and checking the result against a regular expression"
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the command-line flags.
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	//var err error
	f, _ := flags.(*Flags)
	s.config = f
	// sets up config for tls flags
	if s.config.Config == nil {
		//TODO: use the tlsFlags instead of doing this ? See if it works
		s.config.Config = &tls.Config{
			ForceSuites:        true,
			InsecureSkipVerify: true,
			CipherSuites:       zgrab2.GetWeakCSFromProtoVersion(s.config.ProtocolVersion),
			MinVersion:         uint16(0x300 + slices.Index(protocolVersions, s.config.ProtocolVersion)),
			MaxVersion:         uint16(0x300 + slices.Index(protocolVersions, s.config.ProtocolVersion)),
		}
	}
	return nil
}

func (s *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	conn, err := target.OpenTLS(&s.config.BaseFlags, &s.config.TLSFlags)

	if conn == nil || err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	} else {
		defer conn.Close()
	}

	var results Results

	if hsLog := conn.GetHandshakeLog(); hsLog != nil {
		if serverHello := hsLog.ServerHello; serverHello != nil {
			weakSupportedCS := serverHello.CipherSuite
			results.WeakProtocol = s.config.ProtocolVersion != "TLSv1.2" && s.config.ProtocolVersion != "TLSv1.3"
			results.WeakCipher = true
			results.WeakSupportedCS = append(results.WeakSupportedCS, weakSupportedCS)
			results.ProtocolVersion = s.config.ProtocolVersion
			return zgrab2.SCAN_SUCCESS, results, nil
		}
	}
	return zgrab2.SCAN_SUCCESS, nil, NoMatchError
}

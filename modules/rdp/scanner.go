package rdp

import (
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/nmap"
)

type ScanResults struct {
	Banner        []byte               `json:"banner,omitempty"`
	ProtocolFlags []string             `json:"protocol_flags,omitempty"`
	NTLMInfo      NTLMInfo             `json:"ntlm_info,omitempty"`
	TLSLog        *zgrab2.TLSLog       `json:"tls_log,omitempty"`
	Products      []nmap.ExtractResult `json:"products,omitempty"`
}

type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	ProductMatchers string `long:"product-matchers" default:"*/ms-wbt-server" description:"Matchers from nmap-service-probes file used to detect product info. Format: <probe>/<service>[,...] (wildcards supported)."`
}

type Scanner struct {
	config          *Flags
	productMatchers nmap.Matchers
}

type Module struct{}

func (module *Module) NewFlags() interface{} {
	return &Flags{}
}

func (module *Module) NewScanner() zgrab2.Scanner {
	return &Scanner{}
}

func (module *Module) Description() string {
	return "Fetch RDP banners"
}

func (flags *Flags) Validate(_ []string) error {
	return nil
}

func (flags *Flags) Help() string {
	return ""
}

func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.productMatchers = nmap.SelectMatchersGlob(f.ProductMatchers)
	return nil
}

func (scanner *Scanner) InitPerSender(_ int) error {
	return nil
}

func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

func (scanner *Scanner) Protocol() string {
	return "rdp"
}

func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("rdp", "rdp", module.Description(), 3389, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	c, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, errors.Wrap(err, "error target.Open")
	}
	//goland:noinspection GoUnhandledErrorResult
	defer c.Close()

	rdpConn := connection{
		regularConn: c,
	}

	banner, err := rdpConn.initAndGetBanner()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, errors.Wrap(err, "error rdpConn.initAndGetBanner")
	}

	result := ScanResults{Banner: banner}
	result.Products, err = scanner.productMatchers.ExtractInfoFromBytes(banner)
	if err != nil {
		log.Println(err)
	}

	answer := newFirstAnswer(banner)
	if !answer.IsRDP {
		return zgrab2.SCAN_PROTOCOL_ERROR, &result, errors.Errorf("not rdp protocol")
	}

	result.ProtocolFlags = answer.ProtocolFlags

	if !answer.CanPerformTLS {
		return zgrab2.SCAN_SUCCESS, &result, nil
	}

	tlsConn, err := scanner.config.TLSFlags.GetTLSConnection(c)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &result, errors.Wrap(err, "error TLSFlags.GetTLSConnection")
	}

	tlsLog, err := rdpConn.setTLSConnectionAndGetTLSLog(tlsConn)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &result, errors.Wrap(err, "rdpConn.setTLSConnectionAndGetTLSLog")
	}

	result.TLSLog = tlsLog

	rdpNTLMInfo, err := rdpConn.getNTLMInfo()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &result, errors.Wrap(err, "error rdpConn.getNTLMInfo")
	}

	result.NTLMInfo = rdpNTLMInfo

	return zgrab2.SCAN_SUCCESS, &result, nil
}

package dicom

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/zmap/zgrab2"
)

type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags

	CallingAETitle string `long:"calling-ae-title" description:"Source DICOM Application Name. 16bytes max."`
	CalledAETitle  string `long:"called-ae-title" description:"Destination DICOM Application Name. 16bytes max."`

	RetryTLS bool `long:"retry-tls" description:"retry the connection now over TLS"`
	UseTLS   bool `long:"use-tls" description:"force TLS handshake"`
}

// Validate performs any needed validation on the arguments
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns module-specific help
func (flags *Flags) Help() string {
	return ""
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// NewScanner returns a new instance Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return `This module sends a DICOM A-ASSOCIATION-RQ and a C-ECHO-RQ.`
}

type Result struct {
	ScanResults []*ScanResult `json:"scan_result"`
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config            *Flags
	builder           *ScanBuilder
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

// Protocol returns the protocol identifer for the scanner.
func (scanner *Scanner) Protocol() string {
	return "DICOM"
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	fl, _ := flags.(*Flags)
	scanner.config = fl
	scanner.builder = NewScanBuilder(scanner)

	scanner.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		NeedSeparateL4Dialer:            true,
		BaseFlags:                       &fl.BaseFlags,
		TLSEnabled:                      fl.UseTLS,
		TLSFlags:                        &fl.TLSFlags,
	}
	return nil
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// NewFlags returns an empty Flags object.
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

func (s *Scanner) scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, t *zgrab2.ScanTarget, scheme string) (zgrab2.ScanStatus, interface{}, error) {
	scan := s.builder.Build(ctx, dialGroup, t, scheme)
	if err := scan.Grab(); err != nil {
		return err.Unpack(scan.result)
	}
	return zgrab2.SCAN_SUCCESS, scan.result, nil
}

func (s *Scanner) getRetryIterator() []string {
	var schemes []string
	var base string
	switch {
	case s.config.UseTLS:
		base = "ssl"
	default:
		base = "tcp"
	}

	schemes = append(schemes, base)
	if s.config.RetryTLS && !s.config.UseTLS {
		schemes = append(schemes, "ssl")
	}
	return schemes
}

func (s *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, t *zgrab2.ScanTarget) (status zgrab2.ScanStatus, results interface{}, err error) {
	schemes := s.getRetryIterator()
	for _, scheme := range schemes {
		if status, results, err = s.scan(ctx, dialGroup, t, scheme); status == zgrab2.SCAN_SUCCESS {
			return
		}
	}
	return
}

// RegisterModule is called by modules/mqtt.go to register this module with the
// zgrab2 framework.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("dicom-echo", "DICOM Banner Grab", module.Description(), 104, &module)
	if err != nil {
		log.Fatal(err)
	}
}

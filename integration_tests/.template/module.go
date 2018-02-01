package modules

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// #{MODULE_NAME}ScanResults is the output of the scan.
type #{MODULE_NAME}ScanResults struct {
	// TODO: Add protocol

	// Protocols that support TLS should include
	// TLSLog      *zgrab2.TLSLog `json:"tls,omitempty"`
}

// #{MODULE_NAME}-specific command-line flags.
type #{MODULE_NAME}Flags struct {
	zgrab2.BaseFlags
	// TODO: Add more protocol-specific flags
	// Protocols that support TLS should include zgrab2.TLSFlags

	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// #{MODULE_NAME}Module implements the zgrab2.Module interface
type #{MODULE_NAME}Module struct {
	// TODO: Add any module-global state
}

// #{MODULE_NAME}Scanner implements the zgrab2.Scanner interface
type #{MODULE_NAME}Scanner struct {
	config *#{MODULE_NAME}Flags
	// TODO: Add scan state
}

// #{MODULE_NAME}.init() registers the zgrab2 module
func init() {
	var module #{MODULE_NAME}Module
	// FIXME: Set default port
	_, err := zgrab2.AddCommand("#{MODULE_NAME}", "#{MODULE_NAME}", "Probe for #{MODULE_NAME}", FIXME_DEFAULT_PORT, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *#{MODULE_NAME}Module) NewFlags() interface{} {
	return new(#{MODULE_NAME}Flags)
}

func (m *#{MODULE_NAME}Module) NewScanner() zgrab2.Scanner {
	return new(#{MODULE_NAME}Scanner)
}

func (f *#{MODULE_NAME}Flags) Validate(args []string) error {
	return nil
}

func (f *#{MODULE_NAME}Flags) Help() string {
	return ""
}

func (s *#{MODULE_NAME}Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*#{MODULE_NAME}Flags)
	s.config = f
	return nil
}

func (s *#{MODULE_NAME}Scanner) InitPerSender(senderID int) error {
	return nil
}

func (s *#{MODULE_NAME}Scanner) GetName() string {
	return s.config.Name
}

func (s *#{MODULE_NAME}Scanner) GetPort() uint {
	return s.config.Port
}

// #{MODULE_NAME}Scanner.Scan() TODO: describe what is scanned
func (s *#{MODULE_NAME}Scanner) Scan(t zgrab2.ScanTarget) (status zgrab2.ScanStatus, result interface{}, thrown error) {
	// TODO: implement
	return zgrab2.SCAN_UNKNOWN_ERROR, nil, nil
}

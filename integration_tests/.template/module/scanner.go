package #{MODULE_NAME}

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// #{EXPORTED_MODULE_NAME}ScanResults is the output of the scan.
type #{EXPORTED_MODULE_NAME}ScanResults struct {
	// TODO: Add protocol

	// Protocols that support TLS should include
	// TLSLog      *zgrab2.TLSLog `json:"tls,omitempty"`
}

// #{EXPORTED_MODULE_NAME}-specific command-line flags.
type #{EXPORTED_MODULE_NAME}Flags struct {
	zgrab2.BaseFlags
	// TODO: Add more protocol-specific flags
	// Protocols that support TLS should include zgrab2.TLSFlags

	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// #{EXPORTED_MODULE_NAME}Module implements the zgrab2.Module interface
type #{EXPORTED_MODULE_NAME}Module struct {
	// TODO: Add any module-global state
}

// #{EXPORTED_MODULE_NAME}Scanner implements the zgrab2.Scanner interface
type #{EXPORTED_MODULE_NAME}Scanner struct {
	config *#{MODULE_NAME}Flags
	// TODO: Add scan state
}

// #{EXPORTED_MODULE_NAME}.init() registers the zgrab2 module
func init() {
	var module #{EXPORTED_MODULE_NAME}Module
	// FIXME: Set default port
	_, err := zgrab2.AddCommand("#{MODULE_NAME}", "#{FRIENDLY_MODULE_NAME}", "Probe for #{FRIENDLY_MODULE_NAME}", FIXME_DEFAULT_PORT, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (module *#{EXPORTED_MODULE_NAME}Module) NewFlags() interface{} {
	return new(#{EXPORTED_MODULE_NAME}Flags)
}

func (module *#{EXPORTED_MODULE_NAME}Module) NewScanner() zgrab2.Scanner {
	return new(#{EXPORTED_MODULE_NAME}Scanner)
}

func (flags *#{EXPORTED_MODULE_NAME}Flags) Validate(args []string) error {
	return nil
}

func (flags *#{MODULE_NAME}Flags) Help() string {
	return ""
}

func (scanner *#{EXPORTED_MODULE_NAME}Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*#{EXPORTED_MODULE_NAME}Flags)
	scanner.config = f
	return nil
}

func (scanner *#{EXPORTED_MODULE_NAME}Scanner) InitPerSender(senderID int) error {
	return nil
}

func (scanner *#{EXPORTED_MODULE_NAME}Scanner) GetName() string {
	return s.config.Name
}

func (scanner *#{EXPORTED_MODULE_NAME}Scanner) GetPort() uint {
	return s.config.Port
}

// #{EXPORTED_MODULE_NAME}Scanner.Scan() TODO: describe what is scanned
func (scanner *#{EXPORTED_MODULE_NAME}Scanner) Scan(t zgrab2.ScanTarget) (status zgrab2.ScanStatus, result interface{}, thrown error) {
	// TODO: implement
	return zgrab2.SCAN_UNKNOWN_ERROR, nil, nil
}

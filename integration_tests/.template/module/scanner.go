// Package #{MODULE_NAME} provides a zgrab2 module that proves for #{MODULE_NAME}.
// TODO: Describe module, the flags, the probe, the output, etc.
package #{MODULE_NAME}

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// ScanResults is the output of the scan.
type ScanResults struct {
	// TODO: Add protocol

	// Protocols that support TLS should include
	// TLSLog      *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Flags is #{MODULE_NAME}-specific command-line flags.
type Flags struct {
	zgrab2.BaseFlags
	// TODO: Add more protocol-specific flags
	// Protocols that support TLS should include zgrab2.TLSFlags

	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// Module implements the zgrab2.Module interface
type Module struct {
	// TODO: Add any module-global state
}

// Scanner implements the zgrab2.Scanner interface
type Scanner struct {
	config *Flags
	// TODO: Add scan state
}

// RegisterModule() registers the zgrab2 module
func RegisterModule() {
	var module Module
	// FIXME: Set default port
	_, err := zgrab2.AddCommand("#{MODULE_NAME}", "#{MODULE_NAME}", "Probe for #{MODULE_NAME}", FIXME_DEFAULT_PORT, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags provides an empty instance of the flags that will be filled in by the framework
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner provides a new scanner instance
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate checks that the flags are valid
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string
func (flags *Flags) Help() string {
	return ""
}

// Init initializes the scanner
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	return nil
}

// InitPerSender initializes the scanner for a given sender
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the name of the scanner
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetPort returns the port being scanned
func (scanner *Scanner) GetPort() uint {
	return scanner.config.Port
}

// Scan() TODO: describe what is scanned
func (scanner *Scanner) Scan(t zgrab2.ScanTarget) (status zgrab2.ScanStatus, result interface{}, thrown error) {
	// TODO: implement
	return zgrab2.SCAN_UNKNOWN_ERROR, nil, nil
}

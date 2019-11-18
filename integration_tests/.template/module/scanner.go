// Package #{MODULE_NAME} provides a zgrab2 module that scans for #{MODULE_NAME}.
// TODO: Describe module, the flags, the probe, the output, etc.
package #{MODULE_NAME}

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	// TODO: Add protocol

	// Protocols that support TLS should include
	// TLSLog      *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Flags holds the command-line configuration for the #{MODULE_NAME} scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	// TODO: Add more protocol-specific flags
	// Protocols that support TLS should include zgrab2.TLSFlags

	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
	// TODO: Add any module-global state
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
	// TODO: Add scan state
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	// FIXME: Set default port
	_, err := zgrab2.AddCommand("#{MODULE_NAME}", "#{MODULE_NAME}", "Probe for #{MODULE_NAME}", FIXME_DEFAULT_PORT, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object.
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string.
func (flags *Flags) Help() string {
	return ""
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
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

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "#{MODULE_NAME}"
}

// Scan TODO: describe what is scanned
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	conn, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()
	// TODO: implement
	return zgrab2.SCAN_UNKNOWN_ERROR, nil, nil
}

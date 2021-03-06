// Package fox provides a zgrab2 module that scans for fox.
// Default port: 1911 (TCP)
//
// Copied unmodified from the original zgrab.
// Connects, sends a static query, and reads the banner. Parses out as much of the response as possible.
package fox

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the fox scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags

	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("fox", "fox", module.Description(), 1911, &module)
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

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Probe for Tridium Fox"
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
	return "fox"
}

// Scan probes for a Tridium Fox service.
// 1. Opens a TCP connection to the configured port (default 1911)
// 2. Sends a static query
// 3. Attempt to read the response (up to 8k + 4 bytes -- larger responses trigger an error)
// 4. If the response has the Fox response prefix, mark the scan as having detected the service.
// 5. Attempt to read any / all of the data fields from the Log struct
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	conn, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()
	result := new(FoxLog)

	err = GetFoxBanner(result, conn)
	if !result.IsFox {
		result = nil
		err = &zgrab2.ScanError{
			Err:    errors.New("host responds, but is not a fox service"),
			Status: zgrab2.SCAN_PROTOCOL_ERROR,
		}
	}
	return zgrab2.TryGetScanStatus(err), result, err
}

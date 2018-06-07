// Package ipp provides a zgrab2 module that scans for ipp.
// TODO: Describe module, the flags, the probe, the output, etc.
package ipp

import (
	//"bytes"
	//"errors"
	"io"
	//"net"
	//"net/url"
	//"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

//TODO: Tag relevant results and exlain in comments
// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	// TODO: Add protocol
	//TODO: Explain Protocol Version
	ProtocolVersion int16 `json:"version"`
	ServerVersion string `json:"version_string"`

	//TODO: Explain CUPS-Version
	CUPSVersion string `json:"cups_version,omitempty"`

	//TODO: Uncomment this when implementing the TLS version of things
	// Protocols that support TLS should include
	// TLSLog      *zgrab2.TLSLog `json:"tls,omitempty"`
}

//FIXME: We don't need this.
func readResultsFromResponseBody(body *io.ReadCloser) *ScanResults {
	return &ScanResults{}
}

// TODO: Add more protocol-specific flags
// Flags holds the command-line configuration for the ipp scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	//TODO: Include once TLS is implemented
	// Protocols that support TLS should include zgrab2.TLSFlags

	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

//TODO: Figure out what moduel-global state may be necessary
// Module implements the zgrab2.Module interface.
type Module struct {
	// TODO: Add any module-global state
}

//TODO: Figure out what scan state may be necessary
// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
	// TODO: Add scan state
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("ipp", "ipp", "Probe for ipp", 631, &module)
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
	//TODO: Write a help string
	return ""
}

//TODO: Implement
// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	//TODO: Take action in response to flags which were set
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

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "ipp"
}

// GetPort returns the port being scanned.
func (scanner *Scanner) GetPort() uint {
	return scanner.config.Port
}

// Scan TODO: describe what is scanned
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	conn, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()
	// TODO: implement
	
	//FIXME: Dummy result currently, replace with an actual result assignment
	result := map[string]string{
		"test_key": "FIXME: Remove this",
	}
	return zgrab2.SCAN_SUCCESS, &result, nil
}

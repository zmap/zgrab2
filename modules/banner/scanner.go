// Package banner provides simple banner grab and matching implementation of the zgrab2.Module.
// It sends a customizble probe (default to "\n") and filters the results based on a custom regexp (--pattern)

package banner

import (
	"errors"
	"io"
	"log"
	"regexp"
	"strings"

	"github.com/zmap/zgrab2"
)

// Flags give the command-line flags for the banner module.
type Flags struct {
	zgrab2.BaseFlags
	Probe   string `long:"probe" default:"\n" description:"Probe to send to the server."`
	Pattern string `long:"pattern" description:"Pattern to match, must be valid regexp."`
}

// Module is the implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
	regex  *regexp.Regexp
}

type Results struct {
	Banner string `json:"banner,omitempty"`
	Length int    `json:"length,omitempty"`
}

// RegisterModule is called by modules/banner.go to register the scanner.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("banner", "Banner", "Grab banner by sending probe and match with regexp", 80, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a new default flags object.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
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
	return "banner"
}

// GetPort returns the port being scanned.
func (scanner *Scanner) GetPort() uint {
	return scanner.config.Port
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// NewScanner returns a new Scanner object.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate validates the flags and returns nil on success.
func (f *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the command-line flags.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	scanner.regex = regexp.MustCompile(scanner.config.Pattern)
	return nil
}

var NoMatchError = errors.New("pattern did not match")

func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	conn, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer conn.Close()
	r := strings.NewReplacer(`\n`, "\n", `\r`, "\r", `\t`, "\t")
	probe := r.Replace(scanner.config.Probe)
	conn.Write([]byte(probe))
	ret, err := zgrab2.ReadAvailable(conn)
	if err != io.EOF && err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	results := Results{Banner: string(ret), Length: len(ret)}
	if scanner.regex.Match(ret) {
		return zgrab2.SCAN_SUCCESS, &results, nil
	}

	return zgrab2.SCAN_PROTOCOL_ERROR, &results, NoMatchError

}

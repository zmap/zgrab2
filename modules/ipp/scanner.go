// Package ipp provides a zgrab2 module that scans for ipp.
// TODO: Describe module, the flags, the probe, the output, etc.
package ipp

//TODO: Clean up these imports
import (
	//"bytes"
	"encoding/binary"
	//"errors"
	"io"
	"net/http"
	"strconv"
	//"net"
	//"net/url"
	//"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

//TODO: Tag relevant results and exlain in comments
// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	Response *http.Response `json:"response,omitempty"`

	MajorVersion int8 `json:"major_version"`
	MinorVersion int8 `json:"minor_version"`

	Version string `json:"version_string,omitempty"`
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
	//FIXME: Borrowed from http module
	MaxSize int `long:"max-size" default:"256" description:"Max kilobytes to read in response to an HTTP request"`
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

//FIXME: Maybe switch to ipp/ipps schemes, at least optionally
//FIXME: Stolen from http module, which isn't a good practice
func getIPPURL(https bool, host string, port uint16, endpoint string) string {
	var proto string
	if https {
		proto = "https"
	} else {
		proto = "http"
	}
	return proto + "://" + host + ":" + strconv.FormatUint(uint64(port), 10) + endpoint
}

//TODO: Doesn't support TLS at all right now
func (scanner *Scanner) grab(target zgrab2.ScanTarget) (int8, int8, *zgrab2.ScanError) {
	//FIXME: This is not where this hostname assignment logic should live
	host := target.Domain
	if host == "" {
		host = target.IP.String()
	}
	//TODO: Make https bool depend on scanner's config
	//TODO: ?Shouldn't put any endpoint, since we get the same response w/o on CUPS??
	uri := getIPPURL(false, host, uint16(scanner.config.BaseFlags.Port), "/ipp")
	b := getPrinterAttributesRequest(uri)
	resp, err := http.Post(uri, "application/ipp", &b)
	if err != nil {
		//FIXME: Create a descriptive error
		return 0, 0, zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
	}
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	} else {
		//FIXME: Determine whether we need this error to avoid reading from Body
		return 0, 0, zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
	}
	//FIXME: Maybe add something to handle redirects
	//FIXME: Probably return the whole response for further inspection, rather
	//         than grabbing first 2 bytes. In that case, probs instate maxRead like http
	//FIXME: Check to make sure that the response is actually IPP
	var version int16
	if err := binary.Read(resp.Body, binary.BigEndian, &version); err != nil {
		return 0, 0, zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
	}
	return int8(version >> 8), int8(version & 0xff), nil
}

// Scan TODO: describe how scan operates
//1. FIXME: Don't open connection, because we don't need it?
//2. Send something (currently get-printer-attributes)
//3. Take in that response & read out version numbers
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	// TODO: implement
	major, minor, err := scanner.grab(target)
	//FIXME: Triggering even though error IS nil
	//FIXME: This is a sloppy bodge to handle the issue, since you must know implementation details below you
	if major == 0 && minor == 0 && err != nil {
		//TODO: Consider mimicking HTTP Scan's retryHTTPS functionality
		//TODO: Create relevant error, or send something more descriptive?
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	results := &ScanResults{}
	results.MajorVersion = major
	results.MinorVersion = minor
	return zgrab2.SCAN_SUCCESS, results, nil
}

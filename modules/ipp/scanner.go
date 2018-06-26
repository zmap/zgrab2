// Package ipp provides a zgrab2 module that scans for ipp.
// TODO: Describe module, the flags, the probe, the output, etc.
package ipp

//TODO: Clean up these imports
import (
	//"bytes"
	"encoding/binary"
	//"errors"
	//"fmt"
	//"io"
	"net/http"
	"strconv"
	"strings"
	//"net"
	//"net/url"
	//"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

const (
	ContentType string = "application/ipp"
)

//TODO: Tag relevant results and exlain in comments
// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	//TODO: ?Include the request sent as well??
	//TODO: Include a full response or at least a blob in the data (at least in verbose mode)
	//Response *http.Response `json:"response,omitempty"`

	MajorVersion int8 `json:"version_major"`
	MinorVersion int8 `json:"version_minor"`

	VersionString string `json:"version_string,omitempty"`
	CUPSVersion   string `json:"cups_version,omitempty"`

	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// TODO: Annotate every flag thoroughly
// TODO: Add more protocol-specific flags as needed
// Flags holds the command-line configuration for the ipp scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	//FIXME: Borrowed from http module
	MaxRead int `long:"max-size" default:"256" description:"Max kilobytes to read in response to an HTTP request"`
	// TODO: Protocols that support TLS should include zgrab2.TLSFlags (do once implemented)
	// TODO: Maybe implement both an ipps connection and upgrade to https
	IPPSecure bool `long:"ipps" description:"Perform a TLS handshake immediately upon connecting."`

	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
	// TODO: Add any module-global state if necessary
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
	// TODO: Add scan state if any is necessary
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

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
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
func getIPPURL(https bool, host string, port uint16, endpoint string) string {
	var proto string
	if https {
		proto = "https"
	} else {
		proto = "http"
	}
	return proto + "://" + host + ":" + strconv.FormatUint(uint64(port), 10) + endpoint
}

// FIXME: Ensure that an actual content type is being used with some library
func ippInContentType(resp http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), ContentType)
}

// FIXME: Change to instead return (*ScanResults, *zgrab2.ScanError)
// TODO: Doesn't support TLS at all right now
func (scanner *Scanner) grab(target zgrab2.ScanTarget) (int8, int8, *zgrab2.ScanError) {
	//FIXME: This is not where this hostname assignment logic should live
	host := target.Domain
	if host == "" {
		host = target.IP.String()
	}
	//FIXME: ?Should just use endpoint "/", since we get the same response as "/ipp" on CUPS??
	uri := getIPPURL(scanner.config.IPPSecure, host, uint16(scanner.config.BaseFlags.Port), "/ipp")
	b := getPrinterAttributesRequest(uri)

	resp, err := http.Post(uri, ContentType, &b)
	if err != nil {
		return 0, 0, zgrab2.DetectScanError(err)
	}
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	} else {
		// FIXME: Is empty body allowed in IPP?
		// Cite RFC!!
		// Empty body is not allowed in valid IPP
		return 0, 0, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, nil)
	}

	// FIXME: Maybe add something to handle redirects
	// FIXME: Probably return the whole response for further inspection by ztag, rather
	//         than grabbing first 2 bytes. In that case, implement maxRead like http module

	//Check to make sure that the repsonse received is actually IPP
	//Content-Type header matches is sufficient
	//HTTP on port 631 is sufficient
	//Still record data in the case of protocol error to see what that data looks like

	// TODO: Record server-header version numbers
	//protocols := resp.Header.Get("Server")
	// TODO: Change this to perform two separate binary.Reads
	var version uint16
	// TODO: Determine whether errors other than protocol (ie: too few bytes) can be triggered here
	if err := binary.Read(resp.Body, binary.BigEndian, &version); err != nil {
		// FIXME: Determine whether sending fewer than 2 bytes is a protocol or application error
		// I believe it's protocol, since the version must be specified (iirc)
		// FIXME: Cite RFC!!
		return 0, 0, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, err)
	}
	// Returns signed integers because "every integer MUST be encoded as a signed integer"
	// (Source: https://tools.ietf.org/html/rfc8010#section-3)
	return int8(version >> 8), int8(version & 0xff), nil
}

// Scan TODO: describe how scan operates
//1. Send a request (currently get-printer-attributes)
//2. Take in that response & read out version numbers
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	// TODO: use Connection again, at least when implementing TLS
	major, minor, err := scanner.grab(target)
	results := &ScanResults{}
	results.MajorVersion = major
	results.MinorVersion = minor
	// FIXME: Triggering even though error IS nil
	// FIXME: This is a sloppy bodge to handle the issue
	if major == 0 && minor == 0 && err != nil {
		// TODO: Consider mimicking HTTP Scan's retryHTTPS functionality
		return zgrab2.TryGetScanStatus(err), results, err
	}
	return zgrab2.SCAN_SUCCESS, results, nil
}

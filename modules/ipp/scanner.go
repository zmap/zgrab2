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
	"mime"
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
	Response *http.Response `json:"response,omitempty" zgrab:"debug"`

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
	zgrab2.TLSFlags
	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`

	//FIXME: Borrowed from http module
	MaxSize int `long:"max-size" default:"256" description:"Max kilobytes to read in response to an IPP request"`
	MaxRedirects int    `long:"max-redirects" default:"0" description:"Max number of redirects to follow"`

	// FIXME: Should just be called HTTPS?
	// TODO: Maybe separately implement both an ipps connection and upgrade to https
	IPPSecure bool `long:"ipps" description:"Perform a TLS handshake immediately upon connecting."`
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

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "ipp"
}

// GetPort returns the port being scanned.
func (scanner *Scanner) GetPort() uint {
	return scanner.config.Port
}

// FIXME: Maybe switch to ipp/ipps schemes, at least optionally
func getIPPURI(https bool, host string, port uint16, endpoint string) string {
	var proto string
	if https {
		proto = "https"
	} else {
		proto = "http"
	}
	return proto + "://" + host + ":" + strconv.FormatUint(uint64(port), 10) + endpoint
}

func ippInContentType(resp http.Response) (bool, error) {
	// TODO: See if capturing parameters gets anything interesting in scan
	// Parameters can be ignored, since there are no required or optional parameters
	// IPP parameters specified at https://www.iana.org/assignments/media-types/application/ipp
	mediatype, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	// FIXME: See if empty media type is sufficient,
	// there could be other states where reading mediatype screwed up, but isn't empty (ie: corrupted)
	if mediatype == "" && err != nil {
		//TODO: Handle errors in a weird way, since media type is still returned
		//      if error when parsing optional parameters
		return false, err
	}
	return mediatype == ContentType, nil
}

// TODO: Rework errors so that a partial scan is possible. If one field isn't present, just skip it.
//       If something prevents other fields, then skip all such fields.
// TODO: Doesn't support TLS at all right now
func (scanner *Scanner) grab(target zgrab2.ScanTarget) (*ScanResults, *zgrab2.ScanError) {
	// FIXME: This is not where this hostname assignment logic should live
	//        Occurs when configuring HTTPscan object in http module, we don't need that weight
	host := target.Domain
	if host == "" {
		// FIXME: I only know this works for sure for IPv4, uri string might get weird w/ IPv6
		host = target.IP.String()
	}
	// FIXME: ?Should just use endpoint "/", since we get the same response as "/ipp" on CUPS??
	uri := getIPPURI(scanner.config.IPPSecure, host, uint16(scanner.config.BaseFlags.Port), "/ipp")
	body := getPrinterAttributesRequest(uri)

	// FIXME: Consider setting "Allow: */*" in the headers of request
	resp, err := http.Post(uri, ContentType, body)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	} else {
		// FIXME: Is empty body allowed in IPP?
		// Cite RFC!!
		// Empty body is not allowed in valid IPP
		// TODO: Return whatever response we got, if any, and then return error denoting empty body
		// b/c resp == nil or Body == nil
		return nil, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, nil)
	}
	if err != nil {
		// FIXME: Maybe only return with failure here if err != nil && resp == nil, b/c otherwise we have a response
		return nil, zgrab2.DetectScanError(err)
	}
	result := &ScanResults{}
	result.Response = resp
	protocols := strings.Split(resp.Header.Get("Server"), " ")
	for _, p := range protocols {
		// TODO: Determine whether these Server items will always be formatted in all caps
		// (seems like there's no standard)
		if strings.HasPrefix(p, "IPP/") {
			result.VersionString = p[4:]
		}
		if strings.HasPrefix(p, "CUPS/") {
			result.CUPSVersion = p[5:]
		}
	}

	// FIXME: Maybe add something to handle redirects
	// FIXME: Probably return the whole response for further inspection by ztag, rather
	//        than grabbing first 2 bytes. In that case, implement maxRead like http module

	//Check to make sure that the repsonse received is actually IPP
	//Content-Type header matches is sufficient
	//HTTP on port 631 is sufficient
	//Still record data in the case of protocol error to see what that data looks like

	// Returns signed integers because "every integer MUST be encoded as a signed integer"
	// (Source: https://tools.ietf.org/html/rfc8010#section-3)
	var major, minor int8

	// TODO: Determine whether errors other than protocol (ie: too few bytes) can be triggered here
	if err := binary.Read(resp.Body, binary.BigEndian, &major); err != nil {
		// FIXME: Determine whether sending fewer than 2 bytes is a protocol or application error
		// I believe it's protocol, since the version must be specified (iirc)
		// FIXME: Cite RFC!!
		// Resolve if block below if resolved here
		return nil, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, err)
	}
	if err := binary.Read(resp.Body, binary.BigEndian, &minor); err != nil {
		// FIXME: Address the same concerns as in previous if block
		return nil, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, err)
	}
	result.MajorVersion = major
	result.MinorVersion = minor
	return result, nil
}

// Scan TODO: describe how scan operates in appropriate detail
//1. Send a request (currently get-printer-attributes)
//2. Take in that response & read out version numbers
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	// TODO: use Connection again, at least when implementing TLS?
	results, err := scanner.grab(target)
	if err != nil {
		// TODO: Consider mimicking HTTP Scan's retryHTTPS functionality
		return zgrab2.TryGetScanStatus(err), results, err
	}
	return zgrab2.SCAN_SUCCESS, results, nil
}

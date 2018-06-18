// Package ipp provides a zgrab2 module that scans for ipp.
// TODO: Describe module, the flags, the probe, the output, etc.
package ipp

//TODO: Clean up these imports
import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	//"fmt"
	"io"
	"mime"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http"
)

const (
	ContentType string = "application/ipp"
	VersionsSupported string = "ipp-versions-supported"
	CupsVersion string = "cups-version"
	PrinterURISupported string = "printer-uri-supported"
)

var (
	// ErrRedirLocalhost is returned when an HTTP redirect points to localhost,
	// unless FollowLocalhostRedirects is set.
	ErrRedirLocalhost = errors.New("Redirecting to localhost")

	// ErrTooManyRedirects is returned when the number of HTTP redirects exceeds
	// MaxRedirects.
	ErrTooManyRedirects = errors.New("Too many redirects")
)

// FIXME: Pared down from http module, might not need all of this
type scan struct {
	connections []net.Conn
	// NOTE: Transport is the same between our & standard http library
	transport *http.Transport
	// NOTE: Client adds UserAgent member and response argument to CheckRedirect
	client  *http.Client
	// FIXME: Figure out whether there's a good reason to have this by value other than not initializing it manually and not checking for nil-ness
	results *ScanResults
	url     string
}

//TODO: Tag relevant results and exlain in comments
// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	//TODO: ?Include the request sent as well??
	Response *http.Response `json:"response,omitempty" zgrab:"debug"`

	// RedirectResponseChain is non-empty if the scanner follows a redirect.
	// It contains all redirect responses prior to the final response.
	RedirectResponseChain []*http.Response `json:"redirect_response_chain,omitempty" zgrab:"debug"`

	// TODO: These should be pointers to int, so that they can be nil when not found, rather than 0.0
	// TODO: Maybe these should also be omitempty. They don't have to exist.
	MajorVersion *int8 `json:"version_major,omitempty"`
	MinorVersion *int8 `json:"version_minor,omitempty"`

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
	MaxSize      int    `long:"max-size" default:"256" description:"Max kilobytes to read in response to an IPP request"`
	MaxRedirects int    `long:"max-redirects" default:"0" description:"Max number of redirects to follow"`
	UserAgent    string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent"`
	RetryTLS   bool   `long:"retry-tls" description:"If the initial request fails, reconnect and try with HTTPS."`

	//TODO: Figure out whether we need to have this?
	// FollowLocalhostRedirects overrides the default behavior to return
	// ErrRedirLocalhost whenever a redirect points to localhost.
	FollowLocalhostRedirects bool `long:"follow-localhost-redirects" description:"Follow HTTP redirects to localhost"`

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

// This doesn't use ipp(s) scheme, because http doesn't recognize them, so we need http scheme
// We convert as needed later in convertURIToIPP
func getHTTPURL(https bool, host string, port uint16, endpoint string) string {
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
	// FIXME: See if empty media type is sufficient as failure indicator,
	// there could be other states where reading mediatype screwed up, but isn't empty (ie: corrupted)
	if mediatype == "" && err != nil {
		//TODO: Handle errors in a weird way, since media type is still returned
		//      if there's an error when parsing optional parameters
		return false, err
	}
	// FIXME: Maybe pass the error along, maybe not. We got what we wanted.
	return mediatype == ContentType, nil
}

// TODO: Refactor to more-generically determine whether a protocol is present in the Server header
func isCUPS(resp *http.Response) bool {
	// FIXME: This is largely copied and pasted from within Grab()
	protocols := strings.Split(resp.Header.Get("Server"), " ")
	for _, p := range protocols {
		if strings.HasPrefix(p, "CUPS/") {
			return true
		}
	}
	return false
}

// FIXME: Take in something other than string as body, like bytes.Buffer of []byte
// FIXME: Genericize this if possible, should be able to return different things?
// FIXME: add proper error handling here
func readAttributeFromBody(attr string, body *string) (*[]byte, error) {
	index := strings.Index(*body, attr)
	if index != -1 {
		//valueTag := body[index - 3]
		buf := bytes.NewBuffer([]byte((*body)[index:]))
		ignore := make([]byte, len(attr))
		if err := binary.Read(buf, binary.BigEndian, &ignore); err != nil {
			//Read in attribute-name failed
			return nil, err
		}
		var length int16
		if err := binary.Read(buf, binary.BigEndian, &length); err != nil {
			//Length of content wasn't even read
			return nil, err
		}
		val := make([]byte, length)
		if err := binary.Read(buf, binary.BigEndian, &val); err != nil {
			//Content was not successfully read.
			return nil, err
		}
		return &val, nil
	}
	return nil, errors.New("Specified attribute not present.")
}

func (scanner *Scanner) Grab(scan *scan, target *zgrab2.ScanTarget) *zgrab2.ScanError {
	body := getPrinterAttributesRequest(scan.url)
	request, err := http.NewRequest("POST", scan.url, body)
	if err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
	}
	request.Header.Set("Accept", "*/*")
	request.Header.Set("Content-Type", ContentType)
	resp, err := scan.client.Do(request)
	//Store response regardless of error in request, because you may have gotten something back
	scan.results.Response = resp
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	} else {
		// resp == nil || resp.Body == nil
		// Empty response/body is not allowed in IPP because a response has required parameter
		// Source: RFC 8011 Section 4.1.1 https://tools.ietf.org/html/rfc8011#section-4.1.1
		// Still returns the response, if any, because assignment occurs before this else block
		// TODO: Examine whether an empty response overall is a protocol error, I'd think of it as another kind of error entirely,
		//       and later conditions might handle that case; see RFC 8011 Section 4.2.5.2?
		return zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, nil)
	}
	if err != nil {
		//If error is a url.Error (a struct), unwrap it
		if urlError, ok := err.(*url.Error); ok {
			err = urlError.Err
		}
	}
	// TODO: I assume this second check is here because the error that a url Error wraps could be nil
	if err != nil {
		switch err {
		case ErrRedirLocalhost:
			// FIXME: Do nothing when redirecting to local is an issue?
			break
		case ErrTooManyRedirects:
			// FIXME: Does it make sense to have an application error for a lot of redirects
			return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
		default:
			return zgrab2.DetectScanError(err)
		}
	}
	protocols := strings.Split(resp.Header.Get("Server"), " ")
	for _, p := range protocols {
		// TODO: Determine whether these Server items will always be formatted in all caps
		// (seems like there's no standard, but it's also very prevalent)
		if strings.HasPrefix(p, "IPP/") {
			scan.results.VersionString = p
		}
		if strings.HasPrefix(p, "CUPS/") {
			scan.results.CUPSVersion = p
		}
	}

	// TODO: Split off optional CUPS-only stuff into a separate function
	if scan.results.CUPSVersion != "" {
		// Send a CUPS-get-printers request
		cupsBody := getPrintersRequest()
		cupsReq, err := http.NewRequest("POST", scan.url, cupsBody)
		if err != nil {
			return zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
		}
		cupsReq.Header.Set("Accept", "*/*")
		cupsReq.Header.Set("Content-Type", ContentType)
		cupsResp, err := scan.client.Do(cupsReq)
		// Read back some data from it, storing that data into the BodyText and BodySHA256 of cupsResp
		storeBody(cupsResp, scanner)

		cupsVersion, err := readAttributeFromBody(CupsVersion, &cupsResp.BodyText)
		if err != nil {
			//Handle failure
			return zgrab2.DetectScanError(err)
		}
		// Report this cupsVersion b/c it's more detailed than the one found in Server header
		scan.results.CUPSVersion = strings.Split(scan.results.CUPSVersion, "/")[0] + "/" + string(*cupsVersion)
	}

	// TODO: Check to make sure that the repsonse received is actually IPP
	//Content-Type header matches is sufficient
	//HTTP on port 631 is sufficient
	//Still record data in the case of protocol error to see what that data looks like

	buf := copyBody(resp, scanner)
	// TODO: Check for copyBody errors here

	// Reads in signed integers because "every integer MUST be encoded as a signed integer"
	// (Source: https://tools.ietf.org/html/rfc8010#section-3)
	var major, minor int8
	// TODO: Refactor this so that an assignment happens for each successful Read
	// TODO: Determine whether errors other than protocol (ie: too few bytes) can be triggered here
	if err := binary.Read(buf, binary.BigEndian, &major); err != nil {
		// Empty body is not allowed in IPP because version-number is a required parameter in the first two bytes
		// Source: RFC 8011 Section 4.1.1 https://tools.ietf.org/html/rfc8011#section-4.1.1
		// Still returns the response, if any, because assignment occurs before this else block
		return zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, err)
	}
	if err := binary.Read(buf, binary.BigEndian, &minor); err != nil {
		// Body with fewer than 2 bytes is also a protocol error; see above if block
		return zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, err)
	}
	scan.results.MajorVersion = &major
	scan.results.MinorVersion = &minor

	return nil
}

//Taken from zgrab/zlib/grabber.go -- check if the URL points to localhost
func redirectsToLocalhost(host string) bool {
	if i := net.ParseIP(host); i != nil {
		return i.IsLoopback() || i.Equal(net.IPv4zero)
	}
	if host == "localhost" {
		return true
	}

	if addrs, err := net.LookupHost(host); err == nil {
		for _, i := range addrs {
			if ip := net.ParseIP(i); ip != nil {
				if ip.IsLoopback() || ip.Equal(net.IPv4zero) {
					return true
				}
			}
		}
	}
	return false
}

// Taken from zgrab/zlib/grabber.go -- get a CheckRedirect callback that uses the redirectToLocalhost and MaxRedirects config
func (scan *scan) getCheckRedirect(scanner *Scanner) func(*http.Request, *http.Response, []*http.Request) error {
	return func(req *http.Request, res *http.Response, via []*http.Request) error {
		if !scanner.config.FollowLocalhostRedirects && redirectsToLocalhost(req.URL.Hostname()) {
			return ErrRedirLocalhost
		}
		scan.results.RedirectResponseChain = append(scan.results.RedirectResponseChain, res)
		storeBody(res, scanner)

		if len(via) > scanner.config.MaxRedirects {
			return ErrTooManyRedirects
		}

		return nil
	}
}

// FIXME: I think this refactoring is meaningfully less performant than just copying and pasting, but it's a lot cleaner to write
//        Also quite possibly not easier to read ("What does storeBody do? Where does it store it?")
// FIXME: Add some error handling somewhere in here, unless errors should just be ignored and we get what we get
func storeBody(res *http.Response, scanner *Scanner) {
	b := copyBody(res, scanner)
	res.BodyText = b.String()
	if len(res.BodyText) > 0 {
		m := sha256.New()
		m.Write(b.Bytes())
		res.BodySHA256 = m.Sum(nil)
	}
}

func copyBody(res *http.Response, scanner *Scanner) *bytes.Buffer {
	b := new(bytes.Buffer)
	maxReadLen := int64(scanner.config.MaxSize) * 1024
	readLen := maxReadLen
	if res.ContentLength >= 0 && res.ContentLength < maxReadLen {
		readLen = res.ContentLength
	}
	io.CopyN(b, res.Body, readLen)
	return b
}

// Taken from zgrab2 http library, slightly modified to use slightly leaner scan object
func (scan *scan) getTLSDialer(scanner *Scanner) func(net, addr string) (net.Conn, error) {
	return func(net, addr string) (net.Conn, error) {
		outer, err := zgrab2.DialTimeoutConnection(net, addr, time.Second*time.Duration(scanner.config.BaseFlags.Timeout))
		if err != nil {
			return nil, err
		}
		scan.connections = append(scan.connections, outer)
		tlsConn, err := scanner.config.TLSFlags.GetTLSConnection(outer)
		if err != nil {
			return nil, err
		}
		// TODO: Understand what this comment is trying to say
		// lib/http/transport.go fills in the TLSLog in the http.Request instance(s)
		err = tlsConn.Handshake()
		return tlsConn, err
	}
}

// FIXME: Why is this a method of Scanner?
// Adapted from newHTTPScan in zgrab2 http module
func (scanner *Scanner) newIPPScan(target *zgrab2.ScanTarget) *scan {
	newScan := scan{
		client: http.MakeNewClient(),
	}
	transport := &http.Transport{
		Proxy:               nil, // TODO: implement proxying
		DisableKeepAlives:   false,
		DisableCompression:  false,
		MaxIdleConnsPerHost: scanner.config.MaxRedirects,
	}
	transport.DialTLS = newScan.getTLSDialer(scanner)
	transport.DialContext = zgrab2.GetTimeoutConnectionDialer(time.Duration(scanner.config.Timeout) * time.Second).DialContext
	newScan.client.CheckRedirect = newScan.getCheckRedirect(scanner)
	newScan.client.UserAgent = scanner.config.UserAgent
	newScan.client.Transport = transport
	newScan.client.Jar = nil // Don't transfer cookies FIXME: Stolen from HTTP, unclear if needed
	host := target.Domain
	if host == "" {
		// FIXME: I only know this works for sure for IPv4, uri string might get weird w/ IPv6
		// FIXME: Change this, since ipp uri's cannot contain an IP address. Still valid for HTTP
		host = target.IP.String()
	}
	// FIXME: ?Should just use endpoint "/", since we get the same response as "/ipp" on CUPS??
	newScan.url = getHTTPURL(scanner.config.IPPSecure, host, uint16(scanner.config.BaseFlags.Port), "/ipp")
	// FIXME: We're already passing a scan object around all over the place, so it wouldn't be more to have an object for this
	// results is a pointer to minimize memory overhead from passing around a bulky ScanResults object
	newScan.results = &ScanResults{}
	return &newScan
}

// Scan TODO: describe how scan operates in appropriate detail
//1. Send a request (currently get-printer-attributes)
//2. Take in that response & read out version numbers
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	scan := scanner.newIPPScan(&target)
	//defer scan.Cleanup()
	err := scanner.Grab(scan, &target)
	if err != nil {
		// Ripped directly from http module's RetryTLS functionality
		if scanner.config.RetryTLS && !scanner.config.IPPSecure {
			//scan.Cleanup()
			scanner.config.IPPSecure = true
			retry := scanner.newIPPScan(&target)
			//defer retry.Cleanup()
			retryErr := scanner.Grab(retry, &target)
			if retryErr != nil {
				return retryErr.Unpack(retry.results)
			}
			return zgrab2.SCAN_SUCCESS, retry.results, nil
		}
		return zgrab2.TryGetScanStatus(err), scan.results, err
	}
	return zgrab2.SCAN_SUCCESS, scan.results, nil
}

// Package ipp provides a zgrab2 module that scans for ipp.
// TODO: Describe module, the flags, the probe, the output, etc.
package ipp

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	//"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net"
	"net/url"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http"
)

const (
	ContentType         string = "application/ipp"
	VersionsSupported   string = "ipp-versions-supported"
	CupsVersion         string = "cups-version"
	PrinterURISupported string = "printer-uri-supported"
)

var (
	// ErrRedirLocalhost is returned when an HTTP redirect points to localhost,
	// unless FollowLocalhostRedirects is set.
	ErrRedirLocalhost = errors.New("Redirecting to localhost")

	// ErrTooManyRedirects is returned when the number of HTTP redirects exceeds
	// MaxRedirects.
	ErrTooManyRedirects = errors.New("Too many redirects")

	// TODO: Explain this error
	ErrVersionNotSupported = errors.New("IPP version not supported")

	Versions = []version{
		{Major: 2, Minor: 1},
		{Major: 2, Minor: 0},
		{Major: 1, Minor: 1},
		{Major: 1, Minor: 0},
	}

	AttributesCharset = []byte{
		0x47, 0x00, 0x12, 0x61, 0x74, 0x74, 0x72, 0x69,
		0x62, 0x75, 0x74, 0x65, 0x73, 0x2d, 0x63, 0x68,
		0x61, 0x72, 0x73, 0x65, 0x74,
	}
)

type scan struct {
	connections []net.Conn
	transport   *http.Transport
	client      *http.Client
	results     ScanResults
	url         string
	tls         bool
}

// TODO: Tag relevant results and exlain in comments
// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	//TODO: ?Include the request sent as well??
	Response     *http.Response `json:"response,omitempty" zgrab:"debug"`
	CUPSResponse *http.Response `json:"cups_response,omitempty" zgrab:"debug"`

	// RedirectResponseChain is non-empty if the scanner follows a redirect.
	// It contains all redirect responses prior to the final response.
	RedirectResponseChain []*http.Response `json:"redirect_response_chain,omitempty" zgrab:"debug"`

	MajorVersion  *int8  `json:"version_major,omitempty"`
	MinorVersion  *int8  `json:"version_minor,omitempty"`
	VersionString string `json:"version_string,omitempty"`
	CUPSVersion   string `json:"cups_version,omitempty"`

	Attributes           []*Attribute `json:"attributes,omitempty"`
	AttributeCUPSVersion string       `json:"attr_cups_version,omitempty"`
	AttributeIPPVersions []string     `json:"attr_ipp_versions,omitempty"`
	AttributePrinterURIs []string     `json:"attr_printer_uris,omitempty"`

	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Flags holds the command-line configuration for the ipp scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	Verbose bool `long:"verbose" description:"More verbose logging, include debug fields in the scan results"`

	//FIXME: Borrowed from http module, determine whether this is all needed
	MaxSize      int    `long:"max-size" default:"256" description:"Max kilobytes to read in response to an IPP request"`
	MaxRedirects int    `long:"max-redirects" default:"0" description:"Max number of redirects to follow"`
	UserAgent    string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent"`
	TLSRetry     bool   `long:"ipps-retry" description:"If the initial request using TLS fails, reconnect and try using plaintext IPP."`

	// FollowLocalhostRedirects overrides the default behavior to return
	// ErrRedirLocalhost whenever a redirect points to localhost.
	FollowLocalhostRedirects bool `long:"follow-localhost-redirects" description:"Follow HTTP redirects to localhost"`

	// TODO: Maybe separately implement both an ipps connection and upgrade to https
	IPPSecure bool `long:"ipps" description:"Perform a TLS handshake immediately upon connecting."`
}

// Module implements the zgrab2.Module interface.
type Module struct {
	// TODO: Add any module-global state if necessary
}

type version struct {
	Major int8
	Minor int8
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
	// TODO: Add scan state if any is necessary
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("ipp", "ipp", module.Description(), 631, &module)
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
	return "Probe for printers via IPP"
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
	// TODO: Remove debug logging for unexpected behavior after 1% scan
	if f.Verbose {
		log.SetLevel(log.DebugLevel)
	}
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

// FIXME: Add some error handling somewhere in here, unless errors should just be ignored and we get what we get
func storeBody(res *http.Response, scanner *Scanner) {
	b := bufferFromBody(res, scanner)
	res.BodyText = b.String()
	if len(res.BodyText) > 0 {
		m := sha256.New()
		m.Write(b.Bytes())
		res.BodySHA256 = m.Sum(nil)
	}
}

func bufferFromBody(res *http.Response, scanner *Scanner) *bytes.Buffer {
	b := new(bytes.Buffer)
	maxReadLen := int64(scanner.config.MaxSize) * 1024
	readLen := maxReadLen
	if res.ContentLength >= 0 && res.ContentLength < maxReadLen {
		readLen = res.ContentLength
	}
	io.CopyN(b, res.Body, readLen)
	res.Body.Close()
	res.Body = ioutil.NopCloser(b)
	return b
}

type Value struct {
	Bytes []byte `json:"raw,omitempty"`
}

type Attribute struct {
	Name     string  `json:"name,omitempty"`
	Values   []Value `json:"values,omitempty"`
	ValueTag byte    `json:"tag,omitempty"`
}

func shouldReturnAttrs(length, soFar, size, upperBound int) (bool, error) {
	if soFar+length > size {
		// Size should never exceed upperBound in practice because of truncation, but this is more general
		if size >= upperBound {
			return true, nil
		}
		return true, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, errors.New("Reported field length runs out of bounds."))

	}
	return false, nil
}

func detectReadBodyError(err error) error {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, errors.New("Fewer body bytes read than expected."))
	}
	return zgrab2.NewScanError(zgrab2.TryGetScanStatus(err), err)
}

/*
	An IPP response contains the following data (as specified in RFC 8010 Section 3.1.8
	  https://tools.ietf.org/html/rfc8010#section-3.1.8)

bytes name
----------------------------
2     version-number
2     status-code
4     request-id

(0 or more instances of the following pair of fields)
1     delimiter-tag OR value-tag
x     empty if delimiter-tag to begin a group OR rest of attribute if value-tag

1     end-of-attributes-tag
----------------------------

Those x bytes of any given attribute consist of the following (as specified in RFC 8010 Section 3.1.4
https://tools.ietf.org/html/rfc8010#section-3.1.4)
----------------------------
2     name-length = u
u     name
2     value-length = v
v     value
----------------------------
*/
func readAllAttributes(body []byte, scanner *Scanner) ([]*Attribute, error) {
	var attrs []*Attribute
	bytesRead := 0
	buf := bytes.NewBuffer(body)
	// Each field of this struct is exported to avoid binary.Read panicking
	var start struct {
		Version    int16
		StatusCode int16
		ReqID      int32
	}
	// Read in pre-attribute part of body to ignore it
	if err := binary.Read(buf, binary.BigEndian, &start); err != nil {
		return attrs, detectReadBodyError(err)
	}
	bytesRead += 8
	// Read in first delimiter tag, usually a begin-attribute-group-tag (which is equal to 1)
	var tag byte
	if err := binary.Read(buf, binary.BigEndian, &tag); err != nil {
		return attrs, detectReadBodyError(err)
	}
	bytesRead++
	var lastTag byte
	// Until encountering end-of-attributes-tag (which is equal to 3):
	for tag != 0x03 {
		// If tag is a delimiter-tag ([0x00, 0x05]), read the next tag, which corresponds to the first
		// attribute's value-tag
		if tag <= 0x05 {
			lastTag = tag
			if err := binary.Read(buf, binary.BigEndian, &tag); err != nil {
				return attrs, detectReadBodyError(err)
			}
			bytesRead++
			// Start a new iteration after reading this tag, since the next tag could be another
			// delimiter to be caught by this same if block
			continue
		}
		// TODO: Implement parsing attribute collections, since they're special
		// Read in length of attribute's name, which will be used to determine
		// whether this attribute stands alone or provides an additonal value
		// for the previous attribute
		var nameLength uint16
		if err := binary.Read(buf, binary.BigEndian, &nameLength); err != nil {
			return attrs, detectReadBodyError(err)
		}
		bytesRead += 2
		// If reading the name would entail reading past body, check whether body was truncated
		if should, err := shouldReturnAttrs(int(nameLength), bytesRead, len(body), scanner.config.MaxSize*1024); should {
			// If body was truncated, return all attributes so far without error
			// Otherwise, return a protocol error because name-length should indicate the
			// length of the following name when obeying the protocol's encoding
			return attrs, err
		}

		var attr *Attribute
		// If sequential tags match and name-length of the latter is 0, the second attribute is
		// an additional value for the former, so we read and append another value for that attr
		if tag == lastTag && nameLength == 0 {
			attr = attrs[len(attrs)-1]
			// Otherwise, create a new attribute and read in its name
		} else {
			attr = &Attribute{ValueTag: tag}
			attrs = append(attrs, attr)
		}
		// Read in name into this slice (or no name into an empty slice if nameLength == 0)
		name := make([]byte, nameLength)
		if err := binary.Read(buf, binary.BigEndian, &name); err != nil {
			return attrs, detectReadBodyError(err)
		}
		bytesRead += int(nameLength)
		if attr.Name == "" {
			attr.Name = string(name)
		}
		// Determine length of current value of the current attribute
		var length int16
		if err := binary.Read(buf, binary.BigEndian, &length); err != nil {
			return attrs, detectReadBodyError(err)
		}
		bytesRead += 2
		// If reading the name would entail reading past body, check whether body was truncated
		if should, err := shouldReturnAttrs(int(length), bytesRead, len(body), scanner.config.MaxSize*1024); should {
			// If body was truncated, return all attributes so far without error
			// Otherwise, return a protocol error because name-length should indicate the
			// length of the following name when obeying the protocol's encoding
			return attrs, err
		}
		if length > 0 {
			// Read and append a value to the current attribute
			val := make([]byte, length)
			if err := binary.Read(buf, binary.BigEndian, &val); err != nil {
				return attrs, detectReadBodyError(err)
			}
			bytesRead += int(length)
			attr.Values = append(attr.Values, Value{Bytes: val})
		}

		// Read in the following tag to be assessed at the next iteration's start
		lastTag = tag
		if err := binary.Read(buf, binary.BigEndian, &tag); err != nil {
			return attrs, detectReadBodyError(err)
		}
		bytesRead++
	}

	return attrs, nil
}

func (scanner *Scanner) tryReadAttributes(resp *http.Response, scan *scan) *zgrab2.ScanError {
	body := []byte(resp.BodyText)
	// A well-formed IPP response MUST include the required status-code field.
	// "If an IPP status-code is returned, the HTTP status-code MUST be 200"
	// Therefore, an HTTP Status Code other than 200 indicates the response is not a well-formed IPP response.
	// RFC 8010 Section 3.4.3 Source: https://tools.ietf.org/html/rfc8010#section-3.4.3
	if resp.StatusCode != 200 {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, errors.New("Response returned with status "+resp.Status))
	}

	// Reject successful responses which specify non-IPP MIME mediatype (ie: text/html)
	// RFC 8010's abstract specifies that IPP uses the MIME media type "application/ipp"
	if !isIPP(resp) {
		return zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, errors.New("IPP Content-Type not detected."))
	}

	attrs, err := readAllAttributes(body, scanner)
	if err != nil {
		// TODO: Handle error appropriately
		log.WithFields(log.Fields{
			"error": err,
			"body":  resp.BodyText,
		}).Debug("Failed to read attributes from body with error.")
	}
	scan.results.Attributes = append(scan.results.Attributes, attrs...)

	for _, attr := range scan.results.Attributes {
		if attr.Name == CupsVersion && scan.results.AttributeCUPSVersion == "" && len(attr.Values) > 0 {
			scan.results.AttributeCUPSVersion = string(attr.Values[0].Bytes)
		}
		if attr.Name == VersionsSupported && len(scan.results.AttributeIPPVersions) == 0 {
			for _, v := range attr.Values {
				scan.results.AttributeIPPVersions = append(scan.results.AttributeIPPVersions, string(v.Bytes))
			}
		}
		if attr.Name == PrinterURISupported && len(attr.Values) > 0 {
			scan.results.AttributePrinterURIs = append(scan.results.AttributePrinterURIs, string(attr.Values[0].Bytes))
		}
	}

	return nil
}

func versionNotSupported(body string) bool {
	if body != "" {
		buf := bytes.NewBuffer([]byte(body))
		// Ignore first two bytes, read second two for status code
		var reader struct {
			_          uint16
			StatusCode uint16
		}
		err := binary.Read(buf, binary.BigEndian, &reader)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"body":  body,
			}).Debug("Failed to read statusCode from body.")
			return false
		}
		// 0x0503 in the second two bytes of the body denotes server-error-version-not-supported
		// Source: RFC 8011 Section 4.1.8 (https://tools.ietf.org/html/rfc8011#4.1.8)
		return reader.StatusCode == 0x0503
	}
	return false
}

// TODO: Genericize this with passed-in getIPPRequest function and *http.Response for some result field to store into
func (scanner *Scanner) augmentWithCUPSData(scan *scan, target *zgrab2.ScanTarget, version *version) *zgrab2.ScanError {
	cupsBody := getPrintersRequest(version.Major, version.Minor)
	cupsResp, err := sendIPPRequest(scan, cupsBody)
	//Store response regardless of error in request, because we may have gotten something back
	scan.results.CUPSResponse = cupsResp
	if err != nil {
		return err
	}
	// Store data into BodyText and BodySHA256 of cupsResp
	storeBody(cupsResp, scanner)
	if versionNotSupported(scan.results.CUPSResponse.BodyText) {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, ErrVersionNotSupported)
	}

	if err := scanner.tryReadAttributes(scan.results.CUPSResponse, scan); err != nil {
		return err
	}
	return nil
}

// TODO: Let this receive generic *io.Reader rather than *bytes.Buffer in particular
func sendIPPRequest(scan *scan, body *bytes.Buffer) (*http.Response, *zgrab2.ScanError) {
	request, err := http.NewRequest("POST", scan.url, body)
	if err != nil {
		// TODO: Log the error to see what exactly went wrong
		return nil, zgrab2.DetectScanError(err)
	}
	request.Header.Set("Accept", "*/*")
	request.Header.Set("Content-Type", ContentType)
	resp, err := scan.client.Do(request)
	if err != nil {
		if urlError, ok := err.(*url.Error); ok {
			err = urlError.Err
		}
	}
	if err != nil {
		switch err {
		case ErrRedirLocalhost:
			break
		case ErrTooManyRedirects:
			return resp, zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
		default:
			return resp, zgrab2.DetectScanError(err)
		}
	}
	// TODO: Examine whether an empty response overall is a connection error; see RFC 8011 Section 4.2.5.2
	if resp == nil {
		return resp, zgrab2.NewScanError(zgrab2.SCAN_CONNECTION_TIMEOUT, errors.New("No HTTP response"))
	}
	// Empty body is not allowed in IPP because a response has required parameter
	// Source: RFC 8011 Section 4.1.1 (https://tools.ietf.org/html/rfc8011#section-4.1.1)
	if resp.Body == nil {
		return resp, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, errors.New("Empty body."))
	}
	return resp, nil
}

func hasContentType(resp *http.Response, contentType string) bool {
	// Removal of everything post-comma added in response to empirical examples of Virata-EmWeb
	// print servers listed with "Content-Type" of "application/ipp, public"
	cType := strings.Split(resp.Header.Get("Content-Type"), ",")[0]
	// Parameters can be ignored, since there are no required or optional parameters
	// IPP parameters specified at https://www.iana.org/assignments/media-types/application/ipp
	mediatype, _, err := mime.ParseMediaType(cType)
	// Certainly doesn't have correct Content-Type if there was a malformed or empty Content-Type
	if mediatype == "" && err != nil {
		return false
	}
	// Check for only subtype added in resonse to empirical examples of Rapid Logic print servers
	// listed with "Content-Type" of "IPP"
	subType := strings.Split(contentType, "/")[1]
	return strings.HasPrefix(mediatype, contentType) || strings.HasPrefix(mediatype, subType)
}

func isIPP(resp *http.Response) bool {
	hasIPP := hasContentType(resp, ContentType)
	body := []byte(resp.BodyText)
	// If Content-Type header doesn't clearly indicate IPP, but "attributes-charset"
	// attribute is specified in the correct format for IPP, still indicate a positive detection
	// This is in response to empirical evidence of all false negatives specifying "attributes-charset"
	// in the correct format.
	return resp.StatusCode == 200 && (hasIPP || bytes.Contains(body, AttributesCharset))
}

func (scanner *Scanner) Grab(scan *scan, target *zgrab2.ScanTarget, version *version) *zgrab2.ScanError {
	// Send get-printer-attributes request to the host, preferably a print server
	body := getPrinterAttributesRequest(version.Major, version.Minor, scan.url, scan.tls)
	// TODO: Log any weird errors coming out of this
	resp, err := sendIPPRequest(scan, body)
	//Store response regardless of error in request, because we may have gotten something back
	scan.results.Response = resp
	if err != nil {
		return err
	}
	storeBody(resp, scanner)
	if versionNotSupported(scan.results.Response.BodyText) {
		return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, ErrVersionNotSupported)
	}

	protocols := strings.Split(resp.Header.Get("Server"), " ")
	for _, p := range protocols {
		if strings.HasPrefix(strings.ToUpper(p), "IPP/") {
			scan.results.VersionString = p
			protocol := strings.Split(p, "/")[1]
			components := strings.Split(protocol, ".")
			// Reads in signed integers because "every integer MUST be encoded as a signed integer"
			// (Source: https://tools.ietf.org/html/rfc8010#section-3)
			var major, minor int8
			if len(components) >= 1 {
				if val, err := strconv.Atoi(components[0]); err != nil {
					log.WithFields(log.Fields{
						"error":  err,
						"string": components[0],
					}).Debug("Failed to read major version from string.")
				} else {
					major = int8(val)
					scan.results.MajorVersion = &major
				}
			}
			if len(components) >= 2 {
				if val, err := strconv.Atoi(components[1]); err != nil {
					log.WithFields(log.Fields{
						"error":  err,
						"string": components[1],
					}).Debug("Failed to read minor version from string.")
				} else {
					minor = int8(val)
					scan.results.MinorVersion = &minor
				}
			}
		}
		if strings.HasPrefix(strings.ToUpper(p), "CUPS/") {
			scan.results.CUPSVersion = p
		}
	}

	if err := scanner.tryReadAttributes(scan.results.Response, scan); err != nil {
		return err
	}
	if scan.results.CUPSVersion != "" {
		err := scanner.augmentWithCUPSData(scan, target, version)
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Debug("Failed to augment with CUPS-get-printers request.")
		}
	}

	return nil
}

// Taken from zgrab/zlib/grabber.go -- check if the URL points to localhost
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

// Taken from zgrab/zlib/grabber.go -- get a CheckRedirect callback that uses redirectToLocalhost and MaxRedirects config
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

// Taken from zgrab2 http library, slightly modified to use slightly leaner scan object
func (scan *scan) getTLSDialer(scanner *Scanner) func(net, addr string) (net.Conn, error) {
	return func(net, addr string) (net.Conn, error) {
		outer, err := zgrab2.DialTimeoutConnection(net, addr, scanner.config.BaseFlags.Timeout, 0)
		if err != nil {
			return nil, err
		}
		scan.connections = append(scan.connections, outer)
		tlsConn, err := scanner.config.TLSFlags.GetTLSConnection(outer)
		if err != nil {
			return nil, err
		}
		// lib/http/transport.go fills in the TLSLog in the http.Request instance(s)
		err = tlsConn.Handshake()
		scan.results.TLSLog = tlsConn.GetLog()
		return tlsConn, err
	}
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

// Adapted from newHTTPScan in zgrab2 http module
func (scanner *Scanner) newIPPScan(target *zgrab2.ScanTarget, tls bool) *scan {
	newScan := scan{
		client: http.MakeNewClient(),
	}
	newScan.results = ScanResults{}
	transport := &http.Transport{
		Proxy:               nil, // TODO: implement proxying
		DisableKeepAlives:   false,
		DisableCompression:  false,
		MaxIdleConnsPerHost: scanner.config.MaxRedirects,
	}
	transport.DialTLS = newScan.getTLSDialer(scanner)
	transport.DialContext = zgrab2.GetTimeoutConnectionDialer(scanner.config.Timeout).DialContext
	newScan.client.CheckRedirect = newScan.getCheckRedirect(scanner)
	newScan.client.UserAgent = scanner.config.UserAgent
	newScan.client.Transport = transport
	newScan.client.Jar = nil // Don't transfer cookies FIXME: Stolen from HTTP, unclear if needed
	newScan.tls = tls
	host := target.Domain
	if host == "" {
		// FIXME: I only know this works for sure for IPv4, uri string might get weird w/ IPv6
		// FIXME: Change this, since ipp uri's cannot contain an IP address. Still valid for HTTP
		host = target.IP.String()
	}
	// Scanner Target port overrides config flag port
	var port uint16
	if target.Port != nil {
		port = uint16(*target.Port)
	} else {
		port = uint16(scanner.config.BaseFlags.Port)
	}
	// FIXME: ?Should just use endpoint "/", since we get the same response as "/ipp" on CUPS??
	newScan.url = getHTTPURL(tls, host, port, "/ipp")
	return &newScan
}

// Cleanup closes any connections that have been opened during the scan
func (scan *scan) Cleanup() {
	if scan.connections != nil {
		for _, conn := range scan.connections {
			defer conn.Close()
		}
		scan.connections = nil
	}
}

// TODO: Do you want to retry with TLS for all versions? Just one's you've already tried? Haven't tried? Just the same version?
func (scanner *Scanner) tryGrabForVersions(target *zgrab2.ScanTarget, versions []version, tls bool) (*scan, *zgrab2.ScanError) {
	scan := scanner.newIPPScan(target, tls)
	defer scan.Cleanup()
	var err *zgrab2.ScanError
	for i := 0; i < len(versions); i++ {
		err = scanner.Grab(scan, target, &versions[i])
		if err != nil && err.Err == ErrVersionNotSupported && i < len(versions)-1 {
			continue
		}
		break
	}
	return scan, err
}

// TODO: Incorporate status into this? I don't think so, b/c with certain statuses, we should return
// early, so special casing seems to make sense
func (scan *scan) shouldReportResult(scanner *Scanner) bool {
	if scan.results.Response != nil {
		return true
	} else if scan.tls {
		l := scan.results.TLSLog
		return l != nil && l.HandshakeLog != nil && l.HandshakeLog.ServerHello != nil
	}
	return false
}

// Scan TODO: describe how scan operates in appropriate detail
// 1. Send a request (currently get-printer-attributes)
// 2. Take in that response & read out version numbers
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	// Try all known IPP versions from newest to oldest until we reach a supported version
	scan, err := scanner.tryGrabForVersions(&target, Versions, scanner.config.TLSRetry || scanner.config.IPPSecure)
	if err != nil {
		// If versionNotSupported error was confirmed, the scanner was connecting w/o TLS, so don't retry
		// Same goes for a protocol error of any kind. It means we got something back but it didn't conform.
		if err.Err == ErrVersionNotSupported || err.Status == zgrab2.SCAN_PROTOCOL_ERROR {
			return err.Unpack(&scan.results)
		}
		if scanner.config.TLSRetry && !scanner.config.IPPSecure {
			retry, retryErr := scanner.tryGrabForVersions(&target, Versions, false)
			if retryErr != nil {
				if retry.shouldReportResult(scanner) {
					return retryErr.Unpack(&retry.results)
				}
				// Use original result as a fallback when retry result shouldn't be returned
				if scan.shouldReportResult(scanner) {
					return err.Unpack(&scan.results)
				}
				return zgrab2.TryGetScanStatus(retryErr), nil, retryErr
			}
			return zgrab2.SCAN_SUCCESS, &retry.results, nil
		}
		if scan.shouldReportResult(scanner) {
			return err.Unpack(&scan.results)
		}
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	return zgrab2.SCAN_SUCCESS, &scan.results, nil
}

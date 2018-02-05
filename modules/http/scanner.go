// Package http contains the zgrab2 Module implementation for HTTP(S).
// The scan performs a GET on the specified path (default /).
// If --use-https is provided, it uses TLS instead.
// The output is based on the original zgrab HTTP output: it has the
// high-level connect_request and connect_response (NOTE: Currently unused both
// here and in zgrab), and the full parsed response object in response; if there
// were any redirects, their full parsed responses also appear in
// redirect_response_chain.
package http

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http"
)

var (
	// ErrRedirLocalhost is thrown if there is an HTTP redirect pointing to localhost, when FollowLocalhostRedirects = false
	ErrRedirLocalhost = errors.New("Redirecting to localhost")

	// ErrTooManyRedirects is thrown if the number of HTTP redirects exceeds the MaxRedirects flags
	ErrTooManyRedirects = errors.New("Too many redirects")
)

// Flags holds the command-line configuration for the HTTP scan module. Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	Method                   string `long:"method" default:"GET" description:"Set HTTP request method type"`
	Endpoint                 string `long:"endpoint" default:"/" description:"Send an HTTP request to an endpoint"`
	UserAgent                string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent"`
	ProxyDomain              string `long:"proxy-domain" description:"Send a CONNECT <domain> first"`
	MaxSize                  int    `long:"max-size" default:"256" description:"Max kilobytes to read in response to an HTTP request"`
	MaxRedirects             int    `long:"max-redirects" default:"0" description:"Max number of redirects to follow"`
	FollowLocalhostRedirects bool   `long:"follow-localhost-redirects" description:"Follow HTTP redirects to localhost"`
	UseHTTPS                 bool   `long:"use-https" description:"Perform an HTTPS connection on the initial host"`
	// TODO: Custom headers?
}

// Request holds the data used for the HTTP request sent to the target
// NOTE: Currently unused (in the original zgrab, this was only populated in
// sendHTTPRequestReadHTTPResponse(), which was only called from doProxy(),
// which was never called.
type Request struct {
	Method    string `json:"method,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Body      string `json:"body,omitempty"`
}

// Headers contains the HTTP headers. Currently unused (see NOTE in Request).
type Headers map[string]interface{}

// Response holds the raw data returned by the server. NOTE: as with Request,
// this is unused both here and in the original zgrab.
type Response struct {
	VersionMajor int     `json:"version_major,omitempty"`
	VersionMinor int     `json:"version_minor,omitempty"`
	StatusCode   int     `json:"status_code,omitempty"`
	StatusLine   string  `json:"status_line,omitempty"`
	Headers      Headers `json:"headers,omitempty"`
	Body         string  `json:"body,omitempty"`
	BodySHA256   []byte  `json:"body_sha256,omitempty"`
}

// Results is the type returned to by the scan. NOTE: ProxyRequest/ProxyResponse
// are currently never set (nor were they ever set in the original zgrab).
type Results struct {
	ProxyRequest          *Request         `json:"connect_request,omitempty"`
	ProxyResponse         *Response        `json:"connect_response,omitempty"`
	Response              *http.Response   `json:"response,omitempty"`
	RedirectResponseChain []*http.Response `json:"redirect_response_chain,omitempty"`
}

// Module is the implementation of the zgrab scan module.
type Module struct {
}

// Scanner is the implementation of the zgrab Scanner interface.
type Scanner struct {
	config *Flags
}

// Scan holds the state for a single scan (maybe entailing multiple connections)
type Scan struct {
	scanner   *Scanner
	target    *zgrab2.ScanTarget
	transport *http.Transport
	client    *http.Client
	results   Results
	url       string
}

// NewFlags returns an empty flags object
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new instance of the module's zgrab2.Scanner implementation
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Validate performs any needed validation on the arguments
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns module-specific help
func (flags *Flags) Help() string {
	return ""
}

// Init initializes the scanner with the given flags
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	fl, _ := flags.(*Flags)
	scanner.config = fl
	return nil
}

// InitPerSender initializes the scanner for a specific sender thread
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName gets the scanner's name
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// getTLSDialer returns a Dial function that connects using the zgrab2.GetTLSConnection()
func (scan *Scan) getTLSDialer() func(net, addr string) (net.Conn, error) {
	return func(net, addr string) (net.Conn, error) {
		outer, err := zgrab2.DialTimeoutConnection(net, addr, time.Second*time.Duration(scan.scanner.config.BaseFlags.Timeout))
		if err != nil {
			return nil, err
		}
		tlsConn, err := scan.scanner.config.TLSFlags.GetTLSConnection(outer)
		if err != nil {
			return nil, err
		}
		// lib/http/transport.go fills in the TLSLog in the http.Request instance(s)
		err = tlsConn.Handshake()
		return tlsConn, err
	}
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

// Taken from zgrab/zlib/grabber.go -- get a CheckRedirect callback that uses the redirectToLocalhost and MaxRedirects config
func (scan *Scan) getCheckRedirect() func(*http.Request, *http.Response, []*http.Request) error {
	return func(req *http.Request, res *http.Response, via []*http.Request) error {
		if !scan.scanner.config.FollowLocalhostRedirects && redirectsToLocalhost(req.URL.Hostname()) {
			return ErrRedirLocalhost
		}
		scan.results.RedirectResponseChain = append(scan.results.RedirectResponseChain, res)
		b := new(bytes.Buffer)
		maxReadLen := int64(scan.scanner.config.MaxSize) * 1024
		readLen := maxReadLen
		if res.ContentLength >= 0 && res.ContentLength < maxReadLen {
			readLen = res.ContentLength
		}
		io.CopyN(b, res.Body, readLen)
		res.BodyText = b.String()
		if len(res.BodyText) > 0 {
			m := sha256.New()
			m.Write(b.Bytes())
			res.BodySHA256 = m.Sum(nil)
		}

		if len(via) > scan.scanner.config.MaxRedirects {
			return ErrTooManyRedirects
		}

		return nil
	}
}

// Maps URL protocol to the default port for that protocol
var protoToPort = map[string]uint16{
	"http":  80,
	"https": 443,
}

// getHTTPURL gets the HTTP URL (sans default port) for the given protocol/host/port/endpoint.
func getHTTPURL(https bool, host string, port uint16, endpoint string) string {
	var proto string
	if https {
		proto = "https"
	} else {
		proto = "http"
	}
	if protoToPort[proto] == port {
		return proto + "://" + host + endpoint
	}
	return proto + "://" + net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)) + endpoint
}

// NewHTTPScan gets a new Scan instance for the given target
func (scanner *Scanner) NewHTTPScan(t *zgrab2.ScanTarget) *Scan {
	ret := Scan{
		scanner: scanner,
		target:  t,
		transport: &http.Transport{
			Proxy:               nil, // TODO: implement proxying
			DisableKeepAlives:   false,
			DisableCompression:  false,
			MaxIdleConnsPerHost: scanner.config.MaxRedirects,
		},
		client: http.MakeNewClient(),
	}
	ret.transport.DialTLS = ret.getTLSDialer()
	ret.client.UserAgent = scanner.config.UserAgent
	ret.client.CheckRedirect = ret.getCheckRedirect()
	ret.client.Transport = ret.transport
	ret.client.Jar = nil // Don't send or receive cookies (otherwise use CookieJar)
	host := t.Domain
	if host == "" {
		host = t.IP.String()
	}
	ret.url = getHTTPURL(scanner.config.UseHTTPS, host, uint16(scanner.config.BaseFlags.Port), scanner.config.Endpoint)

	return &ret
}

// Grab performs the HTTP scan -- implementation taken from zgrab/zlib/grabber.go
func (scan *Scan) Grab() *zgrab2.ScanError {
	// TODO: Allow body?
	request, err := http.NewRequest(scan.scanner.config.Method, scan.url, nil)
	if err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
	}
	// TODO: Headers from input?
	request.Header.Set("Accept", "*/*")
	resp, err := scan.client.Do(request)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	scan.results.Response = resp
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
			return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
		default:
			return zgrab2.DetectScanError(err)
		}
	}

	buf := new(bytes.Buffer)
	maxReadLen := int64(scan.scanner.config.MaxSize) * 1024
	readLen := maxReadLen
	if resp.ContentLength >= 0 && resp.ContentLength < maxReadLen {
		readLen = resp.ContentLength
	}
	io.CopyN(buf, resp.Body, readLen)
	scan.results.Response.BodyText = buf.String()
	if len(scan.results.Response.BodyText) > 0 {
		m := sha256.New()
		m.Write(buf.Bytes())
		scan.results.Response.BodySHA256 = m.Sum(nil)
	}

	return nil
}

// Scan performs the full scan of the target
func (scanner *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	scan := scanner.NewHTTPScan(&t)
	err := scan.Grab()
	if err != nil {
		return err.Unpack(&scan.results)
	}
	return zgrab2.SCAN_SUCCESS, &scan.results, nil
}

// RegisterModule is called by modules/http.go to register this module with the zgrab2 framework
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("http", "HTTP Banner Grab", "Grab a banner over HTTP", 80, &module)
	log.SetLevel(log.DebugLevel)
	if err != nil {
		log.Fatal(err)
	}
}

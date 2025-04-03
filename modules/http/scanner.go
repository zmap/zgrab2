// Package http contains the zgrab2 Module implementation for HTTP(S).
//
// The Flags can be configured to perform a specific Method (e.g. "GET") on the
// specified Path (e.g. "/"). If UseHTTPS is true, the scanner uses TLS for the
// initial request. The Result contains the final HTTP response following each
// response in the redirect chain.
package http

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/html/charset"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http"
)

var (
	// ErrRedirLocalhost is returned when an HTTP redirect points to localhost,
	// unless FollowLocalhostRedirects is set.
	ErrRedirLocalhost = errors.New("Redirecting to localhost")

	// ErrTooManyRedirects is returned when the number of HTTP redirects exceeds
	// MaxRedirects.
	ErrTooManyRedirects = errors.New("Too many redirects")
)

// Flags holds the command-line configuration for the HTTP scan module.
// Populated by the framework.
//
// TODO: Custom headers?
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`
	Method           string `long:"method" default:"GET" description:"Set HTTP request method type"`
	Endpoint         string `long:"endpoint" default:"/" description:"Send an HTTP request to an endpoint"`
	FailHTTPToHTTPS  bool   `long:"fail-http-to-https" description:"Trigger retry-https logic on known HTTP/400 protocol mismatch responses"`
	UserAgent        string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent"`
	RetryHTTPS       bool   `long:"retry-https" description:"If the initial request fails, reconnect and try with HTTPS."`
	MaxSize          int    `long:"max-size" default:"256" description:"Max kilobytes to read in response to an HTTP request"`
	MaxRedirects     int    `long:"max-redirects" default:"0" description:"Max number of redirects to follow"`

	// FollowLocalhostRedirects overrides the default behavior to return
	// ErrRedirLocalhost whenever a redirect points to localhost.
	FollowLocalhostRedirects bool `long:"follow-localhost-redirects" description:"Follow HTTP redirects to localhost"`

	// UseHTTPS causes the first request to be over TLS, without requiring a
	// redirect to HTTPS. It does not change the port used for the connection.
	UseHTTPS bool `long:"use-https" description:"Perform an HTTPS connection on the initial host"`

	// RedirectsSucceed causes the ErrTooManRedirects error to be suppressed
	RedirectsSucceed bool `long:"redirects-succeed" description:"Redirects are always a success, even if max-redirects is exceeded"`

	// Set arbitrary HTTP headers
	CustomHeadersNames     string `long:"custom-headers-names" description:"CSV of custom HTTP headers to send to server"`
	CustomHeadersValues    string `long:"custom-headers-values" description:"CSV of custom HTTP header values to send to server. Should match order of custom-headers-names."`
	CustomHeadersDelimiter string `long:"custom-headers-delimiter" description:"Delimiter for customer header name/value CSVs"`
	// Set HTTP Request body
	RequestBody    string `long:"request-body" description:"HTTP request body to send to server"`
	RequestBodyHex string `long:"request-body-hex" description:"HTTP request body to send to server"`

	// ComputeDecodedBodyHashAlgorithm enables computing the body hash later than the default,
	// using the specified algorithm, allowing a user of the response to recompute a matching hash
	ComputeDecodedBodyHashAlgorithm string `long:"compute-decoded-body-hash-algorithm" choice:"sha256" choice:"sha1" description:"Choose algorithm for BodyHash field"`

	// WithBodyLength enables adding the body_size field to the Response
	WithBodyLength bool `long:"with-body-size" description:"inserts the body_size field into the http result, listing how many bytes were read of the body"`

	// Extract the raw header as it is on the wire
	RawHeaders bool `long:"raw-headers" description:"Extract raw response up through headers"`
}

// A Results object is returned by the HTTP module's Scanner.Scan()
// implementation.
type Results struct {
	// Result is the final HTTP response in the RedirectResponseChain
	Response *http.Response `json:"response,omitempty"`

	// RedirectResponseChain is non-empty is the scanner follows a redirect.
	// It contains all redirect response prior to the final response.
	RedirectResponseChain []*http.Response `json:"redirect_response_chain,omitempty"`
}

// Module is an implementation of the zgrab2.Module interface.
type Module struct {
}

// Scanner is the implementation of the zgrab2.Scanner interface.
type Scanner struct {
	config            *Flags
	customHeaders     map[string]string
	requestBody       string
	decodedHashFn     func([]byte) string
	dialerGroupConfig *zgrab2.DialerGroupConfig
}

// scan holds the state for a single scan. This may entail multiple connections.
// It is used to implement the zgrab2.Scanner interface.
type scan struct {
	connections    []net.Conn
	scanner        *Scanner
	target         *zgrab2.ScanTarget
	transport      *http.Transport
	client         *http.Client
	results        Results
	url            string
	globalDeadline time.Time
}

// NewFlags returns an empty Flags object.
func (module *Module) NewFlags() any {
	return new(Flags)
}

// NewScanner returns a new instance Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Send an HTTP request and read the response, optionally following redirects."
}

// Validate performs any needed validation on the arguments
func (flags *Flags) Validate() error {
	return nil
}

// Help returns module-specific help
func (flags *Flags) Help() string {
	return ""
}

// Protocol returns the protocol identifer for the scanner.
func (scanner *Scanner) Protocol() string {
	return "http"
}

func (scanner *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return scanner.dialerGroupConfig
}

// Init initializes the scanner with the given flags
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	fl, _ := flags.(*Flags)
	scanner.config = fl
	scanner.config.RequestBody = fl.RequestBody

	// parse out custom headers at initialization so that they can be easily
	// iterated over when constructing individual scanners
	if len(fl.CustomHeadersNames) > 0 || len(fl.CustomHeadersValues) > 0 {
		if len(fl.CustomHeadersNames) == 0 {
			log.Panicf("custom-headers-names must be specified if custom-headers-values is provided")
		}
		if len(fl.CustomHeadersValues) == 0 {
			log.Panicf("custom-headers-values must be specified if custom-headers-names is provided")
		}
		namesReader := csv.NewReader(strings.NewReader(fl.CustomHeadersNames))
		if namesReader == nil {
			log.Panicf("unable to read custom-headers-names in CSV reader")
		}
		valuesReader := csv.NewReader(strings.NewReader(fl.CustomHeadersValues))
		if valuesReader == nil {
			log.Panicf("unable to read custom-headers-values in CSV reader")
		}

		// By default, the CSV delimiter will remain a comma unless explicitly specified
		if len(fl.CustomHeadersDelimiter) > 1 {
			log.Panicf("Invalid delimiter custom-header delimiter, must be a single character")
		} else if fl.CustomHeadersDelimiter != "" {
			valuesReader.Comma = rune(fl.CustomHeadersDelimiter[0])
			namesReader.Comma = rune(fl.CustomHeadersDelimiter[0])
		}

		headerNames, err := namesReader.Read()
		if err != nil {
			return err
		}
		headerValues, err := valuesReader.Read()
		if err != nil {
			return err
		}
		if len(headerNames) != len(headerValues) {
			log.Panicf("inconsistent number of HTTP header names and values")
		}
		scanner.customHeaders = make(map[string]string)
		for i := 0; i < len(headerNames); i++ {
			// The case of header names is normalized to title case later by HTTP library
			// explicitly ToLower() to catch duplicates more easily
			hName := strings.ToLower(headerNames[i])
			switch {
			case hName == "host":
				log.Panicf("Attempt to set immutable header 'Host', specify this in targets file")
			case hName == "user-agent":
				log.Panicf("Attempt to set special header 'User-Agent', use --user-agent instead")
			case hName == "content-length":
				log.Panicf("Attempt to set immutable header 'Content-Length'")
			}
			// Disallow duplicate headers
			_, ok := scanner.customHeaders[hName]
			if ok {
				log.Panicf("Attempt to set same custom header twice")
			}
			scanner.customHeaders[hName] = headerValues[i]
		}
	}

	if fl.ComputeDecodedBodyHashAlgorithm == "sha1" {
		scanner.decodedHashFn = func(body []byte) string {
			rawHash := sha1.Sum(body)
			return fmt.Sprintf("sha1:%s", hex.EncodeToString(rawHash[:]))
		}
	} else if fl.ComputeDecodedBodyHashAlgorithm == "sha256" {
		scanner.decodedHashFn = func(body []byte) string {
			rawHash := sha256.Sum256(body)
			return fmt.Sprintf("sha256:%s", hex.EncodeToString(rawHash[:]))
		}
	} else if fl.ComputeDecodedBodyHashAlgorithm != "" {
		log.Panicf("Invalid ComputeDecodedBodyHashAlgorithm choice made it through zflags: %s", scanner.config.ComputeDecodedBodyHashAlgorithm)
	}

	scanner.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		NeedSeparateL4Dialer:            true,
		BaseFlags:                       &scanner.config.BaseFlags,
		TLSEnabled:                      true,
		TLSFlags:                        &scanner.config.TLSFlags,
	}

	return nil
}

// InitPerSender does nothing in this module.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
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

// Get a context whose deadline is the earliest of the context's deadline (if it has one) and the
// global scan deadline.
func (scan *scan) withDeadlineContext(ctx context.Context) context.Context {
	ctxDeadline, ok := ctx.Deadline()
	if !ok || scan.globalDeadline.Before(ctxDeadline) {
		ret, _ := context.WithDeadline(ctx, scan.globalDeadline)
		return ret
	}
	return ctx
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

// Taken from zgrab/zlib/grabber.go -- get a CheckRedirect callback that uses
// the redirectToLocalhost and MaxRedirects config
func (scan *scan) getCheckRedirect() func(*http.Request, *http.Response, []*http.Request) error {
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
		bytesRead, _ := io.CopyN(b, res.Body, readLen)
		if scan.scanner.config.WithBodyLength {
			res.BodyTextLength = bytesRead
		}
		res.BodyText = b.String()
		if len(res.BodyText) > 0 {
			if scan.scanner.decodedHashFn != nil {
				res.BodyHash = scan.scanner.decodedHashFn([]byte(res.BodyText))
			} else {
				m := sha256.New()
				m.Write(b.Bytes())
				res.BodySHA256 = m.Sum(nil)
			}
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
	if protoToPort[proto] == port && strings.Contains(host, ":") {
		//If the host has a ":" in it, assume literal IPv6 address
		return proto + "://[" + host + "]" + endpoint
	} else if protoToPort[proto] == port {
		//Otherwise, just concatenate host and endpoint
		return proto + "://" + host + endpoint
	}

	//For non-default ports, net.JoinHostPort will handle brackets for IPv6 literals
	return proto + "://" + net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)) + endpoint
}

// NewHTTPScan gets a new Scan instance for the given target
func (scanner *Scanner) newHTTPScan(ctx context.Context, t *zgrab2.ScanTarget, useHTTPS bool, dialerGroup *zgrab2.DialerGroup) *scan {
	ret := scan{
		scanner: scanner,
		target:  t,
		transport: &http.Transport{
			Proxy:               nil, // TODO: implement proxying
			DisableKeepAlives:   false,
			DisableCompression:  false,
			MaxIdleConnsPerHost: scanner.config.MaxRedirects,
			RawHeaderBuffer:     scanner.config.RawHeaders,
		},
		client: http.MakeNewClient(),
	}
	if scanner.config.Timeout != 0 {
		ret.globalDeadline = time.Now().Add(scanner.config.Timeout)
	}
	ret.transport.DialTLS = func(network, addr string) (net.Conn, error) {
		ctx = ret.withDeadlineContext(ctx)
		conn, err := dialerGroup.GetTLSDialer(ctx, t)(network, addr)
		if err != nil {
			return nil, fmt.Errorf("unable to dial target (%s) with TLS Dialer: %w", t.String(), err)
		}
		ret.connections = append(ret.connections, conn)
		return conn, nil
	}
	ret.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		ctx = ret.withDeadlineContext(ctx)
		conn, err := dialerGroup.L4Dialer(t)(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("unable to dial target (%s) with L4 Dialer: %w", t.String(), err)
		}
		ret.connections = append(ret.connections, conn)
		return conn, nil
	}
	ret.client.UserAgent = scanner.config.UserAgent
	ret.client.CheckRedirect = ret.getCheckRedirect()
	ret.client.Transport = ret.transport
	ret.client.Jar = nil // Don't send or receive cookies (otherwise use CookieJar)
	ret.client.Timeout = scanner.config.Timeout
	if deadline, ok := ctx.Deadline(); ok {
		ret.client.Timeout = min(ret.client.Timeout, deadline.Sub(time.Now()))
	}

	host := t.Domain
	if host == "" {
		host = t.IP.String()
	}
	ret.url = getHTTPURL(useHTTPS, host, uint16(t.Port), scanner.config.Endpoint)

	return &ret
}

// Grab performs the HTTP scan -- implementation taken from zgrab/zlib/grabber.go
func (scan *scan) Grab() *zgrab2.ScanError {
	// TODO: Allow body?
	var (
		request *http.Request
		err     error
	)
	if len(scan.scanner.config.RequestBody) > 0 {
		request, err = http.NewRequest(scan.scanner.config.Method, scan.url, strings.NewReader(scan.scanner.config.RequestBody))
	} else if len(scan.scanner.config.RequestBodyHex) > 0 {
		reqbody, _ := hex.DecodeString(scan.scanner.config.RequestBodyHex)
		request, err = http.NewRequest(scan.scanner.config.Method, scan.url, bytes.NewReader(reqbody))
	} else {
		request, err = http.NewRequest(scan.scanner.config.Method, scan.url, nil)
	}
	if err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
	}

	// By default, the following headers are *always* set:
	// Host, User-Agent, Accept, Accept-Encoding
	if scan.scanner.customHeaders != nil {
		request.Header.Set("Accept", "*/*")
		for k, v := range scan.scanner.customHeaders {
			request.Header.Set(k, v)
		}
	} else {
		// If user did not specify custom headers, legacy behavior has always been
		// to set the Accept header
		request.Header.Set("Accept", "*/*")
	}

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
			if scan.scanner.config.RedirectsSucceed {
				return nil
			}
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
	encoder, encoding, certain := charset.DetermineEncoding(buf.Bytes(), resp.Header.Get("content-type"))

	bodyText := ""
	decodedSuccessfully := false
	decoder := encoder.NewDecoder()

	//"windows-1252" is the default value and will likely not decode correctly
	if certain || encoding != "windows-1252" {
		decoded, decErr := decoder.Bytes(buf.Bytes())

		if decErr == nil {
			bodyText = string(decoded)
			decodedSuccessfully = true
		}
	}

	if !decodedSuccessfully {
		bodyText = buf.String()
	}

	// Application-specific logic for retrying HTTP as HTTPS; if condition matches, return protocol error
	bodyTextLen := int64(len(bodyText))
	if scan.scanner.config.FailHTTPToHTTPS && scan.results.Response.StatusCode == 400 && bodyTextLen < 1024 && bodyTextLen > 24 {
		// Apache: "You're speaking plain HTTP to an SSL-enabled server port"
		// NGINX: "The plain HTTP request was sent to HTTPS port"
		var sliceLen int64 = 128
		if readLen < sliceLen {
			sliceLen = readLen
		}

		if bodyTextLen < sliceLen {
			sliceLen = bodyTextLen
		}

		sliceBuf := bodyText[:sliceLen]
		if strings.Contains(sliceBuf, "The plain HTTP request was sent to HTTPS port") ||
			strings.Contains(sliceBuf, "You're speaking plain HTTP") ||
			strings.Contains(sliceBuf, "combination of host and port requires TLS") ||
			strings.Contains(sliceBuf, "Client sent an HTTP request to an HTTPS server") {
			return zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, errors.New("NGINX or Apache HTTP over HTTPS failure"))
		}
	}

	// re-enforce readlen
	if int64(len(bodyText)) > readLen {
		scan.results.Response.BodyText = bodyText[:int(readLen)]
	} else {
		scan.results.Response.BodyText = bodyText
	}

	if scan.scanner.config.WithBodyLength {
		scan.results.Response.BodyTextLength = int64(len(scan.results.Response.BodyText))
	}

	if len(scan.results.Response.BodyText) > 0 {
		if scan.scanner.decodedHashFn != nil {
			scan.results.Response.BodyHash = scan.scanner.decodedHashFn([]byte(scan.results.Response.BodyText))
		} else {
			m := sha256.New()
			m.Write(buf.Bytes())
			scan.results.Response.BodySHA256 = m.Sum(nil)
		}
	}

	return nil
}

// Scan implements the zgrab2.Scanner interface and performs the full scan of
// the target. If the scanner is configured to follow redirects, this may entail
// multiple TCP connections to hosts other than target.
func (scanner *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	if dialGroup == nil || dialGroup.L4Dialer == nil || dialGroup.TLSWrapper == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, fmt.Errorf("must specify a dialer group with L4 dialer and TLS wrapper")
	}
	scan := scanner.newHTTPScan(ctx, target, scanner.config.UseHTTPS, dialGroup)
	defer scan.Cleanup()
	err := scan.Grab()
	if err != nil {
		if scanner.config.RetryHTTPS && !scanner.config.UseHTTPS {
			scan.Cleanup()
			retry := scanner.newHTTPScan(ctx, target, true, dialGroup)
			defer retry.Cleanup()
			retryError := retry.Grab()
			if retryError != nil {
				return err.Unpack(&scan.results)
			}
			return zgrab2.SCAN_SUCCESS, &retry.results, nil
		}
		return err.Unpack(&scan.results)
	}
	return zgrab2.SCAN_SUCCESS, &scan.results, nil
}

// RegisterModule is called by modules/http.go to register this module with the
// zgrab2 framework.
func RegisterModule() {
	var module Module

	_, err := zgrab2.AddCommand("http", "HTTP Banner Grab", module.Description(), 80, &module)
	if err != nil {
		log.Fatal(err)
	}
}

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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http"
	"golang.org/x/net/html/charset"
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
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	Method       string `long:"method" default:"GET" description:"Set HTTP request method type"`
	Endpoint     string `long:"endpoint" default:"/" description:"Send an HTTP request to an endpoint"`
	UserAgent    string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent"`
	RetryHTTPS   bool   `long:"retry-https" description:"If the initial request fails, reconnect and try with HTTPS."`
	MaxSize      int    `long:"max-size" default:"256" description:"Max kilobytes to read in response to an HTTP request"`
	MaxRedirects int    `long:"max-redirects" default:"0" description:"Max number of redirects to follow"`

	// FollowLocalhostRedirects overrides the default behavior to return
	// ErrRedirLocalhost whenever a redirect points to localhost.
	FollowLocalhostRedirects bool `long:"follow-localhost-redirects" description:"Follow HTTP redirects to localhost"`

	// UseHTTPS causes the first request to be over TLS, without requiring a
	// redirect to HTTPS. It does not change the port used for the connection.
	UseHTTPS bool `long:"use-https" description:"Perform an HTTPS connection on the initial host"`

	// RedirectsSucceed causes the ErrTooManRedirects error to be suppressed
	RedirectsSucceed bool `long:"redirects-succeed" description:"Redirects are always a success, even if max-redirects is exceeded"`

	OverrideSH bool `long:"override-sig-hash" description:"Override the default SignatureAndHashes TLS option with more expansive default"`

	// ComputeDecodedBodyHashAlgorithm enables computing the body hash later than the default,
	// using the specified algorithm, allowing a user of the response to recompute a matching hash
	ComputeDecodedBodyHashAlgorithm string `long:"compute-decoded-body-hash-algorithm" choice:"sha256" choice:"sha1" description:"Choose algorithm for BodyHash field"`

	// WithBodyLength enables adding the body_size field to the Response
	WithBodyLength bool `long:"with-body-size" description:"Enable the body_size attribute, for how many bytes actually read"`
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
	config        *Flags
	decodedHashFn func([]byte) string
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
func (module *Module) NewFlags() interface{} {
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
func (flags *Flags) Validate(args []string) error {
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

// Init initializes the scanner with the given flags
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	fl, _ := flags.(*Flags)
	scanner.config = fl

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

// Dial a connection using the configured timeouts, as well as the global deadline, and on success,
// add the connection to the list of connections to be cleaned up.
func (scan *scan) dialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	dialer := zgrab2.GetTimeoutConnectionDialer(scan.scanner.config.Timeout)

	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		// If the scan is for a specific IP, and a domain name is provided, we
		// don't want to just let the http library resolve the domain.  Create
		// a fake resolver that we will use, that always returns the IP we are
		// given to scan.
		if scan.target.IP != nil && scan.target.Domain != "" {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				log.Errorf("http/scanner.go dialContext: unable to split host:port '%s'", addr)
				log.Errorf("No fake resolver, IP address may be incorrect: %s", err)
			} else {
				// In the case of redirects, we don't want to blindly use the
				// IP we were given to scan, however.  Only use the fake
				// resolver if the domain originally specified for the scan
				// target matches the current address being looked up in this
				// DialContext.
				if host == scan.target.Domain {
					resolver, err := zgrab2.NewFakeResolver(scan.target.IP.String())
					if err != nil {
						return nil, err
					}
					dialer.Dialer.Resolver = resolver
				}
			}
		}
	}

	timeoutContext, _ := context.WithTimeout(context.Background(), scan.scanner.config.Timeout)

	conn, err := dialer.DialContext(scan.withDeadlineContext(timeoutContext), network, addr)
	if err != nil {
		return nil, err
	}
	scan.connections = append(scan.connections, conn)
	return conn, nil
}

// getTLSDialer returns a Dial function that connects using the
// zgrab2.GetTLSConnection()
func (scan *scan) getTLSDialer(t *zgrab2.ScanTarget) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		outer, err := scan.dialContext(context.Background(), network, addr)
		if err != nil {
			return nil, err
		}
		cfg, err := scan.scanner.config.TLSFlags.GetTLSConfigForTarget(t)
		if err != nil {
			return nil, err
		}

		// Set SNI server name on redirects unless --server-name was used (issue #300)
		//  - t.Domain is always set to the *original* Host so it's not useful for setting SNI
		//  - host is the current target of the request in this context; this is true for the
		//    initial request as well as subsequent requests caused by redirects
		//  - scan.scanner.config.ServerName is the value from --server-name if one was specified

		// If SNI is enabled and --server-name is not set, use the target host for the SNI server name
		if !scan.scanner.config.NoSNI && scan.scanner.config.ServerName == "" {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				log.Errorf("getTLSDialer(): Something went wrong splitting host/port '%s': %s", addr, err)
			}
			// RFC4366: Literal IPv4 and IPv6 addresses are not permitted in "HostName"
			if i := net.ParseIP(host); i == nil {
				cfg.ServerName = host
			}
		}

		if scan.scanner.config.OverrideSH {
			cfg.SignatureAndHashes = []tls.SigAndHash{
				{0x01, 0x04}, // rsa, sha256
				{0x03, 0x04}, // ecdsa, sha256
				{0x01, 0x02}, // rsa, sha1
				{0x03, 0x02}, // ecdsa, sha1
				{0x01, 0x04}, // rsa, sha256
				{0x01, 0x05}, // rsa, sha384
				{0x01, 0x06}, // rsa, sha512
			}
		}
		tlsConn := scan.scanner.config.TLSFlags.GetWrappedConnection(outer, cfg)

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
	if protoToPort[proto] == port {
		return proto + "://" + host + endpoint
	}
	return proto + "://" + net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)) + endpoint
}

// NewHTTPScan gets a new Scan instance for the given target
func (scanner *Scanner) newHTTPScan(t *zgrab2.ScanTarget, useHTTPS bool) *scan {
	ret := scan{
		scanner: scanner,
		target:  t,
		transport: &http.Transport{
			Proxy:               nil, // TODO: implement proxying
			DisableKeepAlives:   false,
			DisableCompression:  false,
			MaxIdleConnsPerHost: scanner.config.MaxRedirects,
		},
		client:         http.MakeNewClient(),
		globalDeadline: time.Now().Add(scanner.config.Timeout),
	}
	ret.transport.DialTLS = ret.getTLSDialer(t)
	ret.transport.DialContext = ret.dialContext
	ret.client.UserAgent = scanner.config.UserAgent
	ret.client.CheckRedirect = ret.getCheckRedirect()
	ret.client.Transport = ret.transport
	ret.client.Jar = nil // Don't send or receive cookies (otherwise use CookieJar)
	ret.client.Timeout = scanner.config.Timeout
	host := t.Domain
	if host == "" {
		host = t.IP.String()
	}
	// Scanner Target port overrides config flag port
	var port uint16
	if t.Port != nil {
		port = uint16(*t.Port)
	} else {
		port = uint16(scanner.config.BaseFlags.Port)
	}
	ret.url = getHTTPURL(useHTTPS, host, port, scanner.config.Endpoint)

	return &ret
}

// Grab performs the HTTP scan -- implementation taken from zgrab/zlib/grabber.go
func (scan *scan) Grab() *zgrab2.ScanError {
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
func (scanner *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	scan := scanner.newHTTPScan(&t, scanner.config.UseHTTPS)
	defer scan.Cleanup()
	err := scan.Grab()
	if err != nil {
		if scanner.config.RetryHTTPS && !scanner.config.UseHTTPS {
			scan.Cleanup()
			retry := scanner.newHTTPScan(&t, true)
			defer retry.Cleanup()
			retryError := retry.Grab()
			if retryError != nil {
				return retryError.Unpack(&retry.results)
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

package modules

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/url"
	"io"
	"net"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2/lib/http"
	"github.com/zmap/zgrab2"
)

type HTTPFlags struct {
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

type HTTPRequest struct {
	Method    string `json:"method,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Body      string `json:"body,omitempty"`
}

type HTTPHeaders map[string]interface{}

type HTTPResponse struct {
	VersionMajor int    `json:"version_major,omitempty"`
	VersionMinor int    `json:"version_minor,omitempty"`
	StatusCode   int    `json:"status_code,omitempty"`
	StatusLine   string `json:"status_line,omitempty"`
	Headers      HTTPHeaders `json:"headers,omitempty"`
	Body       string `json:"body,omitempty"`
	BodySHA256 []byte `json:"body_sha256,omitempty"`
}

type HTTPResults struct {
	ProxyRequest          *HTTPRequest     `json:"connect_request,omitempty"`
	ProxyResponse         *HTTPResponse    `json:"connect_response,omitempty"`
	Response              *http.Response   `json:"response,omitempty"`
	RedirectResponseChain []*http.Response `json:"redirect_response_chain,omitempty"`
}

type HTTPModule struct {
}

type HTTPScanner struct {
	config *HTTPFlags
}

// HTTPScan holds the state for a single scan (possibly entailing multiple connections)
type HTTPScan struct {
	scanner   *HTTPScanner
	target    *zgrab2.ScanTarget
	transport *http.Transport
	client    *http.Client
	results   HTTPResults
	url       string
}

func init() {
	var httpModule HTTPModule
	_, err := zgrab2.AddCommand("http", "HTTP Banner Grab", "Grab a banner over HTTP", 80, &httpModule)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *HTTPModule) NewFlags() interface{} {
	return new(HTTPFlags)
}

func (m *HTTPModule) NewScanner() zgrab2.Scanner {
	return new(HTTPScanner)
}

func (f *HTTPFlags) Validate(args []string) error {
	return nil
}

func (f *HTTPFlags) Help() string {
	return ""
}

func (s *HTTPScanner) Init(flags zgrab2.ScanFlags) error {
	fl, _ := flags.(*HTTPFlags)
	s.config = fl
	return nil
}

func (s *HTTPScanner) InitPerSender(senderID int) error {
	return nil
}

func (s *HTTPScanner) GetName() string {
	return s.config.Name
}

func (s *HTTPScan) getTLSDialer() func(net, addr string) (net.Conn, error) {
	return func(net, addr string) (net.Conn, error) {
		log.Warnf("** TLS DIALER: %s, %s ***", net, addr)
		outer, err := zgrab2.DialTimeoutConnection(net, addr, time.Second*time.Duration(s.scanner.config.BaseFlags.Timeout))
		if err != nil {
			return nil, err
		}
		tlsConn, err := s.scanner.config.TLSFlags.GetTLSConnection(outer)
		if err != nil {
			return nil, err
		}
		// lib/http/transport.go fills in the TLSLog in the http.Request instance(s)
		err = tlsConn.Handshake()
		return tlsConn, err
	}
}

func redirectsToLocalhost(host string) bool {
	if i := net.ParseIP(host); i != nil {
		return i.IsLoopback() || i.Equal(net.IPv4zero)
	} else {
		if host == "localhost" {
			return true
		} else {
			if addrs, err := net.LookupHost(host); err == nil {
				for _, i := range addrs {
					if ip := net.ParseIP(i); ip != nil {
						if ip.IsLoopback() || ip.Equal(net.IPv4zero) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

var ErrRedirLocalhost = errors.New("Redirecting to localhost")
var ErrTooManyRedirects = errors.New("Too many redirects")

func (s *HTTPScan) getCheckRedirect() func(*http.Request, *http.Response, []*http.Request) error {
	return func(req *http.Request, res *http.Response, via []*http.Request) error {
		if !s.scanner.config.FollowLocalhostRedirects && redirectsToLocalhost(req.URL.Hostname()) {
			return ErrRedirLocalhost
		}
		s.results.RedirectResponseChain = append(s.results.RedirectResponseChain, res)
		b := new(bytes.Buffer)
		maxReadLen := int64(s.scanner.config.MaxSize) * 1024
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

		if len(via) > s.scanner.config.MaxRedirects {
			return ErrTooManyRedirects
		}

		return nil
	}
}

var protoToPort = map[string]uint16{
	"http":  80,
	"https": 443,
}

func getHTTPURL(https bool, host string, port uint16, endpoint string) string {
	var proto string
	if https {
		proto = "https"
	} else {
		proto = "http"
	}
	if protoToPort[proto] == port {
		return proto + "://" + host + endpoint
	} else {
		return proto + "://" + net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)) + endpoint
	}
}

func (s *HTTPScanner) NewHTTPScan(t *zgrab2.ScanTarget) *HTTPScan {
	ret := HTTPScan{
		scanner: s,
		target:  t,
		transport: &http.Transport{
			Proxy:               nil, // TODO: implement proxying
			DisableKeepAlives:   false,
			DisableCompression:  false,
			MaxIdleConnsPerHost: s.config.MaxRedirects,
		},
		client: http.MakeNewClient(),
	}
	ret.transport.DialTLS = ret.getTLSDialer()
	ret.client.UserAgent = s.config.UserAgent
	ret.client.CheckRedirect = ret.getCheckRedirect()
	ret.client.Transport = ret.transport
	ret.client.Jar = nil // Don't send or receive cookies (otherwise use CookieJar)
	host := t.Domain
	if host == "" {
		host = t.IP.String()
	}
	ret.url = getHTTPURL(s.config.UseHTTPS, host, uint16(s.config.BaseFlags.Port), s.config.Endpoint)
	
	return &ret
}

func (s *HTTPScan) grab() *zgrab2.ScanError {
	// TODO: Allow body?
	request, err := http.NewRequest(s.scanner.config.Method, s.url, nil)
	if err != nil {
		return zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, err)
	}
	// TODO: Headers from input?
	request.Header.Set("Accept", "*/*")
	resp, err := s.client.Do(request)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	s.results.Response = resp
	if err != nil {
		if urlError, ok := err.(*url.Error); ok {
			log.Debugf("Swap out error: %v -> %v", err, urlError.Err)
			err = urlError.Err
		}
	}
	if err != nil {
		switch err {
		case ErrRedirLocalhost:
			err = nil
			break
		case ErrTooManyRedirects:
			return zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, err)
		default:
			return zgrab2.DetectScanError(err)			
		}
	}

	buf := new(bytes.Buffer)
	maxReadLen := int64(s.scanner.config.MaxSize) * 1024
	readLen := maxReadLen
	if resp.ContentLength >= 0 && resp.ContentLength < maxReadLen {
		readLen = resp.ContentLength
	}
	io.CopyN(buf, resp.Body, readLen)
	s.results.Response.BodyText = buf.String()
	if len(s.results.Response.BodyText) > 0 {
		m := sha256.New()
		m.Write(buf.Bytes())
		s.results.Response.BodySHA256 = m.Sum(nil)
	}

	return nil
} 

func (s *HTTPScanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	scan := s.NewHTTPScan(&t)
	err := scan.grab()
	if err != nil {
		return err.Unpack(&scan.results)
	}
	return zgrab2.SCAN_SUCCESS, &scan.results, nil
}

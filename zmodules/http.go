package zmodules

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2/zgrab2"
)

type HTTPModule struct {
	zgrab2.BaseModule
	HTTP HTTPOptions `json:"http"`
}

type HTTPOptions struct {
	Method       string `long:"method" default:"GET" description:"Set HTTP request method type"`
	Endpoint     string `long:"endpoint" default:"/" description:"Send an HTTP request to an endpoint"`
	UserAgent    string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent"`
	ProxyDomain  string `long:"proxy-domain" description:"Send a CONNECT <domain> first"`
	MaxSize      int    `long:"max-size" default:"256" description:"Max kilobytes to read in response to an HTTP request"`
	MaxRedirects int    `long:"max-redirects" default:"0" description:"Max number of redirects to follow"`
}

type HTTPRequest struct {
	Method    string `json:"method,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Body      string `json:"body,omitempty"`
}

type HTTPResponse struct {
	VersionMajor int    `json:"version_major,omitempty"`
	VersionMinor int    `json:"version_minor,omitempty"`
	StatusCode   int    `json:"status_code,omitempty"`
	StatusLine   string `json:"status_line,omitempty"`
	//Headers      HTTPHeaders `json:"headers,omitempty"`
	Body       string `json:"body,omitempty"`
	BodySHA256 []byte `json:"body_sha256,omitempty"`
}

type HTTPResults struct {
	ProxyRequest  *HTTPRequest  `json:"connect_request,omitempty"`
	ProxyResponse *HTTPResponse `json:"connect_response,omitempty"`
	//Response              *http.Response   `json:"response,omitempty"`
	//RedirectResponseChain []*http.Response `json:"redirect_response_chain,omitempty"`
}

// Per module initialization call
func init() {
	var httpModule HTTPModule
	cmd, err := zgrab2.AddCommand("http", "HTTP Banner Grab", "Grab a banner over HTTP", &httpModule)
	if err != nil {
		log.Fatal(err)
	}
	httpModule.SetDefaultPortAndName(cmd, uint(80), "http")
}

// Per module per goroutine initialization call
func (x HTTPModule) PerRoutineInitialize() {

}

// Validates the options sent to HTTPConfig, registers the config module, and then passes operation back to main
func (x *HTTPModule) Validate(args []string) error {
	zgrab2.RegisterLookup(x.Name, *x)
	return nil
}

func (x HTTPModule) Scan() (interface{}, error) {
	http := HTTPRequest{Method: "Get", Body: "testing"}
	ret := HTTPResults{ProxyRequest: &http}
	return ret, nil
}

package zmodules

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2/zgrab2"
)

type HTTPConfig struct {
	zgrab2.BaseProtocol
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

type HTTPResults struct {
}

func init() {
	var httpConfig HTTPConfig
	cmd, err := zgrab2.Parser.AddCommand("http", "HTTP Banner Grab", "Grab a banner over HTTP", &httpConfig)
	if err != nil {
		log.Fatal(err)
	}
	httpConfig.SetDefaultPortAndName(cmd, uint(80), "http")
}

// Validates the options sent to HTTPConfig, registers the config module, and then passes operation back to main
func (x *HTTPConfig) Validate(args []string) error {
	zgrab2.ValidateHighLevel()

	zgrab2.RegisterLookup(x.Name, x)
	return nil
}

func (x HTTPConfig) GetBanner() (interface{}, error) {
	return x, nil
}

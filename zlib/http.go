package zlib

type HTTPConfig struct {
	Port int         `short:"p" long:"port" default:"80" description:"Specify port to grab on" json:"port"`
	Name string      `short:"n" long:"name" default:"http" description:"Specify name for output json, only necessary if scanning multiple protocols" json:"-"`
	HTTP HTTPOptions `json:"http"`
}

type HTTPOptions struct {
	Method       string `long:"method" default:"GET" description:"Set HTTP request method type" json:"method"`
	Endpoint     string `long:"endpoint" default:"/" description:"Send an HTTP request to an endpoint" json:"endpoint"`
	UserAgent    string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent" json:"useragent"`
	ProxyDomain  string `long:"proxy-domain" description:"Send a CONNECT <domain> first" json:"proxydomain"`
	MaxSize      int    `long:"max-size" default:"256" description:"Max kilobytes to read in response to an HTTP request" json:"maxsize"`
	MaxRedirects int    `long:"max-redirects" default:"0" description:"Max number of redirects to follow" json:"maxredirects"`
}

// Execute validates the options sent to HTTPConfig and then passes operation back to main
func (x *HTTPConfig) Execute(args []string) error {
	validateHighLevel()

	return nil
}

func (x HTTPConfig) GetName() string {
	return x.Name
}

func (x HTTPConfig) GetPort() int {
	return x.Port
}

func (x HTTPConfig) GetBanner() HTTPConfig {
	return x
}

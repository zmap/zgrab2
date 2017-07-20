package zlib

type TLSConfig struct {
	Port                 int         `short:"p" long:"port" default:"443" description:"Specify port to grab on" json:"port"`
	Name                 string      `short:"n" long:"name" default:"tls" description:"Specify name for output json, only necessary if scanning multiple protocols" json:"-"`
	Heartbleed           bool        `long:"heartbleed" description:"Check if server is vulnerable to Heartbleed" json:"heart"`
	Version              int         `long:"version" description:"Max TLS version to use" json:"version"`
	Verbose              bool        `long:"verbose" description:"Add extra TLS information to JSON output (client hello, client KEX, key material, etc)" json:"verbose"`
	SessionTicket        bool        `long:"session-ticket" description:"Send support for TLS Session Tickets and output ticket if presented" json:"session"`
	ExtendedMasterSecret bool        `long:"extended-master-secret" description:"Offer RFC 7627 Extended Master Secret extension" json:"extended"`
	ExtendedRandom       bool        `long:"extended-random" description:"Send TLS Extended Random Extension" json:"extran"`
	NoSNI                bool        `long:"no-sni" description:"Do not send domain name in TLS Handshake regardless of whether known" json:"sni"`
	SCTExt               bool        `long:"sct" description:"Request Signed Certificate Timestamps during TLS Handshake" json:"sct"`
	HTTP                 HTTPOptions `json:"http"`
}

// Execute validates the options sent to TLSConfig and then passes operation back to main
func (x *TLSConfig) Execute(args []string) error {
	validateHighLevel()

	return nil
}

func (x TLSConfig) GetName() string {
	return x.Name
}

func (x TLSConfig) GetPort() int {
	return x.Port
}

func (x TLSConfig) GetBanner() TLSConfig {
	return x
}

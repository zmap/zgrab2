package zmodules

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type TLSModule struct {
	zgrab2.BaseModule
	Heartbleed           bool        `long:"heartbleed" description:"Check if server is vulnerable to Heartbleed"`
	Version              int         `long:"version" description:"Max TLS version to use"`
	Verbose              bool        `long:"verbose" description:"Add extra TLS information to JSON output (client hello, client KEX, key material, etc)" json:"verbose"`
	SessionTicket        bool        `long:"session-ticket" description:"Send support for TLS Session Tickets and output ticket if presented" json:"session"`
	ExtendedMasterSecret bool        `long:"extended-master-secret" description:"Offer RFC 7627 Extended Master Secret extension" json:"extended"`
	ExtendedRandom       bool        `long:"extended-random" description:"Send TLS Extended Random Extension" json:"extran"`
	NoSNI                bool        `long:"no-sni" description:"Do not send domain name in TLS Handshake regardless of whether known" json:"sni"`
	SCTExt               bool        `long:"sct" description:"Request Signed Certificate Timestamps during TLS Handshake" json:"sct"`
	HTTP                 HTTPOptions `json:"http"`
}

func init() {
	var tlsModule TLSModule
	cmd, err := zgrab2.AddCommand("tls", "TLS Banner Grab", "Grab banner over TLS", &tlsModule)
	if err != nil {
		log.Fatal(err)
	}
	tlsModule.SetDefaultPortAndName(cmd, uint(443), "ssh")
}

func (x *TLSModule) New() interface{} {
	return new(TLSModule)
}

func (x *TLSModule) PerRoutineInitialize() {

}

// Execute validates the options sent to TLSModule and then passes operation back to main
func (x *TLSModule) Validate(args []string) error {
	zgrab2.RegisterLookup(x.Name, x)
	return nil
}

func (x *TLSModule) Scan() (interface{}, error) {
	return x, nil
}

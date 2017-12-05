package zgrab2

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zcrypto/tls"
)

// Scanner is an interface that represents all functions necessary to run a scan
type Scanner interface {
	// Init runs once for this module at library init time
	Init(flags ScanFlags) error

	// InitPerSender runs once per Goroutine. A single Goroutine will scan some non-deterministics
	// subset of the input scan targets
	InitPerSender(senderID int) error

	// Returns the name passed at init
	GetName() string

	// Scan connects to a host. The result should be JSON-serializable
	Scan(t ScanTarget) (interface{}, error)
}

// ScanModule is an interface which represents a module that the framework can
// manipulate
type ScanModule interface {
	// NewFlags is called by the framework to pass to the argument parser. The parsed flags will be passed
	// to the scanner created by NewScanner().
	NewFlags() interface{}

	// NewScanner is called by the framework for each time an individual scan is specified in the config or on
	// the command-line. The framework will then call scanner.Init(name, flags).
	NewScanner() Scanner
}

// ScanFlags is an interface which must be implemented by all types sent to
// the flag parser
type ScanFlags interface {
	// Help optionally returns any additional help text, e.g. specifying what empty defaults
	// are interpreted as.
	Help() string

	// Validate enforces all command-line flags and positional arguments have valid values.
	Validate(args []string) error
}

// BaseFlags contains the options that every flags type must embed
type BaseFlags struct {
	Port    uint   `short:"p" long:"port" description:"Specify port to grab on"`
	Name    string `short:"n" long:"name" description:"Specify name for output json, only necessary if scanning multiple modules"`
	Timeout uint   `short:"t" long:"timeout" description:"Set connection timeout in seconds"`
}

// GetName returns the name of the respective scanner
func (b *BaseFlags) GetName() string {
	return b.Name
}

// Adapted from modules/ssh.go
type TLSFlags struct {
	Heartbleed bool `long:"heartbleed" description:"Check if server is vulnerable to Heartbleed"`

	SessionTicket        bool `long:"session-ticket" description:"Send support for TLS Session Tickets and output ticket if presented" json:"session"`
	ExtendedMasterSecret bool `long:"extended-master-secret" description:"Offer RFC 7627 Extended Master Secret extension" json:"extended"`
	ExtendedRandom       bool `long:"extended-random" description:"Send TLS Extended Random Extension" json:"extran"`
	NoSNI                bool `long:"no-sni" description:"Do not send domain name in TLS Handshake regardless of whether known" json:"sni"`
	SCTExt               bool `long:"sct" description:"Request Signed Certificate Timestamps during TLS Handshake" json:"sct"`

	Time string `long:"time" description:"Explicit request time to use, instead of clock. YYYYMMDDhhmmss format."`
	// TODO: directory? glob? How to map server name -> certificate?
	Certificates string `long:"certificates" description:"Set of certificates to present to the server"`
	// TODO: re-evaluate this, or at least specify the file format
	CertificateMap string `long:"certificate-map" description:"A file mapping server names to certificates"`
	// TODO: directory? glob?
	RootCAs string `long:"root-cas" description:"Set of certificates to use when verifying server certificates"`
	// TODO: format?
	NextProtos              string `long:"next-protos" description:"A list of supported application-level protocols"`
	ServerName              string `long:"server-name" description:"Server name used for certificate verification and (optionally) SNI"`
	VerifyServerCertificate bool   `long:"verify-server-certificate" description:"If set, the scan will fail if the server certificate does not match the server-name, or does not chain to a trusted root."`
	// TODO: format? mapping? zgrab1 had flags like ChromeOnly, FirefoxOnly, etc...
	CipherSuite      string `long:"cipher-suite" description:"A list of cipher suites to use."`
	MinVersion       int    `long:"min-version" description:"The minimum SSL/TLS version that is acceptable. 0 means that SSLv3 is the minimum."`
	MaxVersion       int    `long:"max-version" description:"The maximum SSL/TLS version that is acceptable. 0 means use the highest supported value."`
	CurvePreferences string `long:"curve-preferences" description:"A list of elliptic curves used in an ECDHE handshake, in order of preference."`
	NoECDHE          bool   `long:"no-ecdhe" description:"Do not allow ECDHE handshakes"`
	// TODO: format?
	SignatureAlgorithms string `long:"signature-algorithms" description:"Signature and hash algorithms that are acceptable"`
	HeartbeatEnabled    bool   `long:"heartbeat-enabled" description:"If set, include the heartbeat extension"`
	DSAEnabled          bool   `long:"dsa-enabled" description:"Accept server DSA keys"`
	//ExtendedRandom       bool   `long:"extended-random" description:"Use extended random"`
	// ForceSesionTicket -> SessionTicket
	//ForceSessionTicket   bool   `long:"force-session-ticket" description:"Force Client Hello to send TLS Session Ticket extension"`
	//ExtendedMasterSecret bool   `long:"extended-master-secret" description:"Enable Extended Master Secret extension"`
	// SignedCertificateTimestampExt -> SCTExt
	// TODO: format?
	ClientRandom string `long:"client-random" description:"Set an explicit Client Random (base64 encoded)"`
	// TODO: format?
	ClientHello string `long:"client-hello" description:"Set an explicit ClientHello (base64 encoded)"`
}

func getCSV(arg string) []string {
	// TODO: Find standard way to pass array-valued options
	split := strings.Split(arg, ",")
	ret := make([]string, len(split))
	for i, v := range split {
		ret[i] = strings.Trim(v, " \t")
	}
	return ret
}

func (t *TLSFlags) GetTLSConfig() (*tls.Config, error) {
	var err error

	// TODO: Find standard names
	cipherMap := map[string][]uint16{
		"dhe-only":        tls.DHECiphers,
		"ecdhe-only":      tls.ECDHECiphers,
		"exports-dh-only": tls.DHEExportCiphers,
		"chrome-only":     tls.ChromeCiphers,
		"chrome-no-dhe":   tls.ChromeNoDHECiphers,
		"firefox-only":    tls.FirefoxCiphers,
		"firefox-no-dhe":  tls.FirefoxNoDHECiphers,
		"safari-only":     tls.SafariCiphers,
		"safari-no-dhe":   tls.SafariNoDHECiphers}

	ret := tls.Config{}

	if t.Time != "" {
		// TODO: Find standard time format
		var baseTime time.Time
		baseTime, err = time.Parse("20060102150405Z", t.Time)
		if err != nil {
			return nil, fmt.Errorf("Error parsing time '%s': %s", t.Time, err)
		}
		startTime := time.Now()
		ret.Time = func() time.Time {
			offset := time.Now().Sub(startTime)
			// Return (now - startTime) + baseTime
			return baseTime.Add(offset)
		}
	}
	if t.Certificates != "" {
		// TODO FIXME: Implement
		log.Warnf("--certificates not implemented")
	}
	if t.CertificateMap != "" {
		// TODO FIXME: Implement
		log.Warnf("--certificate-map not implemented")
	}
	if t.RootCAs != "" {
		// TODO FIXME: Implement
		log.Warnf("--root-cas not implemented")
	}
	if t.NextProtos != "" {
		// TODO: Different format?
		ret.NextProtos = getCSV(t.NextProtos)
	}
	if t.ServerName != "" {
		// TODO: In the original zgrab, this was only set of NoSNI was not set (though in that case, it set it to the scanning host name)
		ret.ServerName = t.ServerName
	}
	if t.VerifyServerCertificate {
		ret.InsecureSkipVerify = false
	} else {
		ret.InsecureSkipVerify = true
	}

	if t.CipherSuite != "" {
		ret.CipherSuites = cipherMap[t.CipherSuite]
		if ret.CipherSuites == nil {
			return nil, fmt.Errorf("%s is not a valid cipher suite", t.CipherSuite)
		}
	}

	if t.MinVersion != 0 {
		ret.MinVersion = uint16(t.MinVersion)
	}

	if t.MaxVersion != 0 {
		ret.MaxVersion = uint16(t.MaxVersion)
	}

	if t.CurvePreferences != "" {
		// TODO FIXME: Implement (how to map curveName to CurveID? Or are there standard 'suites' like we use for cipher suites?)
		log.Warnf("--curve-preferences not implemented")
	}

	if t.NoECDHE {
		ret.ExplicitCurvePreferences = true
		ret.CurvePreferences = nil
	}

	if t.SignatureAlgorithms != "" {
		// TODO FIXME: Implement (none of the signatureAndHash functions/consts are exported from common.go...?)
		log.Warnf("--signature-algorithms not implemented")
	}

	if t.HeartbeatEnabled {
		ret.HeartbeatEnabled = true
	} else {
		ret.HeartbeatEnabled = false
	}

	if t.DSAEnabled {
		ret.ClientDSAEnabled = true
	} else {
		ret.ClientDSAEnabled = false
	}

	if t.ExtendedRandom {
		ret.ExtendedRandom = true
	} else {
		ret.ExtendedRandom = false
	}

	if t.SessionTicket {
		ret.ForceSessionTicketExt = true
	} else {
		ret.ForceSessionTicketExt = false
	}

	if t.ExtendedMasterSecret {
		ret.ExtendedMasterSecret = true
	} else {
		ret.ExtendedMasterSecret = false
	}

	if t.SCTExt {
		ret.SignedCertificateTimestampExt = true
	} else {
		ret.SignedCertificateTimestampExt = false
	}

	if t.ClientRandom != "" {
		ret.ClientRandom, err = base64.StdEncoding.DecodeString(t.ClientRandom)
		if err != nil {
			return nil, fmt.Errorf("Error decoding --client-random value '%s': %s", t.ClientRandom, err)
		}
	}

	if t.ClientHello != "" {
		ret.ExternalClientHello, err = base64.StdEncoding.DecodeString(t.ClientHello)
		if err != nil {
			return nil, fmt.Errorf("Error decoding --client-hello value '%s': %s", t.ClientHello, err)
		}
	}

	return &ret, nil
}

type ZGrabConnection struct {
	tls.Conn
	HeartbleedChecked    bool
	HeartbleedVulnerable bool
	flags                *TLSFlags
}

type ZGrabHandshakeLog struct {
	HandshakeLog         *tls.ServerHandshake `json:"handshake_log"`
	HeartbleedVulnerable bool                 `json:"heartbleed_vulnerable"`
	HeartbleedChecked    bool                 `json:"heartbleed_checked"`
}

func (z *ZGrabConnection) GetHandshakeLog() *ZGrabHandshakeLog {
	temp := z.Conn.GetHandshakeLog()
	return &ZGrabHandshakeLog{
		HandshakeLog:         temp,
		HeartbleedChecked:    z.HeartbleedChecked,
		HeartbleedVulnerable: z.HeartbleedVulnerable}
}

func (z *ZGrabConnection) Handshake() error {
	if z.flags.Heartbleed {
		z.HeartbleedChecked = true
		buf := make([]byte, 256)
		_, err := z.CheckHeartbleed(buf)
		z.GetHeartbleedLog()
		if err != nil {
			z.HeartbleedVulnerable = true
		}
		return err
	} else {
		z.HeartbleedVulnerable = false
		z.HeartbleedChecked = false
		return z.Conn.Handshake()
	}
}

func (t *TLSFlags) GetZGrabTLSConnection(conn *net.Conn) (*ZGrabConnection, error) {
	cfg, err := t.GetTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("Error getting TLSConfig for options: %s", err)
	}
	tlsClient := tls.Client(*conn, cfg)
	zClient := ZGrabConnection{
		Conn:              *tlsClient,
		HeartbleedChecked: false,
		flags:             t,
	}
	return &zClient, nil
}

// GetModule returns the registered module that corresponds to the given name
// or nil otherwise
func GetModule(name string) *ScanModule {
	return modules[name]
}

var modules map[string]*ScanModule

func init() {
	modules = make(map[string]*ScanModule)
}

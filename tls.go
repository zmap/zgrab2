package zgrab2

import (
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zcrypto/x509"
)

// Shared code for TLS scans.
// Example usage:
// (include TLSFlags in ScanFlags implementation)
// (in scanning code, where you would call tls.Client()):
// tlsConnection, err := myScanFlags.TLSFlags.GetTLSConnection(myModule.netConn)
// err := tlsConnection.Handshake()
// myModule.netConn = tlsConnection
// result.tls = tlsConnection.GetLog()

// Common flags for TLS configuration -- include this in your module's ScanFlags implementation to use the common TLS code
// Adapted from modules/ssh.go
type TLSFlags struct {
	Heartbleed bool `long:"heartbleed" description:"Check if server is vulnerable to Heartbleed"`

	SessionTicket        bool `long:"session-ticket" description:"Send support for TLS Session Tickets and output ticket if presented" json:"session"`
	ExtendedMasterSecret bool `long:"extended-master-secret" description:"Offer RFC 7627 Extended Master Secret extension" json:"extended"`
	ExtendedRandom       bool `long:"extended-random" description:"Send TLS Extended Random Extension" json:"extran"`
	NoSNI                bool `long:"no-sni" description:"Do not send domain name in TLS Handshake regardless of whether known" json:"sni"`
	SCTExt               bool `long:"sct" description:"Request Signed Certificate Timestamps during TLS Handshake" json:"sct"`

	// TODO: Do we just lump this with Verbose (and put Verbose in TLSFlags)?
	KeepClientLogs bool `long:"keep-client-logs" description:"Include the client-side logs in the TLS handshake"`

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
	CipherSuite      string `long:"cipher-suite" description:"A comma-delimited list of hex cipher suites to advertise."`
	MinVersion       int    `long:"min-version" description:"The minimum SSL/TLS version that is acceptable. 0 means that SSLv3 is the minimum."`
	MaxVersion       int    `long:"max-version" description:"The maximum SSL/TLS version that is acceptable. 0 means use the highest supported value."`
	CurvePreferences string `long:"curve-preferences" description:"A list of elliptic curves used in an ECDHE handshake, in order of preference."`
	NoECDHE          bool   `long:"no-ecdhe" description:"Do not allow ECDHE handshakes"`
	// TODO: format?
	SignatureAlgorithms string `long:"signature-algorithms" description:"Signature and hash algorithms that are acceptable"`
	HeartbeatEnabled    bool   `long:"heartbeat-enabled" description:"If set, include the heartbeat extension"`
	DSAEnabled          bool   `long:"dsa-enabled" description:"Accept server DSA keys"`
	// TODO: format?
	ClientRandom string `long:"client-random" description:"Set an explicit Client Random (base64 encoded)"`
	// TODO: format?
	ClientHello string `long:"client-hello" description:"Set an explicit ClientHello (base64 encoded)"`
}

func getCSV(arg string) []string {
	// TODO: Find standard way to pass array-valued options
	reader := csv.NewReader(strings.NewReader(arg))
	ret, err := reader.ReadAll()
	if err != nil {
		log.Fatalf("Error parsing CSV argument '%s': %s", arg, err)
	}
	if len(ret) != 1 {
		log.Fatalf("Bad CSV -- must have exactly one row (%s)", arg)
	}
	for i, v := range ret[0] {
		ret[0][i] = strings.Trim(v, " \t")
	}
	return ret[0]
}

func (t *TLSFlags) GetTLSConfig() (*tls.Config, error) {
	return t.GetTLSConfigForTarget(nil)
}

func (t *TLSFlags) GetTLSConfigForTarget(target *ScanTarget) (*tls.Config, error) {
	var err error

	// TODO: Find standard names
	cipherMap := map[string][]uint16{
		"portable":        tls.PortableCiphers,
		"dhe-only":        tls.DHECiphers,
		"ecdhe-only":      tls.ECDHECiphers,
		"exports-dh-only": tls.DHEExportCiphers,
		"chrome-only":     tls.ChromeCiphers,
		"chrome-no-dhe":   tls.ChromeNoDHECiphers,
		"firefox-only":    tls.FirefoxCiphers,
		"firefox-no-dhe":  tls.FirefoxNoDHECiphers,
		"safari-only":     tls.SafariCiphers,
		"safari-no-dhe":   tls.SafariNoDHECiphers,
	}

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
		log.Fatalf("--certificates not implemented")
	}
	if t.CertificateMap != "" {
		// TODO FIXME: Implement
		log.Fatalf("--certificate-map not implemented")
	}
	if t.RootCAs != "" {
		var fd *os.File
		if fd, err = os.Open(t.RootCAs); err != nil {
			log.Fatal(err)
		}
		caBytes, readErr := ioutil.ReadAll(fd)
		if readErr != nil {
			log.Fatal(err)
		}
		ret.RootCAs = x509.NewCertPool()
		ok := ret.RootCAs.AppendCertsFromPEM(caBytes)
		if !ok {
			log.Fatalf("Could not read certificates from PEM file. Invalid PEM?")
		}
	}
	if t.NextProtos != "" {
		// TODO: Different format?
		ret.NextProtos = getCSV(t.NextProtos)
	}
	if t.ServerName != "" {
		// TODO: In the original zgrab, this was only set of NoSNI was not set (though in that case, it set it to the scanning host name)
		// Here, if an explicit ServerName is given, set that, ignoring NoSNI.
		ret.ServerName = t.ServerName
	} else {
		// If no explicit ServerName is given, and SNI is not disabled, use the
		// target's domain name (if available).
		if !t.NoSNI && target != nil {
			ret.ServerName = target.Domain
		}
	}
	if t.VerifyServerCertificate {
		ret.InsecureSkipVerify = false
	} else {
		ret.InsecureSkipVerify = true
	}

	if t.CipherSuite != "" {
		// allow either one of our standard values (e.g., chrome) or a comma-delimited list of ciphers
		if _, ok := cipherMap[t.CipherSuite]; ok {
			ret.CipherSuites = cipherMap[t.CipherSuite]
		} else {
			strCiphers := getCSV(t.CipherSuite)
			var intCiphers = make([]uint16, len(strCiphers))
			for i, s := range strCiphers {
				s = strings.TrimPrefix(s, "0x")
				v64, err := strconv.ParseUint(s, 16, 16)
				if err != nil {
					log.Fatalf("cipher suites: unable to convert %s to a 16bit integer: %s", s, err)
				}
				intCiphers[i] = uint16(v64)
			}
			ret.CipherSuites = intCiphers
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
		log.Fatalf("--curve-preferences not implemented")
	}

	if t.NoECDHE {
		ret.ExplicitCurvePreferences = true
		ret.CurvePreferences = nil
	}

	if t.SignatureAlgorithms != "" {
		// TODO FIXME: Implement (none of the signatureAndHash functions/consts are exported from common.go...?)
		log.Fatalf("--signature-algorithms not implemented")
	}

	if t.HeartbeatEnabled || t.Heartbleed {
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

type TLSConnection struct {
	tls.Conn
	flags *TLSFlags
	log   *TLSLog
}

type TLSLog struct {
	// TODO include TLSFlags?
	HandshakeLog *tls.ServerHandshake `json:"handshake_log"`
	// This will be nil if heartbleed is not checked because of client configuration flags
	HeartbleedLog *tls.Heartbleed `json:"heartbleed_log,omitempty"`
}

func (z *TLSConnection) GetLog() *TLSLog {
	if z.log == nil {
		z.log = &TLSLog{}
	}

	return z.log
}

func (z *TLSConnection) Handshake() error {
	log := z.GetLog()
	if z.flags.Heartbleed {
		buf := make([]byte, 256)
		defer func() {
			log.HandshakeLog = z.Conn.GetHandshakeLog()
			log.HeartbleedLog = z.Conn.GetHeartbleedLog()
		}()
		// TODO - CheckHeartbleed does not bubble errors from Handshake
		_, err := z.CheckHeartbleed(buf)
		if err == tls.HeartbleedError {
			err = nil
		}
		return err
	} else {
		defer func() {
			log.HandshakeLog = z.Conn.GetHandshakeLog()
			log.HeartbleedLog = nil
		}()
		return z.Conn.Handshake()
	}
}

// Close the underlying connection.
func (conn *TLSConnection) Close() error {
	return conn.Conn.Close()
}

// Connect opens the TCP connection to the target using the given configuration,
// and then returns the configured wrapped TLS connection. The caller must still
// call Handshake().
func (t *TLSFlags) Connect(target *ScanTarget, flags *BaseFlags) (*TLSConnection, error) {
	tcpConn, err := target.Open(flags)
	if err != nil {
		return nil, err
	}
	return t.GetTLSConnectionForTarget(tcpConn, target)
}

func (t *TLSFlags) GetTLSConnection(conn net.Conn) (*TLSConnection, error) {
	return t.GetTLSConnectionForTarget(conn, nil)
}

func (t *TLSFlags) GetTLSConnectionForTarget(conn net.Conn, target *ScanTarget) (*TLSConnection, error) {
	cfg, err := t.GetTLSConfigForTarget(target)
	if err != nil {
		return nil, fmt.Errorf("Error getting TLSConfig for options: %s", err)
	}
	return t.GetWrappedConnection(conn, cfg), nil
}

func (t *TLSFlags) GetWrappedConnection(conn net.Conn, cfg *tls.Config) *TLSConnection {
	tlsClient := tls.Client(conn, cfg)
	wrappedClient := TLSConnection{
		Conn:  *tlsClient,
		flags: t,
	}
	return &wrappedClient
}

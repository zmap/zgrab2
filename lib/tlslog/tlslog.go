package tlslog

import "github.com/zmap/zcrypto/tls"

type TLSLog struct {
	// TODO include TLSFlags?
	HandshakeLog *tls.ServerHandshake `json:"handshake_log"`
}

type TLSConnection struct {
	tls.Conn
	Flags *TLSFlags
	log   *TLSLog
}

func (z *TLSConnection) GetLog() *TLSLog {
	if z.log == nil {
		z.log = &TLSLog{}
	}

	return z.log
}

func (z *TLSConnection) Handshake() error {
	log := z.GetLog()
	defer func() {
		log.HandshakeLog = z.Conn.GetHandshakeLog()
	}()
	return z.Conn.Handshake()

}

// Close the underlying connection.
func (conn *TLSConnection) Close() error {
	return conn.Conn.Close()
}

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
	Config *tls.Config // Config is ready to use TLS configuration

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
	MinVersion       int    `long:"min-version" description:"The minimum SSL/TLS version that is acceptable. 0 means that TLS1.0 is the minimum."`
	MaxVersion       int    `long:"max-version" description:"The maximum SSL/TLS version that is acceptable. 0 means use the highest supported value."`
	CurvePreferences string `long:"curve-preferences" description:"A list of elliptic curves used in an ECDHE handshake, in order of preference."`
	NoECDHE          bool   `long:"no-ecdhe" description:"Do not allow ECDHE handshakes"`
	// TODO: format?
	SignatureAlgorithms string `long:"signature-algorithms" description:"Signature and hash algorithms that are acceptable"`
	DSAEnabled          bool   `long:"dsa-enabled" description:"Accept server DSA keys"`
	// TODO: format?
	ClientRandom string `long:"client-random" description:"Set an explicit Client Random (base64 encoded)"`
	// TODO: format?
	ClientHello string `long:"client-hello" description:"Set an explicit ClientHello (base64 encoded)"`
	OverrideSH  bool   `long:"override-sig-hash" description:"Override the default SignatureAndHashes TLS option with more expansive default"`
}

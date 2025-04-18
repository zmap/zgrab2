package zgrab2

import (
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zcrypto/encoding/asn1"
	"github.com/zmap/zcrypto/tls"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zcrypto/x509/pkix"

	tlslog "github.com/zmap/zgrab2/tls"
)

// Shared code for TLS scans.
// Example usage:
// (include TLSFlags in ScanFlags implementation)
// (in scanning code, where you would call tls.Client()):
// tlsConnection, err := myScanFlags.TLSFlags.GetTLSConnection(myModule.netConn)
// err := tlsConnection.Handshake()
// myModule.netConn = tlsConnection
// result.tls = tlsConnection.GetLog()

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

func GetTLSConfig(t *tlslog.Flags) (*tls.Config, error) {
	return GetTLSConfigForTarget(t, nil)
}

func GetTLSConfigForTarget(t *tlslog.Flags, target *ScanTarget) (*tls.Config, error) {
	var err error

	// Config already exists
	if t.Config != nil {
		return t.Config, nil
	}

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

	asn1.AllowPermissiveParsing = true
	pkix.LegacyNameString = true

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

	if t.OverrideSH {
		ret.SignatureAndHashes = []tls.SigAndHash{
			{0x01, 0x04}, // rsa, sha256
			{0x03, 0x04}, // ecdsa, sha256
			{0x01, 0x02}, // rsa, sha1
			{0x03, 0x02}, // ecdsa, sha1
			{0x01, 0x04}, // rsa, sha256
			{0x01, 0x05}, // rsa, sha384
			{0x01, 0x06}, // rsa, sha512
		}
	}

	return &ret, nil
}

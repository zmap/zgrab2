package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/zmap/zcrypto/tls"
)

// JA4SProtocol is the transport protocol prefix used in JA4S fingerprints.
type JA4SProtocol string

// Protocol identifiers for JA4S fingerprints.
const (
	JA4SProtocolDTLS JA4SProtocol = "d"
	JA4SProtocolTLS  JA4SProtocol = "t"
	JA4SProtocolQUIC JA4SProtocol = "q"
)

var tlsVersionShortNames = map[tls.TLSVersion]string{
	0x0002: "s2",
	0x0300: "s3",
	0x0301: "10",
	0x0302: "11",
	0x0303: "12",
	0x0304: "13",
}

// JA4S computes a JA4S fingerprint from a TLS ServerHandshake log.
// protocol should be JA4SProtocolTLS, JA4SProtocolQUIC, or JA4SProtocolDTLS.
// Returns empty string if the ServerHello is absent.
func JA4S(protocol JA4SProtocol, log *tls.ServerHandshake) string {
	if log == nil || log.ServerHello == nil {
		return ""
	}

	hello := log.ServerHello

	// TLS 1.3 signals the negotiated version via the SupportedVersions extension.
	// TLS 1.2 and below use ServerHello.Version directly.
	var version tls.TLSVersion
	if hello.SupportedVersions != nil {
		version = hello.SupportedVersions.SelectedVersion
	} else {
		version = hello.Version
	}

	return fmt.Sprintf(
		"%s%s%02d%s_%s_%s",
		protocol,
		tlsShortVersion(version),
		len(hello.ExtensionIdentifiers),
		ja4sALPN(hello.AlpnProtocol),
		ja4sCipherSuite(hello.CipherSuite),
		ja4sExtensionsHash(hello.ExtensionIdentifiers),
	)
}

func tlsShortVersion(version tls.TLSVersion) string {
	if name, ok := tlsVersionShortNames[version]; ok {
		return name
	}

	return ""
}

func ja4sCipherSuite(cs tls.CipherSuiteID) string {
	dst := make([]byte, 4)
	hex.Encode(dst, cs.Bytes())

	return string(dst)
}

func ja4sALPN(alpn string) string {
	if alpn == "" {
		return "00"
	}

	if len(alpn) > 2 {
		alpn = string([]byte{alpn[0], alpn[len(alpn)-1]})
	}

	if alpn[0] > 127 {
		return "99"
	}

	return alpn
}

func ja4sExtensionsHash(ids []uint16) string {
	if len(ids) == 0 {
		return "000000000000"
	}

	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%04x", id)
	}

	joined := strings.Join(parts, ",")
	hash := sha256.Sum256([]byte(joined))

	return hex.EncodeToString(hash[:])[:12]
}

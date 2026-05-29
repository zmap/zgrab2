package fingerprint

import (
	"bytes"
	"crypto/md5"
	"fmt"

	"github.com/zmap/zcrypto/tls"
)

// JA3S computes a JA3S fingerprint from a TLS ServerHandshake log.
// Format: md5(<SSLVersion>,<CipherSuite>,<Extensions IDs hyphen delimited>)
func JA3S(log *tls.ServerHandshake) string {
	if log == nil || log.ServerHello == nil {
		return ""
	}

	hello := log.ServerHello

	var prehash bytes.Buffer
	fmt.Fprintf(&prehash, "%d,%d,", hello.Version, hello.CipherSuite)

	for i, id := range hello.ExtensionIdentifiers {
		fmt.Fprintf(&prehash, "%d", id)
		if i < len(hello.ExtensionIdentifiers)-1 {
			prehash.WriteString("-")
		}
	}

	h := md5.New()
	h.Write(prehash.Bytes())

	return fmt.Sprintf("%x", h.Sum(nil))
}

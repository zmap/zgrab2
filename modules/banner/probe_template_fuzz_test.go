package banner

import (
	"net"
	"testing"
	"time"
)

type zeroReader struct{}

func (zeroReader) Read(data []byte) (int, error) {
	clear(data)
	return len(data), nil
}

func FuzzParseProbeTemplate(f *testing.F) {
	f.Add([]byte("static probe"))
	f.Add([]byte("${SADDR}:${SPORT}"))
	f.Add([]byte("${RAND_BYTE=16}${HEX=00ff}${NTP_TIMESTAMP}"))
	f.Add([]byte("${UNKNOWN=literal}${DADDR"))
	f.Add([]byte("${RAND_ALPHA=-1}"))

	f.Fuzz(func(t *testing.T, data []byte) {
		template, err := parseProbeTemplate(data)
		if err != nil || len(data) > 4096 {
			return
		}

		_, err = template.expand(&probeTemplateContext{
			sourceIP:        net.IPv4(192, 0, 2, 1),
			destinationIP:   net.IPv4(198, 51, 100, 2),
			sourcePort:      12345,
			destinationPort: 443,
			now:             time.Unix(1_700_000_000, 500_000_000),
			random:          zeroReader{},
		})
		if err != nil {
			t.Fatalf("expand parsed template: %v", err)
		}
	})
}

package fingerprint

import (
	"testing"

	"github.com/zmap/zcrypto/tls"
)

func TestJA3S(t *testing.T) {
	tests := []struct {
		name string
		log  *tls.ServerHandshake
		want string
	}{
		{
			name: "nil log",
			log:  nil,
			want: "",
		},
		{
			name: "nil ServerHello",
			log:  &tls.ServerHandshake{},
			want: "",
		},
		{
			// tls-alpn-h2.pcap: TLS 1.2, cipher=0xcca9, exts=[0x0000,0xff01,0x000b,0x0010]
			// prehash: "771,52393,0-65281-11-16"
			name: "TLS 1.2 with extensions",
			log: &tls.ServerHandshake{
				ServerHello: &tls.ServerHello{
					Version:              0x0303,
					CipherSuite:          0xcca9,
					ExtensionIdentifiers: []uint16{0x0000, 0xff01, 0x000b, 0x0010},
				},
			},
			want: "7f76f3e952a1bc7d407366fafe1db7ed",
		},
		{
			// tls-non-ascii-alpn / tls3: TLS 1.3 (legacy version 0x0303), cipher=0x1301, exts=[0x0033,0x002b]
			// prehash: "771,4865,51-43"
			name: "TLS 1.3 with two extensions",
			log: &tls.ServerHandshake{
				ServerHello: &tls.ServerHello{
					Version:              0x0303,
					CipherSuite:          0x1301,
					ExtensionIdentifiers: []uint16{0x0033, 0x002b},
				},
			},
			want: "eb1d94daa7e0344597e756a1fb6e7054",
		},
		{
			// prehash: "771,4865,"
			name: "no extensions",
			log: &tls.ServerHandshake{
				ServerHello: &tls.ServerHello{
					Version:     0x0303,
					CipherSuite: 0x1301,
				},
			},
			want: "e8c07683aecf9b16e8e33f10a5161e4e",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := JA3S(tt.log)
			if got != tt.want {
				t.Errorf("JA3S() = %q, want %q", got, tt.want)
			}
		})
	}
}

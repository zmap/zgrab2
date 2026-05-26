package fingerprint

import (
	"testing"

	"github.com/zmap/zcrypto/tls"
)

func TestJA4S(t *testing.T) {
	tests := []struct {
		name     string
		protocol JA4SProtocol
		log      *tls.ServerHandshake
		want     string
	}{
		{
			name:     "nil log",
			protocol: JA4SProtocolTLS,
			log:      nil,
			want:     "",
		},
		{
			name:     "nil ServerHello",
			protocol: JA4SProtocolTLS,
			log:      &tls.ServerHandshake{},
			want:     "",
		},
		{
			// tls-non-ascii-alpn.pcapng: TLS 1.3, no ALPN, cipher=0x1301, exts=[0x0033,0x002b]
			// SHA256("0033,002b")[:12] = "234ea6891581"
			name:     "TLS 1.3 no ALPN two extensions",
			protocol: JA4SProtocolTLS,
			log: &tls.ServerHandshake{
				ServerHello: &tls.ServerHello{
					Version:     0x0303,
					CipherSuite: 0x1301,
					SupportedVersions: &tls.SupportedVersionsExt{
						SelectedVersion: 0x0304,
					},
					ExtensionIdentifiers: []uint16{0x0033, 0x002b},
				},
			},
			want: "t130200_1301_234ea6891581",
		},
		{
			// tls3.pcapng: TLS 1.3, no ALPN, cipher=0x1301, exts=[0x002b,0x0033,0x0029]
			// SHA256("002b,0033,0029")[:12] = "0ee26285a86f"
			name:     "TLS 1.3 no ALPN three extensions",
			protocol: JA4SProtocolTLS,
			log: &tls.ServerHandshake{
				ServerHello: &tls.ServerHello{
					Version:     0x0303,
					CipherSuite: 0x1301,
					SupportedVersions: &tls.SupportedVersionsExt{
						SelectedVersion: 0x0304,
					},
					ExtensionIdentifiers: []uint16{0x002b, 0x0033, 0x0029},
				},
			},
			want: "t130300_1301_0ee26285a86f",
		},
		{
			// tls-alpn-h2.pcap: TLS 1.2 (no SupportedVersions), ALPN="h2", cipher=0xcca9, exts=[0x0000,0xff01,0x000b,0x0010]
			// SHA256("0000,ff01,000b,0010")[:12] = "1428ce7b4018"
			name:     "TLS 1.2 ALPN h2 four extensions",
			protocol: JA4SProtocolTLS,
			log: &tls.ServerHandshake{
				ServerHello: &tls.ServerHello{
					Version:              0x0303,
					CipherSuite:          0xcca9,
					AlpnProtocol:         "h2",
					ExtensionIdentifiers: []uint16{0x0000, 0xff01, 0x000b, 0x0010},
				},
			},
			want: "t1204h2_cca9_1428ce7b4018",
		},
		{
			// TLS 1.2 with long ALPN: "http/1.1" -> first+last = "h1"
			// exts same as above for a known hash
			name:     "TLS 1.2 long ALPN truncated to first+last",
			protocol: JA4SProtocolTLS,
			log: &tls.ServerHandshake{
				ServerHello: &tls.ServerHello{
					Version:              0x0303,
					CipherSuite:          0xcca9,
					AlpnProtocol:         "http/1.1",
					ExtensionIdentifiers: []uint16{0x0000, 0xff01, 0x000b, 0x0010},
				},
			},
			want: "t1204h1_cca9_1428ce7b4018",
		},
		{
			// No extensions: SHA256 of empty -> "000000000000"
			name:     "TLS 1.3 no extensions",
			protocol: JA4SProtocolTLS,
			log: &tls.ServerHandshake{
				ServerHello: &tls.ServerHello{
					Version:     0x0303,
					CipherSuite: 0x1301,
					SupportedVersions: &tls.SupportedVersionsExt{
						SelectedVersion: 0x0304,
					},
				},
			},
			want: "t130000_1301_000000000000",
		},
		{
			name:     "QUIC protocol prefix",
			protocol: JA4SProtocolQUIC,
			log: &tls.ServerHandshake{
				ServerHello: &tls.ServerHello{
					Version:     0x0303,
					CipherSuite: 0x1301,
					SupportedVersions: &tls.SupportedVersionsExt{
						SelectedVersion: 0x0304,
					},
					ExtensionIdentifiers: []uint16{0x0033, 0x002b},
				},
			},
			want: "q130200_1301_234ea6891581",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := JA4S(tt.protocol, tt.log)
			if got != tt.want {
				t.Errorf("JA4S() = %q, want %q", got, tt.want)
			}
		})
	}
}

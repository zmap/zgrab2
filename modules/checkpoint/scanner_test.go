package checkpoint

import (
	"encoding/binary"
	"testing"
)

// buildCipherSuiteBytes constructs the binary cipher-suite block:
// [4-byte count] ( [4-byte len including \x00] <name>\x00 ) × count
func buildCipherSuiteBytes(names []string) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(len(names)))
	for _, n := range names {
		entry := make([]byte, 4)
		binary.BigEndian.PutUint32(entry, uint32(len(n)+1))
		entry = append(entry, []byte(n)...)
		entry = append(entry, 0x00)
		buf = append(buf, entry...)
	}
	return buf
}

var realCiphers = []string{
	"none", "sslca_clear", "sslca", "sslca_comp",
	"sslca_rc4", "sslca_rc4_comp", "asym_sslca",
	"asym_sslca_comp", "asym_sslca_rc4", "asym_sslca_rc4_comp",
}

// TestDecodeTopologyResponse exercises decodeTopologyResponse with inputs derived from real
// Checkpoint topology scan results.
func TestDecodeTopologyResponse(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		includeRaw       bool
		wantFirewall     string
		wantSmartCenter  string
		wantObjectSuffix string
		wantEncryption   []string
		wantErr          bool
	}{
		{
			// O= has exactly one dot before the SIC suffix.
			name:             "simple_hostname",
			input:            "CN=az66fwieweb-02,O=az66fwcma01.kbyi2z",
			wantFirewall:     "az66fwieweb-02",
			wantSmartCenter:  "az66fwcma01",
			wantObjectSuffix: "kbyi2z",
		},
		{
			// Double-dot: management name ends with a trailing dot (absolute FQDN),
			// producing O=hostname..sicsuffix.
			name:             "simple_hostname_double_dot",
			input:            "CN=TERAZSVCFWEXTCENTRALUS2,O=terazsvcfwmgt01..9zayrh",
			wantFirewall:     "TERAZSVCFWEXTCENTRALUS2",
			wantSmartCenter:  "terazsvcfwmgt01",
			wantObjectSuffix: "9zayrh",
		},
		{
			// Full domain in O= with a single dot before the SIC suffix.
			name:             "fqdn_single_dot_sic",
			input:            "CN=IL-CH3-FW04,O=MN-MSP-EMC.OldRepublicTitle.com.4yyzo3",
			wantFirewall:     "IL-CH3-FW04",
			wantSmartCenter:  "MN-MSP-EMC.OldRepublicTitle.com",
			wantObjectSuffix: "4yyzo3",
		},
		{
			// Full domain with double-dot before SIC suffix.
			name:             "fqdn_double_dot_sic",
			input:            "CN=USTF1FWCP2,O=stmartin.opentext.com..4ugsn6",
			wantFirewall:     "USTF1FWCP2",
			wantSmartCenter:  "stmartin.opentext.com",
			wantObjectSuffix: "4ugsn6",
		},
		{
			// The gateway CN itself contains a dot (FQDN gateway name).
			name:             "cn_with_dot_fqdn_o",
			input:            "CN=fw01-9700-cab106.ny5,O=fms01-cab107.cheetahmail.com.dmrg5n",
			wantFirewall:     "fw01-9700-cab106.ny5",
			wantSmartCenter:  "fms01-cab107.cheetahmail.com",
			wantObjectSuffix: "dmrg5n",
		},
		{
			// O= value with underscores and double-dot SIC separator.
			name:             "underscores_double_dot",
			input:            "CN=FW-PH-TIPerisur-1,O=PH_KIO-SF_SmartCenter_Prim..cp6sy3",
			wantFirewall:     "FW-PH-TIPerisur-1",
			wantSmartCenter:  "PH_KIO-SF_SmartCenter_Prim",
			wantObjectSuffix: "cp6sy3",
		},
		{
			name:             "management_service_double_dot",
			input:            "CN=smis310,O=Management_Service..rry67a",
			wantFirewall:     "smis310",
			wantSmartCenter:  "Management_Service",
			wantObjectSuffix: "rry67a",
		},
		{
			// Realistic wire format: 4-byte message-length prefix, null-terminated DN,
			// then the binary cipher-suite block.
			name: "with_binary_prefix_and_cipher_suffix",
			input: "\x00\x00\x00\x38" +
				"CN=IL-CH3-FW04,O=MN-MSP-EMC.OldRepublicTitle.com.4yyzo3" +
				"\x00" + string(buildCipherSuiteBytes(realCiphers)),
			wantFirewall:     "IL-CH3-FW04",
			wantSmartCenter:  "MN-MSP-EMC.OldRepublicTitle.com",
			wantObjectSuffix: "4yyzo3",
			wantEncryption:   realCiphers,
		},
		{
			// Simple case with cipher suite data.
			name: "cipher_suites_parsed",
			input: "CN=az66fwieweb-02,O=az66fwcma01.kbyi2z" +
				"\x00" + string(buildCipherSuiteBytes(realCiphers)),
			wantFirewall:     "az66fwieweb-02",
			wantSmartCenter:  "az66fwcma01",
			wantObjectSuffix: "kbyi2z",
			wantEncryption:   realCiphers,
		},
		{
			// Response with zero cipher suites — field should be nil/omitted.
			name: "zero_cipher_suites",
			input: "CN=fw,O=mgmt.abc123" +
				"\x00" + string(buildCipherSuiteBytes(nil)),
			wantFirewall:     "fw",
			wantSmartCenter:  "mgmt",
			wantObjectSuffix: "abc123",
			wantEncryption:   nil,
		},
		{
			// includeRaw should populate RawTopologyResponse.
			name:             "include_raw_populates_field",
			input:            "CN=smis310,O=Management_Service..rry67a",
			includeRaw:       true,
			wantFirewall:     "smis310",
			wantSmartCenter:  "Management_Service",
			wantObjectSuffix: "rry67a",
		},
		{
			name:    "empty_response",
			input:   "",
			wantErr: true,
		},
		{
			name:    "binary_only_no_dn",
			input:   "\x00\x00\x00\x04garbage",
			wantErr: true,
		},
		{
			name:    "cn_present_but_no_o_field",
			input:   "CN=somehost",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := &ScanResults{}
			err := decodeTopologyResponse(tt.input, results, tt.includeRaw)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil; FirewallHost=%q SmartCenter=%q",
						results.FirewallHost, results.SmartCenterHost)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if results.FirewallHost != tt.wantFirewall {
				t.Errorf("FirewallHost: got %q, want %q", results.FirewallHost, tt.wantFirewall)
			}
			if results.SmartCenterHost != tt.wantSmartCenter {
				t.Errorf("SmartCenterHost: got %q, want %q", results.SmartCenterHost, tt.wantSmartCenter)
			}
			if results.ObjectSuffix != tt.wantObjectSuffix {
				t.Errorf("SICSuffix: got %q, want %q", results.ObjectSuffix, tt.wantObjectSuffix)
			}
			if len(results.SupportedEncryption) != len(tt.wantEncryption) {
				t.Errorf("SupportedEncryption len: got %d (%v), want %d (%v)",
					len(results.SupportedEncryption), results.SupportedEncryption,
					len(tt.wantEncryption), tt.wantEncryption)
			} else {
				for i, c := range tt.wantEncryption {
					if results.SupportedEncryption[i] != c {
						t.Errorf("SupportedEncryption[%d]: got %q, want %q", i, results.SupportedEncryption[i], c)
					}
				}
			}
			if tt.includeRaw && results.RawTopologyResponse != tt.input {
				t.Errorf("RawTopologyResponse: got %q, want %q", results.RawTopologyResponse, tt.input)
			}
			if !tt.includeRaw && results.RawTopologyResponse != "" {
				t.Errorf("RawTopologyResponse should be empty when includeRaw=false, got %q", results.RawTopologyResponse)
			}
		})
	}
}

func TestParseCipherSuites(t *testing.T) {
	t.Run("real_cipher_list", func(t *testing.T) {
		data := buildCipherSuiteBytes(realCiphers)
		got := parseCipherSuites(data)
		if len(got) != len(realCiphers) {
			t.Fatalf("got %d ciphers, want %d: %v", len(got), len(realCiphers), got)
		}
		for i, c := range realCiphers {
			if got[i] != c {
				t.Errorf("[%d]: got %q, want %q", i, got[i], c)
			}
		}
	})

	t.Run("empty", func(t *testing.T) {
		if got := parseCipherSuites(nil); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("zero_count", func(t *testing.T) {
		if got := parseCipherSuites(buildCipherSuiteBytes(nil)); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("truncated_data", func(t *testing.T) {
		data := buildCipherSuiteBytes(realCiphers)
		// parseCipherSuites should not panic on truncated input
		_ = parseCipherSuites(data[:10])
	})
}

package zgrab2

import (
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestParseIPList(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    []string
		errExpected bool
	}{
		{
			name:     "Single IPv4 without port",
			input:    "8.8.8.8",
			expected: []string{"8.8.8.8:53"},
		},
		{
			name:     "Single IPv4 with custom port",
			input:    "8.8.8.8:5353",
			expected: []string{"8.8.8.8:5353"},
		},
		{
			name:     "Single IPv6 without port",
			input:    "2001:4860:4860::8888",
			expected: []string{"[2001:4860:4860::8888]:53"},
		},
		{
			name:     "Single IPv6 with custom port",
			input:    "[2001:4860:4860::8888]:5353",
			expected: []string{"[2001:4860:4860::8888]:5353"},
		},
		{
			name:     "Multiple IPv4s mixed ports",
			input:    "1.1.1.1:5300,8.8.8.8",
			expected: []string{"1.1.1.1:5300", "8.8.8.8:53"},
		},
		{
			name:  "Mixed IPv4 and IPv6, some with ports",
			input: "1.1.1.1:5300,[2001:4860:4860::8888]:5353,8.8.8.8,2001:4860:4860::8844",
			expected: []string{
				"1.1.1.1:5300",
				"[2001:4860:4860::8888]:5353",
				"8.8.8.8:53",
				"[2001:4860:4860::8844]:53",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseCustomDNSString(tt.input)
			if (err != nil) != tt.errExpected {
				t.Errorf("parseCustomDNSString() error = %v, expected %v", err, tt.errExpected)
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParseIPList(%q) = %v; want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractIPAddresses(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []net.IP
		wantErr  bool
	}{
		// Basic single IP
		{"Single IP", "1.2.3.4", []net.IP{net.ParseIP("1.2.3.4")}, false},

		// Basic 3x IP
		{"3x IPs", "1.2.3.4,128.1.1.1,244.1.3.5", []net.IP{
			net.ParseIP("1.2.3.4"),
			net.ParseIP("128.1.1.1"),
			net.ParseIP("244.1.3.5")}, false},

		// Basic 3x IP w/ spaces
		{"Single IP with spaces", "1.2.3.4, 1.2.3.7, 1.2.3.9", []net.IP{
			net.ParseIP("1.2.3.4"),
			net.ParseIP("1.2.3.7"),
			net.ParseIP("1.2.3.9")}, false},

		// Duplicate single IPs
		{"Duplicate IPs", "1.2.3.4,1.2.3.4", []net.IP{net.ParseIP("1.2.3.4")}, false},

		// IP range
		{"IP Range", "1.2.3.4-1.2.3.6", []net.IP{
			net.ParseIP("1.2.3.4"), net.ParseIP("1.2.3.5"), net.ParseIP("1.2.3.6"),
		}, false},

		// IP range with spaces
		{"IP Range with spaces", "1.2.3.4 - 1.2.3.6", []net.IP{
			net.ParseIP("1.2.3.4"), net.ParseIP("1.2.3.5"), net.ParseIP("1.2.3.6"),
		}, false},

		// Overlapping IP range
		{"Overlapping Range", "1.2.3.4-1.2.3.6,1.2.3.5-1.2.3.7", []net.IP{
			net.ParseIP("1.2.3.4"), net.ParseIP("1.2.3.5"), net.ParseIP("1.2.3.6"), net.ParseIP("1.2.3.7"),
		}, false},

		// CIDR block
		{"CIDR Block /30", "192.168.1.0/30", []net.IP{
			net.ParseIP("192.168.1.0"),
			net.ParseIP("192.168.1.1"),
			net.ParseIP("192.168.1.2"),
			net.ParseIP("192.168.1.3"),
		}, false},

		// CIDR block with a single IP
		{"CIDR and single IP", "192.168.1.0/30,192.168.1.128", []net.IP{
			net.ParseIP("192.168.1.0"),
			net.ParseIP("192.168.1.1"),
			net.ParseIP("192.168.1.2"),
			net.ParseIP("192.168.1.3"),
			net.ParseIP("192.168.1.128"),
		}, false},

		// CIDR block overlapping with a single IP
		{"CIDR and single IP", "192.168.1.0/30,192.168.1.2", []net.IP{
			net.ParseIP("192.168.1.0"),
			net.ParseIP("192.168.1.1"),
			net.ParseIP("192.168.1.2"),
			net.ParseIP("192.168.1.3"),
		}, false},

		{"Max IPv4 CIDR", "255.255.255.255/32", []net.IP{
			net.ParseIP("255.255.255.255"),
		}, false},

		{"Max IPv6 CIDR", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", []net.IP{
			net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		}, false},

		{"Max IPv4 Range", "255.255.255.254-255.255.255.255", []net.IP{
			net.ParseIP("255.255.255.254"),
			net.ParseIP("255.255.255.255"),
		}, false},

		{"Max IPv6 Range", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe - ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", []net.IP{
			net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"),
			net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		}, false},

		// Combination of all formats
		{"Mixed formats", "10.0.0.1,10.0.0.2-10.0.0.3,10.0.0.0/30", []net.IP{
			net.ParseIP("10.0.0.0"),
			net.ParseIP("10.0.0.1"),
			net.ParseIP("10.0.0.2"),
			net.ParseIP("10.0.0.3"),
		}, false},

		// Combination of all formats, with spaces
		{"Mixed formats with spaces", "10.0.0.1, 10.0.0.2 -10.0.0.3 , 10.0.0.0/30", []net.IP{
			net.ParseIP("10.0.0.0"),
			net.ParseIP("10.0.0.1"),
			net.ParseIP("10.0.0.2"),
			net.ParseIP("10.0.0.3"),
		}, false},

		// Invalid formats
		{"Invalid IP", "999.999.999.999", nil, true},
		{"Invalid IP in range", "1.2.3.4-258.1.2.3", nil, true},
		{"Invalid CIDR - non-numeric", "10.0.0.a/24", nil, true},
		{"Invalid CIDR - invalid IP", "10.0.0.256/24", nil, true},
		{"Invalid CIDR - invalid mask", "10.1.2.3/33", nil, true},
		{"Invalid range, starting IP is greater than ending IP", "1.2.3.4-1.2.3", nil, true},
		{"Invalid CIDR", "10.0.0.256/24", nil, true},
		{"Random string", "hello world", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractIPAddresses(strings.Split(tt.input, ","))
			if (err != nil) != tt.wantErr {
				t.Errorf("extractIPAddresses() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			sortedGot := make([]string, len(got))
			for i, ip := range got {
				sortedGot[i] = ip.String()
			}
			slices.Sort(sortedGot)
			sortedExpected := make([]string, len(tt.expected))
			for i, ip := range tt.expected {
				sortedExpected[i] = ip.String()
			}
			slices.Sort(sortedExpected)

			// Ensure deduplication and correct ordering
			if !slices.Equal(sortedGot, sortedExpected) {
				t.Errorf("extractIPAddresses() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestExtractCIDR(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []net.IPNet
		wantErr  bool
	}{
		// Basic single IP
		{"Single IP", "1.2.3.4", []net.IPNet{
			{
				IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(32, 32),
			},
		}, false},

		// Basic 3x IPs (converted to CIDR blocks)
		{"3x IPs", "1.2.3.4,128.1.1.1,244.1.3.5", []net.IPNet{
			{
				IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(32, 32),
			}, {
				IP: net.ParseIP("128.1.1.1"), Mask: net.CIDRMask(32, 32),
			}, {
				IP: net.ParseIP("244.1.3.5"), Mask: net.CIDRMask(32, 32),
			},
		}, false},

		// Single IP with spaces (converted to CIDR blocks)
		{"Single IP with spaces", "1.2.3.4, 1.2.3.7, 1.2.3.9", []net.IPNet{
			{
				IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(32, 32),
			}, {
				IP: net.ParseIP("1.2.3.7"), Mask: net.CIDRMask(32, 32),
			}, {
				IP: net.ParseIP("1.2.3.9"), Mask: net.CIDRMask(32, 32),
			},
		}, false},

		// Duplicate single IPs (converted to CIDR block)
		{"Duplicate IPs", "1.2.3.4,1.2.3.4", []net.IPNet{
			{
				IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(32, 32),
			},
		}, false},

		// IP range (converted to CIDR blocks)
		{"IP Range", "1.2.3.4-1.2.3.6", []net.IPNet{
			{
				IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(32, 32),
			}, {
				IP: net.ParseIP("1.2.3.5"), Mask: net.CIDRMask(32, 32),
			}, {
				IP: net.ParseIP("1.2.3.6"), Mask: net.CIDRMask(32, 32),
			}}, false},

		// IP range with spaces (converted to CIDR blocks)
		{"IP Range with spaces", "1.2.3.4 - 1.2.3.6", []net.IPNet{
			{
				IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(32, 32),
			}, {
				IP: net.ParseIP("1.2.3.5"), Mask: net.CIDRMask(32, 32),
			}, {
				IP: net.ParseIP("1.2.3.6"), Mask: net.CIDRMask(32, 32),
			},
		}, false},

		// Overlapping IP range (converted to CIDR blocks)
		{"Overlapping Range", "1.2.3.4-1.2.3.6,1.2.3.5-1.2.3.7", []net.IPNet{
			{
				IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(32, 32),
			}, {
				IP: net.ParseIP("1.2.3.5"), Mask: net.CIDRMask(32, 32),
			}, {
				IP: net.ParseIP("1.2.3.6"), Mask: net.CIDRMask(32, 32),
			}, {
				IP: net.ParseIP("1.2.3.7"), Mask: net.CIDRMask(32, 32),
			},
		}, false},

		// CIDR block (/30)
		{"CIDR Block /30", "192.168.1.0/30", []net.IPNet{
			{
				IP: net.ParseIP("192.168.1.0"), Mask: net.CIDRMask(30, 32),
			},
		}, false},

		// CIDR block with a single IP (converted to CIDR block)
		{"CIDR and single IP", "192.168.1.0/30,192.168.1.128", []net.IPNet{
			{
				IP: net.ParseIP("192.168.1.0"), Mask: net.CIDRMask(30, 32),
			}, {
				IP: net.ParseIP("192.168.1.128"), Mask: net.CIDRMask(32, 32),
			},
		}, false},

		// Max IPv4 CIDR (/32)
		{"Max IPv4 CIDR", "255.255.255.255/32", []net.IPNet{
			{
				IP: net.ParseIP("255.255.255.255"), Mask: net.CIDRMask(32, 32),
			},
		}, false},

		// Max IPv6 CIDR (/128)
		{"Max IPv6 CIDR", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", []net.IPNet{
			{
				IP: net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), Mask: net.CIDRMask(128, 128),
			},
		}, false},

		// Max IPv4 Range (converted to CIDR blocks)
		{"Max IPv4 Range", "255.255.255.254-255.255.255.255", []net.IPNet{
			{
				IP: net.ParseIP("255.255.255.254"), Mask: net.CIDRMask(32, 32),
			}, {
				IP: net.ParseIP("255.255.255.255"), Mask: net.CIDRMask(32, 32),
			},
		}, false},

		// Combination of all formats
		{"Mixed formats", "10.0.0.1,10.0.0.2-10.0.0.3,10.0.0.0/30", []net.IPNet{
			{
				IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(30, 32),
			}, {
				IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(32, 32),
			}, {
				IP: net.ParseIP("10.0.0.2"), Mask: net.CIDRMask(32, 32),
			}, {
				IP: net.ParseIP("10.0.0.3"), Mask: net.CIDRMask(32, 32),
			},
		}, false},

		// Invalid formats
		{"Invalid IP", "999.999.999.999", nil, true},
		{"Invalid IP in range", "1.2.3.4-258.1.2.3", nil, true},
		{"Invalid CIDR - non-numeric", "10.0.0.a/24", nil, true},
		{"Invalid CIDR - invalid IP", "10.0.0.256/24", nil, true},
		{"Invalid CIDR - invalid mask", "10.1.2.3/33", nil, true},
		{"Invalid range, starting IP is greater than ending IP", "1.2.3.4-1.2.3", nil, true},
		{"Invalid CIDR", "10.0.0.256/24", nil, true},
		{"Random string", "hello world", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractCIDRRanges(strings.Split(tt.input, ","))
			if (err != nil) != tt.wantErr {
				t.Errorf("extractCIDRRanges() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			sortedGot := make([]string, len(got))
			for i, ipNet := range got {
				sortedGot[i] = ipNet.String()
			}
			slices.Sort(sortedGot)
			sortedExpected := make([]string, len(tt.expected))
			for i, ipNet := range tt.expected {
				sortedExpected[i] = ipNet.String()
			}
			slices.Sort(sortedExpected)

			// Ensure deduplication and correct ordering
			if !slices.Equal(sortedGot, sortedExpected) {
				t.Errorf("extractIPAddresses() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestExtractPorts(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []uint16
		wantErr  bool
	}{
		// Positive Test Cases
		{"Single Port", "80", []uint16{80}, false},
		{"Single Port with whitespace", "	80 ", []uint16{80}, false},
		{"Multiple ports", "80,443,8080", []uint16{80, 443, 8080}, false},
		{"Multiple ports with whitespace", "	80,    	443,  8080 ", []uint16{80, 443, 8080}, false},
		{"Port range", "80-85", []uint16{80, 81, 82, 83, 84, 85}, false},
		{"Port range with whitespace", "80 - 85", []uint16{80, 81, 82, 83, 84, 85}, false},
		{"Single port with range", "80, 83-89", []uint16{80, 83, 84, 85, 86, 87, 88, 89}, false},
		{"Duplicate port", "80, 80", []uint16{80}, false},
		{"Duplicate port with port range", "80, 80-82", []uint16{80, 81, 82}, false},
		// Negative Test Cases
		{"Invalid port - too large", "65536", nil, true},
		{"Invalid port - can't be negative", "-5", nil, true},
		{"Invalid port - can't be zero", "0", nil, true},
		{"Invalid port - can't be string", "port 80", nil, true},
		{"Invalid range - start greater than end", "80-70", nil, true},
		{"Invalid range - start can't be zero", "0-70", nil, true},
		{"Invalid range - end can't be greater than a valid port", "1-65536", nil, true},
		{"Invalid range - end must be integer", "1-port", nil, true},
		{"Invalid range - start must be integer", "port-8080", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractPorts(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractPorts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			slices.Sort(got)
			slices.Sort(tt.expected)
			if !slices.Equal(got, tt.expected) {
				t.Errorf("extractPorts() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

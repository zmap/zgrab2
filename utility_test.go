package zgrab2

import (
	"reflect"
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

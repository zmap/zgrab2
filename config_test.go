package zgrab2

import (
	"net"
	"slices"
	"testing"
)

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

		// CIDR block overlapping with a single IP
		{"CIDR and single IP", "192.168.1.0/30,192.168.1.2", []net.IP{
			net.ParseIP("192.168.1.0"),
			net.ParseIP("192.168.1.1"),
			net.ParseIP("192.168.1.2"),
			net.ParseIP("192.168.1.3"),
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
			got, err := extractIPAddresses(tt.input)
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

func TestExtractPorts(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []uint16
		wantErr  bool
	}{
		{"Single Port", "80", []uint16{80}, false},
		{"Single Port with whitespace", "	80 ", []uint16{80}, false},
		{"Multiple ports", "80,443,8080", []uint16{80, 443, 8080}, false},
		{"Multiple ports with whitespace", "	80,    	443,  8080 ", []uint16{80, 443, 8080}, false},
		{"Port range", "80-85", []uint16{80, 81, 82, 83, 84, 85}, false},
		{"Port range with whitespace", "80 - 85", []uint16{80, 81, 82, 83, 84, 85}, false},
		{"Single port with range", "80, 83-89", []uint16{80, 83, 84, 85, 86, 87, 88, 89}, false},
		{"Duplicate port", "80, 80", []uint16{80}, false},
		{"Duplicate port with port range", "80, 80-82", []uint16{80, 81, 82}, false},
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

package zgrab2

import (
	"net"
	"strings"
	"testing"
)

type ipRangeTest struct {
	input             string
	output            []net.IP
	outputErrorString string
}

func TestParseSourceIPRange(t *testing.T) {
	tests := []ipRangeTest{
		ipRangeTest{
			input:  "192.168.1.10",
			output: []net.IP{net.ParseIP("192.168.1.10")},
		},
		ipRangeTest{
			input:             "blah192.168.1.10",
			outputErrorString: "invalid starting source",
		},
		ipRangeTest{
			input:             "192.168.1.10blah   ",
			outputErrorString: "invalid starting source",
		},
		ipRangeTest{
			input:             "192.168.1.10 -   ",
			outputErrorString: "invalid ending source",
		},
		ipRangeTest{
			input:             "192.168.1.10 - blah   ",
			outputErrorString: "invalid ending source",
		},
		ipRangeTest{
			input:  "     192.168.1.10   ",
			output: []net.IP{net.ParseIP("192.168.1.10")},
		},
		ipRangeTest{
			input:  "     192.168.1.10",
			output: []net.IP{net.ParseIP("192.168.1.10")},
		},
		ipRangeTest{
			input:  "192.168.1.10-192.168.1.12",
			output: []net.IP{net.ParseIP("192.168.1.10"), net.ParseIP("192.168.1.11"), net.ParseIP("192.168.1.12")},
		},
		ipRangeTest{
			input:  "    192.168.1.10-     192.168.1.12   ",
			output: []net.IP{net.ParseIP("192.168.1.10"), net.ParseIP("192.168.1.11"), net.ParseIP("192.168.1.12")},
		},
		ipRangeTest{
			input:  "    192.168.1.10   -192.168.1.12   ",
			output: []net.IP{net.ParseIP("192.168.1.10"), net.ParseIP("192.168.1.11"), net.ParseIP("192.168.1.12")},
		},
		ipRangeTest{
			input:  "    192.168.1.10   -    192.168.1.12   ",
			output: []net.IP{net.ParseIP("192.168.1.10"), net.ParseIP("192.168.1.11"), net.ParseIP("192.168.1.12")},
		},
		ipRangeTest{
			input:             "2607:f8b0:4009:80c::200e",
			outputErrorString: "got a v6 address",
		},
		ipRangeTest{
			input:             "2607:f8b0:4009:80c::200e - ",
			outputErrorString: "got a v6 address",
		},
		ipRangeTest{
			input:             "2607:f8b0:4009:80c::200e - 2607:f8b0:4009:80c::200f",
			outputErrorString: "got a v6 address",
		},
		ipRangeTest{
			input:             "   2607:f8b0:4009:80c::200e    ",
			outputErrorString: "got a v6 address",
		},
	}
	for idx, test := range tests {
		ips, err := ParseIPv4RangeString(test.input)
		if err != nil && test.outputErrorString == "" {
			t.Logf("test input: %v", test)
			t.Errorf("got unexpected error on test at index %d: %s", idx, err.Error())
			continue
		}
		if err != nil && test.outputErrorString != "" {
			if !strings.Contains(err.Error(), test.outputErrorString) {
				t.Logf("test input: %v", test)
				t.Errorf("got unexpected error on test at index %d: got %s, wanted %s", idx, err.Error(), test.outputErrorString)
			}
			continue
		}
		t.Logf("test %d input: %v", idx, test)
		t.Logf("test %d output: %v", idx, ips)
		if len(ips) != len(test.output) {
			t.Errorf("mismatched output lengths: got %d, wanted %d", len(ips), len(test.output))
			continue
		}
		for idx := range test.output {
			if test.output[idx] == nil {
				t.Fatalf("invalid test")
			}
			if ips[idx].String() != test.output[idx].String() {
				t.Errorf("output index %d: got %s, expected %s", idx, ips[idx], test.output[idx])
			}
		}
	}
}

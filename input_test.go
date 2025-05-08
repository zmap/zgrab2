package zgrab2

import (
	"net"
	"strings"
	"testing"
)

func TestParseCSVTarget(t *testing.T) {
	parseCIDR := func(s string) *net.IPNet {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			panic(err)
		}
		return ipnet
	}

	parseIP := func(s string) *net.IPNet {
		ip := net.ParseIP(s)
		if ip == nil {
			panic("can't parse IP")
		}
		return &net.IPNet{IP: ip}
	}

	ipnetString := func(ipnet *net.IPNet) string {
		if ipnet == nil {
			return "<nil>"
		} else if ipnet.IP != nil && ipnet.Mask != nil {
			return ipnet.String()
		} else if ipnet.IP != nil {
			return ipnet.IP.String()
		}
		panic("malformed ipnet")
	}

	tests := []struct {
		fields  []string
		ipnet   *net.IPNet
		domain  string
		tag     string
		port    string
		success bool
	}{
		// IP DOMAIN TAG PORT
		{
			fields:  []string{"10.0.0.1", "example.com", "tag", "443"},
			ipnet:   parseIP("10.0.0.1"),
			domain:  "example.com",
			tag:     "tag",
			port:    "443",
			success: true,
		},
		// IP DOMAIN TAG PORT
		{
			fields:  []string{"10.0.0.1", "example.com", "tag"},
			ipnet:   parseIP("10.0.0.1"),
			domain:  "example.com",
			tag:     "tag",
			port:    "",
			success: true,
		},
		// IP DOMAIN TAG
		{
			fields:  []string{"10.0.0.1", "example.com", "tag"},
			ipnet:   parseIP("10.0.0.1"),
			domain:  "example.com",
			tag:     "tag",
			success: true,
		},
		// IP DOMAIN (3 fields)
		{
			fields:  []string{"10.0.0.1", "example.com", ""},
			ipnet:   parseIP("10.0.0.1"),
			domain:  "example.com",
			success: true,
		},
		// IP DOMAIN (2 fields)
		{
			fields:  []string{"10.0.0.1", "example.com"},
			ipnet:   parseIP("10.0.0.1"),
			domain:  "example.com",
			success: true,
		},
		// IP (3 fields)
		{
			fields:  []string{"10.0.0.1", "", ""},
			ipnet:   parseIP("10.0.0.1"),
			success: true,
		},
		// IP (2 fields)
		{
			fields:  []string{"10.0.0.1", ""},
			ipnet:   parseIP("10.0.0.1"),
			success: true,
		},
		// IP (1 fields)
		{
			fields:  []string{"10.0.0.1", ""},
			ipnet:   parseIP("10.0.0.1"),
			success: true,
		},
		// CIDR
		{
			fields:  []string{"10.0.0.1/8", ""},
			ipnet:   parseCIDR("10.0.0.1/8"),
			success: true,
		},

		// DOMAIN (2 fields)
		{
			fields:  []string{"", "example.com"},
			domain:  "example.com",
			success: true,
		},

		// Bare domain
		{
			fields:  []string{"example.com"},
			domain:  "example.com",
			success: true,
		},
		// Error: Empty record (1 field)
		{
			fields:  []string{""},
			success: false,
		},
		// Error: Empty record (no fields)
		{
			fields:  []string{},
			success: false,
		},
		// Error: No address or domain
		{
			fields:  []string{"", "", "tag"},
			success: false,
		},
		// Error: Too many fields
		{
			fields:  []string{"", "", "", ""},
			success: false,
		},
		// Error: IP and domain reversed
		{
			fields:  []string{"example.com", "10.0.0.1"},
			success: false,
		},
	}

	for _, test := range tests {
		ipnet, domain, tag, port, err := ParseCSVTarget(test.fields)
		if (err == nil) != test.success {
			t.Errorf("wrong error status (got err=%v, success should be %v): %q", err, test.success, test.fields)
			return
		}
		if err == nil {
			if ipnetString(ipnet) != ipnetString(test.ipnet) || domain != test.domain || tag != test.tag || port != test.port {
				t.Errorf("wrong result (got %v,%v,%v,%v ; expected %v,%v,%v,%v): %q", ipnetString(ipnet), domain, tag, port, ipnetString(test.ipnet), test.domain, test.tag, test.port, test.fields)
				return
			}
		}
	}
}

func TestGetTargetsCSV(t *testing.T) {
	input := `# Comment
10.0.0.1,example.com,tag
 10.0.0.1 ,"example.com"
10.0.0.1
,example.com
example.com
2.2.2.2/30,, tag
10.0.0.1,example.com,tag,443
10.0.0.1,,,443
`
	port := uint(443)
	expected := []ScanTarget{
		{IP: net.ParseIP("10.0.0.1"), Domain: "example.com", Tag: "tag"},
		{IP: net.ParseIP("10.0.0.1"), Domain: "example.com"},
		{IP: net.ParseIP("10.0.0.1")},
		{Domain: "example.com"},
		{Domain: "example.com"},
		{IP: net.ParseIP("2.2.2.0"), Tag: "tag"},
		{IP: net.ParseIP("2.2.2.1"), Tag: "tag"},
		{IP: net.ParseIP("2.2.2.2"), Tag: "tag"},
		{IP: net.ParseIP("2.2.2.3"), Tag: "tag"},
		{IP: net.ParseIP("10.0.0.1"), Domain: "example.com", Tag: "tag", Port: port},
		{IP: net.ParseIP("10.0.0.1"), Port: port},
	}

	ch := make(chan ScanTarget)
	go func() {
		err := GetTargetsCSV(strings.NewReader(input), ch)
		if err != nil {
			t.Errorf("GetTargets error: %v", err)
		}
		close(ch)
	}()
	res := make([]ScanTarget, 0, len(ch))
	for r := range ch {
		res = append(res, r)
	}

	if len(res) != len(expected) {
		t.Errorf("wrong number of results (got %d; expected %d)", len(res), len(expected))
		return
	}
	for i := range expected {
		if res[i].IP.String() != expected[i].IP.String() ||
			res[i].Domain != expected[i].Domain ||
			res[i].Tag != expected[i].Tag {
			t.Errorf("wrong data in ScanTarget %d (got %v; expected %v)", i, res[i], expected[i])
		}
	}
}

func TestIncrementIP(t *testing.T) {
	tests := []struct {
		input    net.IP
		expected net.IP
	}{
		{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2")},
		{net.ParseIP("192.168.1.255"), net.ParseIP("192.168.2.0")},
		{net.ParseIP("255.255.255.255"), net.ParseIP("255.255.255.255")}, // Test saturate
		{net.ParseIP("1:1:1:1:1:1:1:1"), net.ParseIP("1:1:1:1:1:1:1:2")},
		{net.ParseIP("1:1:1:1:1:1:1:ffff"), net.ParseIP("1:1:1:1:1:1:2:0")},
		{net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")}, // saturate IPv6
	}

	for _, test := range tests {
		ipCopy := duplicateIP(test.input) // Avoid modifying original input
		incrementIP(ipCopy)
		if !ipCopy.Equal(test.expected) {
			t.Errorf("incrementIP(%s) = %s; want %s", test.input, ipCopy, test.expected)
		}
	}
}

func TestDuplicateIP(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	dup := duplicateIP(ip)

	if &dup[0] == &ip[0] { // Check if they point to the same memory
		t.Errorf("duplicateIP() did not create a new copy")
	}

	if !dup.Equal(ip) {
		t.Errorf("duplicateIP() modified the original IP")
	}

	// Modify original IP to ensure it doesn't affect the duplicate
	ip[0] = 1
	if ip.Equal(dup) {
		t.Errorf("duplicateIP() did not create a true copy")
	}
}

func TestCompareIPs(t *testing.T) {
	tests := []struct {
		ip1      net.IP
		ip2      net.IP
		expected int
	}{
		{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.1"), 0},
		{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2"), -1},
		{net.ParseIP("192.168.1.2"), net.ParseIP("192.168.1.1"), 1},
		{net.ParseIP("::1"), net.ParseIP("::1"), 0},
		{net.ParseIP("::1"), net.ParseIP("::2"), -1},
		{net.ParseIP("::2"), net.ParseIP("::1"), 1},
	}

	for _, test := range tests {
		result := compareIPs(test.ip1, test.ip2)
		if result != test.expected {
			t.Errorf("compareIPs(%s, %s) = %d; want %d", test.ip1, test.ip2, result, test.expected)
		}
	}
}

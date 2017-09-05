package zgrab2

import (
	"errors"
	"net"
	"strings"

	"github.com/ajholland/zflags"
)

var parser *flags.Parser

func init() {
	parser = flags.NewParser(&config, flags.Default)
}

// AddCommand adds a module to the parser and returns a pointer to a flags.command object or an error
func AddCommand(command string, shortDescription string, longDescription string, m ScanModule) (*flags.Command, error) {
	return parser.AddCommand(command, shortDescription, longDescription, m)
}

// ParseFlags abstracts away the parser and validates the framework configuration (global options) immediately after parsing
func ParseFlags() ([]string, error) {
	r, err := parser.Parse()
	if err == nil {
		validateFrameworkConfiguration()
	}
	return r, err
}

// ParseInput takes a string representation of either an IP, domain name, or cidr block and parses it into a corresponding IPNet, domain name, or error.
// IPNet may be partial and only contain an IP.
func ParseInput(s string) (*net.IPNet, string, error) {
	i := strings.IndexByte(s, ',')
	j := strings.IndexByte(s, '/')

	switch {
	case i == -1 && j == -1:
		//just ip or domain
		if ip := net.ParseIP(s); ip != nil {
			return &net.IPNet{IP: ip}, "", nil
		} else {
			ips, err := net.LookupIP(s)
			if err != nil {
				return nil, "", err
			}
			return &net.IPNet{IP: ips[0]}, s, nil //only return first IP after a lookup
		}
	case i == -1:
		//cidr block
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, "", err
		}
		return ipnet, "", nil
	case j == -1:
		//ip,domain
		str := strings.Split(s, ",")
		if len(str) != 2 {
			return nil, "", errors.New("malformed input")
		}
		if ip := net.ParseIP(str[0]); ip != nil {
			return &net.IPNet{IP: ip}, str[1], nil
		}
		return nil, str[1], nil
	}
	return nil, "", nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func duplicateIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

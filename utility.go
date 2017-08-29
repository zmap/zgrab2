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

func AddCommand(command string, shortDescription string, longDescription string, m Module) (*flags.Command, error) {
	return parser.AddCommand(command, shortDescription, longDescription, m)
}

func ParseFlags() ([]string, error) {
	r, err := parser.Parse()
	if err == nil {
		validateFrameworkConfiguration()
	}
	return r, err
}

// ParseInput takes input and parses it into either a list of IP addresses, domain name, or errors
func ParseInput(s string) ([]net.IP, string, error) {
	i := strings.IndexByte(s, ',')
	j := strings.IndexByte(s, '/')

	switch {
	case i == -1 && j == -1:
		//just ip or domain
		if ip := net.ParseIP(s); ip != nil {
			return []net.IP{ip}, "", nil
		} else {
			ips, err := net.LookupIP(s)
			if err != nil {
				return nil, "", err
			}
			return ips, s, nil
		}
	case i == -1:
		//cidr block
		ip, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, "", err
		}
		var ips []net.IP
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
			ips = append(ips, duplicateIP(ip))
		}

		return ips, "", nil

	case j == -1:
		//ip,domain
		str := strings.Split(s, ",")
		if len(str) != 2 {
			return nil, "", errors.New("malformed input")
		}
		if ip := net.ParseIP(str[0]); ip != nil {
			return []net.IP{ip}, str[1], nil
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

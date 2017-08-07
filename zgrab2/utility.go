package zgrab2

import (
	"net"
	"strings"

	"github.com/ajholland/zflags"
)

var parser *flags.Parser

func init() {
	parser = flags.NewParser(&config, flags.Default)
}

func AddCommand(command string, shortDescription string, longDescription string, data interface{}) (*flags.Command, error) {
	return parser.AddCommand(command, shortDescription, longDescription, data)
}

func ParseFlags() ([]string, error) {
	return parser.Parse()
}

// ParseInput takes input and parses it into either a list of IP addresses, domain name, or errors
func ParseInput(s string) ([]net.IP, string, error) {
	i := strings.IndexByte(s, '/')
	if i < 0 {
		//not cidr
		if ip := net.ParseIP(s); ip != nil {
			return []net.IP{ip}, "", nil //single ip
		} else {
			return nil, s, nil //domain address
		}
	} else {
		//is cidr
		ip, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, "", err
		}

		var ips []net.IP
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			ips = append(ips, dupIP(ip))
		}

		return ips, "", nil
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func dupIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

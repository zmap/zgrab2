package zgrab2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"time"

	"runtime/debug"

	"github.com/sirupsen/logrus"
)

// ReadAvaiable reads what it can without blocking for more than
// defaultReadTimeout per read, or defaultTotalTimeout for the whole session.
// Reads at most defaultMaxReadSize bytes.
func ReadAvailable(conn net.Conn) ([]byte, error) {
	const defaultReadTimeout = 10 * time.Millisecond
	const defaultMaxReadSize = 1024 * 512
	// if the buffer size exactly matches the number of bytes returned, we hit
	// a corner case where we attempt to read even though there is nothing
	// available. Otherwise we should be able to return without blocking at all.
	// So -- it's better to be large than small, but the worst case is getting
	// the exact right number of bytes.
	const defaultBufferSize = 8209

	return ReadAvailableWithOptions(conn, defaultBufferSize, defaultReadTimeout, 0, defaultMaxReadSize)
}

// Make this implement the net.Error interface so that err.(net.Error).SessionTimeout() works.
type errTotalTimeout string

const (
	ErrTotalTimeout = errTotalTimeout("timeout")
)

func (err errTotalTimeout) Error() string {
	return string(err)
}

func (err errTotalTimeout) Timeout() bool {
	return true
}

func (err errTotalTimeout) Temporary() bool {
	return false
}

// ReadAvailableWithOptions reads whatever can be read (up to maxReadSize) from
// conn without blocking for longer than readTimeout per read, or totalTimeout
// for the entire session. A totalTimeout of 0 means attempt to use the
// connection's timeout (or, failing that, 1 second).
// On failure, returns anything it was able to read along with the error.
func ReadAvailableWithOptions(conn net.Conn, bufferSize int, readTimeout time.Duration, totalTimeout time.Duration, maxReadSize int) ([]byte, error) {
	var totalDeadline time.Time
	if totalTimeout == 0 {
		// Would be nice if this could be taken from the SetReadDeadline(), but that's not possible in general
		const defaultTotalTimeout = 1 * time.Second
		totalTimeout = defaultTotalTimeout
		timeoutConn, isTimeoutConn := conn.(*TimeoutConnection)
		if isTimeoutConn {
			totalTimeout = timeoutConn.SessionTimeout
		}
	}
	if totalTimeout > 0 {
		totalDeadline = time.Now().Add(totalTimeout)
	}

	buf := make([]byte, bufferSize)
	ret := make([]byte, 0)

	// The first read will use any pre-assigned deadlines.
	n, err := conn.Read(buf[0:min(bufferSize, maxReadSize)])
	ret = append(ret, buf[0:n]...)
	if err != nil || n >= maxReadSize {
		return ret, err
	}
	maxReadSize -= n

	// If there were more than bufSize -1 bytes available, read whatever is
	// available without blocking longer than timeout, and do not treat timeouts
	// as an error.
	// Keep reading until we time out or get an error.
	for totalDeadline.IsZero() || totalDeadline.After(time.Now()) {
		deadline := time.Now().Add(readTimeout)
		err = conn.SetReadDeadline(deadline)
		if err != nil {
			return ret, fmt.Errorf("could not set read deadline on conn: %w", err)
		}
		n, err := conn.Read(buf[0:min(maxReadSize, bufferSize)])
		maxReadSize -= n
		ret = append(ret, buf[0:n]...)
		if err != nil {
			if IsTimeoutError(err) {
				err = nil
			}
			return ret, err
		}

		if n >= maxReadSize {
			return ret, err
		}
	}
	return ret, ErrTotalTimeout
}

var ErrInsufficientBuffer = errors.New("not enough buffer space")

// ReadUntilRegex calls connection.Read() until it returns an error, or the cumulatively-read data matches the given regexp
func ReadUntilRegex(connection net.Conn, res []byte, expr *regexp.Regexp) (int, error) {
	buf := res[0:]
	length := 0
	for finished := false; !finished; {
		n, err := connection.Read(buf)
		length += n
		if err != nil {
			return length, err
		}
		if expr.Match(res[0:length]) {
			finished = true
		}
		if length == len(res) {
			return length, ErrInsufficientBuffer
		}
		buf = res[length:]
	}
	return length, nil
}

// TLDMatches checks for a strict TLD match
func TLDMatches(host1 string, host2 string) bool {
	splitStr1 := strings.Split(stripPortNumber(host1), ".")
	splitStr2 := strings.Split(stripPortNumber(host2), ".")

	tld1 := splitStr1[len(splitStr1)-1]
	tld2 := splitStr2[len(splitStr2)-1]

	return tld1 == tld2
}

func stripPortNumber(host string) string {
	return strings.Split(host, ":")[0]
}

type timeoutError interface {
	Timeout() bool
}

// IsTimeoutError checks if the given error corresponds to a timeout (of any type).
func IsTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if cast, ok := err.(timeoutError); ok {
		return cast.Timeout()
	}
	if cast, ok := err.(*ScanError); ok {
		return cast.Status == SCAN_IO_TIMEOUT || cast.Status == SCAN_CONNECTION_TIMEOUT
	}

	return false
}

// LogPanic is intended to be called from within defer -- if there was no panic, it returns without
// doing anything. Otherwise, it logs the stacktrace, the panic error, and the provided message
// before re-raising the original panic.
// Example:
//
//	defer zgrab2.LogPanic("Error decoding body '%x'", body)
func LogPanic(format string, args ...any) {
	err := recover()
	if err == nil {
		return
	}
	logrus.Errorf("Uncaught panic at %s: %v", string(debug.Stack()), err)
	logrus.Errorf(format, args...)
	panic(err)
}

// addDefaultPortToDNSServerName validates that the input DNS server address is correct and appends the default DNS port 53 if no port is specified
func addDefaultPortToDNSServerName(inAddr string) (string, error) {
	// Try to split host and port to see if the port is already specified.
	host, port, err := net.SplitHostPort(inAddr)
	if err != nil {
		// might mean there's no port specified
		host = inAddr
	}

	// Validate the host part as an IP address.
	ip := net.ParseIP(host)
	if ip == nil {
		return "", errors.New("invalid IP address")
	}

	// If the original input does not have a port, specify port 53 as the default
	if port == "" {
		port = defaultDNSPort
	}

	return net.JoinHostPort(ip.String(), port), nil
}

func parseCustomDNSString(customDNS string) ([]string, error) {
	nameservers := make([]string, 0)
	customDNS = strings.TrimSpace(customDNS)
	if customDNS == "" {
		return nil, nil
	}
	for _, ns := range strings.Split(customDNS, ",") {
		ns = strings.TrimSpace(ns)
		if ns == "" {
			continue
		}
		nsWithPort, err := addDefaultPortToDNSServerName(ns)
		if err != nil {
			return nil, fmt.Errorf("invalid DNS server address: %s", ns)
		}
		nameservers = append(nameservers, nsWithPort)
	}
	return nameservers, nil
}

// CloseConnAndHandleError closes the connection and logs an error if it fails. Convenience function for code-reuse.
func CloseConnAndHandleError(conn net.Conn) {
	conn.Close()
}

// HasCtxExpired checks if the context has expired. Common function used in various places.
func HasCtxExpired(ctx context.Context) bool {
	select {
	case <-(ctx).Done():
		return true
	default:
		return false
	}
}

// extractIPAddresses takes in a slice containing strings of IP addresses, ranges, or CIDR blocks and returns a de-duped
// list of IP addresses, or an error if the string is invalid. Whitespace is trimmed from each address string and the
// ranges are inclusive.
// See config_test.go for examples of valid and invalid strings
func extractIPAddresses(input []string) ([]net.IP, error) {
	ipNets, err := extractCIDRRanges(input)
	if err != nil {
		return nil, fmt.Errorf("could not parse IP address string %v: %w", input, err)
	}
	ips := make([]net.IP, 0, len(ipNets))
	// need to expand the CIDR ranges into IP addresses
	for _, ipnet := range ipNets {
		for currentIP := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(currentIP); {
			tempIP := duplicateIP(currentIP)
			ips = append(ips, tempIP)
			incrementIP(currentIP)
			if currentIP.Equal(tempIP) {
				// our IP is the largest IPv4 or IPv6 addr possible, and has saturated
				break
			}
		}
	}
	// de-dupe
	lookupMap := make(map[string]struct{})
	dedupedIPs := make([]net.IP, 0, len(ips))
	for _, i := range ips {
		ipString := i.String()
		if _, ok := lookupMap[ipString]; !ok {
			lookupMap[ipString] = struct{}{}
			dedupedIPs = append(dedupedIPs, i)
		}
	}
	return dedupedIPs, nil

}

// extractCIDRRanges takes in a slice containing strings of IP addresses, ranges, or CIDR blocks and returns a de-duped
// list of CIDR ranges, or an error if the string is invalid. Whitespace is trimmed from each address string
func extractCIDRRanges(inputs []string) ([]net.IPNet, error) {
	ipNets := make([]net.IPNet, 0, len(inputs))
	for _, addr := range inputs {
		addr = strings.TrimSpace(addr) // remove whitespace
		if len(addr) == 0 {
			continue // skip empty strings
		}
		// this addr is either an IP address, ip address range, or a CIDR range
		_, ipnet, err := net.ParseCIDR(addr)
		if err == nil {
			ipNets = append(ipNets, *ipnet)
			continue
		}
		if strings.Contains(addr, "-") {
			// IP range
			parts := strings.Split(addr, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid IP range %s", addr)
			}
			parts[0] = strings.TrimSpace(parts[0])
			parts[1] = strings.TrimSpace(parts[1])
			startIP := net.ParseIP(parts[0])
			endIP := net.ParseIP(parts[1])
			if startIP == nil {
				return nil, fmt.Errorf("invalid start IP %s of IP range", parts[0])
			}
			if endIP == nil {
				return nil, fmt.Errorf("invalid end IP %s of IP range", parts[1])
			}
			if compareIPs(startIP, endIP) > 0 {
				return nil, fmt.Errorf("start IP %s is greater than end IP %s of IP range", startIP.String(), endIP.String())
			}
			if (startIP.To4() == nil) != (endIP.To4() == nil) {
				return nil, fmt.Errorf("start IP %s and end IP %s of IP range are not the same type", startIP.String(), endIP.String())
			}
			isIPv4 := startIP.To4() != nil
			for currentIP := startIP; compareIPs(currentIP, endIP) <= 0; {
				tempIP := duplicateIP(currentIP)
				if isIPv4 {
					ipNets = append(ipNets, net.IPNet{IP: tempIP, Mask: net.CIDRMask(32, 32)})
				} else {
					ipNets = append(ipNets, net.IPNet{IP: tempIP, Mask: net.CIDRMask(128, 128)})
				}
				incrementIP(currentIP)
				if currentIP.Equal(tempIP) {
					// our IP is the largest IPv4 or IPv6 addr possible, and has saturated
					break
				}
			}
			continue
		}
		// single IP
		castIP := net.ParseIP(addr)
		if castIP == nil {
			return nil, fmt.Errorf("could not parse IP address %s", addr)
		}
		if castIP.To4() != nil {
			ipNets = append(ipNets, net.IPNet{IP: castIP, Mask: net.CIDRMask(32, 32)})
		} else {
			ipNets = append(ipNets, net.IPNet{IP: castIP, Mask: net.CIDRMask(128, 128)})
		}
	}
	// de-dupe
	lookupMap := make(map[string]struct{})
	dedupedIPNets := make([]net.IPNet, 0, len(ipNets))
	for _, i := range ipNets {
		str := i.String()
		if _, ok := lookupMap[str]; !ok {
			lookupMap[str] = struct{}{}
			dedupedIPNets = append(dedupedIPNets, i)
		}
	}
	return dedupedIPNets, nil
}

// extractPorts takes in a string of comma-separated ports or port ranges (80-443) and returns a de-duped list of ports
// Whitespace is trimmed from each port string, and the port range is inclusive.
func extractPorts(portString string) ([]uint16, error) {
	portMap := make(map[uint16]struct{})
	for _, portStr := range strings.Split(portString, ",") {
		portStr = strings.TrimSpace(portStr)
		if strings.Contains(portStr, "-") {
			// port range
			parts := strings.Split(portStr, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port range %s, valid range ex: '80-443'", portStr)
			}
			startPort, err := parsePortString(parts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid start port %s of port range: %w", parts[0], err)
			}
			endPort, err := parsePortString(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid end port %s of port range: %w", parts[1], err)
			}
			if startPort >= endPort {
				return nil, fmt.Errorf("start port %d must be less than end port %d", startPort, endPort)
			}
			// validation complete, add all ports in range
			for i := startPort; i <= endPort; i++ {
				portMap[i] = struct{}{}
			}
		} else {
			// single port
			port, err := parsePortString(portStr)
			if err != nil {
				return nil, fmt.Errorf("invalid port %s: %w", portStr, err)
			}
			portMap[port] = struct{}{}
		}
	}
	// build list from de-duped map
	ports := make([]uint16, 0, len(portMap))
	for port := range portMap {
		ports = append(ports, port)
	}
	return ports, nil
}

// parsePortString converts a string to a uint16 port number after removing whitespace
// Checks for validity of the port number and returns an error if invalid
func parsePortString(portStr string) (uint16, error) {
	minimumPort := uint64(1)     // inclusive
	maximumPort := uint64(65535) // inclusive
	port, err := strconv.ParseUint(strings.TrimSpace(portStr), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %s: %w", portStr, err)
	}
	if port < minimumPort {
		return 0, fmt.Errorf("port %s must be in the range [%d,%d]", portStr, minimumPort, maximumPort)
	}
	if port > maximumPort {
		return 0, fmt.Errorf("port %s must be in the range [%d,%d]", portStr, minimumPort, maximumPort)
	}
	return uint16(port), nil
}

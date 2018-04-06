package zgrab2

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"

	"time"

	"github.com/zmap/zflags"
)

var parser *flags.Parser

func init() {
	parser = flags.NewParser(&config, flags.Default)
}

// NewIniParser creates and returns a ini parser initialized
// with the default parser
func NewIniParser() *flags.IniParser {
	return flags.NewIniParser(parser)
}

// AddCommand adds a module to the parser and returns a pointer to
// a flags.command object or an error
func AddCommand(command string, shortDescription string, longDescription string, port int, m ScanModule) (*flags.Command, error) {
	cmd, err := parser.AddCommand(command, shortDescription, longDescription, m)
	if err != nil {
		return nil, err
	}
	cmd.FindOptionByLongName("port").Default = []string{strconv.FormatUint(uint64(port), 10)}
	cmd.FindOptionByLongName("name").Default = []string{command}
	modules[command] = m
	return cmd, nil
}

// ParseCommandLine parses the commands given on the command line
// and validates the framework configuration (global options)
// immediately after parsing
func ParseCommandLine(flags []string) ([]string, string, ScanFlags, error) {
	posArgs, moduleType, f, err := parser.ParseCommandLine(flags)
	if err == nil {
		validateFrameworkConfiguration()
	}
	sf, _ := f.(ScanFlags)
	return posArgs, moduleType, sf, err
}

// ParseTarget takes input as a string and parses it into either an IPNet
// (may have empty mask and just contain IP , domain name, or errors, may
// return both IPNet and domain name
func ParseTarget(s string) (*net.IPNet, string, error) {
	i := strings.IndexByte(s, ',')
	j := strings.IndexByte(s, '/')

	switch {
	case i == -1 && j == -1:
		// just ip or domain
		if ip := net.ParseIP(s); ip != nil {
			return &net.IPNet{IP: ip}, "", nil
		}
		ips, err := net.LookupIP(s)
		if err != nil {
			return nil, "", err
		}
		return &net.IPNet{IP: ips[0]}, s, nil // only return first IP after a lookup
	case i == -1:
		// cidr block
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, "", err
		}
		return ipnet, "", nil
	case j == -1:
		// ip,domain
		str := strings.Split(s, ",")
		if len(str) != 2 {
			return nil, "", errors.New("malformed input")
		}
		d := strings.TrimSpace(str[1])
		if ip := net.ParseIP(str[0]); ip != nil {
			return &net.IPNet{IP: ip}, d, nil
		}
		return nil, d, nil
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

// Make this implement the net.Error interface so that err.(net.Error).Timeout() works.
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
	min := func(a, b int) int {
		if a < b {
			return a
		}
		return b
	}
	var totalDeadline time.Time
	if totalTimeout == 0 {
		// Would be nice if this could be taken from the SetReadDeadline(), but that's not possible in general
		const defaultTotalTimeout = 1 * time.Second
		totalTimeout = defaultTotalTimeout
		timeoutConn, isTimeoutConn := conn.(*TimeoutConnection)
		if isTimeoutConn {
			totalTimeout = timeoutConn.Timeout
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
	if err != nil || n < bufferSize || n >= maxReadSize {
		return ret, err
	}
	maxReadSize -= n

	// If there were more than bufSize -1 bytes available, read whatever is
	// available without blocking longer than timeout, and do not treat timeouts
	// as an error.
	// Keep reading until we time out or get an error.
	for totalDeadline.IsZero() || totalDeadline.After(time.Now()) {
		deadline := time.Now().Add(readTimeout)
		conn.SetReadDeadline(deadline)
		n, err := conn.Read(buf[0:min(maxReadSize, bufferSize)])
		maxReadSize -= n
		ret = append(ret, buf[0:n]...)
		if err != nil {
			if IsTimeoutError(err) {
				err = nil
			}
		}
		if err != nil {
			return ret, err
		}
		if n < bufferSize || n >= maxReadSize {
			return ret, err
		}
	}
	return ret, ErrTotalTimeout
}

var InsufficientBufferError = errors.New("not enough buffer space")

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
			return length, InsufficientBufferError
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

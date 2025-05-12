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
	flags "github.com/zmap/zflags"
)

var parser *flags.Parser

const defaultDNSPort = "53"

func init() {
	parser = flags.NewParser(&config, flags.Default)
	desc := []string{
		// Using a long single line so the terminal can handle wrapping, except for Input/Examples which should be on
		// separate lines
		"zgrab2 is fast, modular L7 application-layer scanner. It is commonly used with tools like ZMap which identify " +
			"\"potential services\", or services we know are active on a given IP + port, and these are fed into ZGrab2 " +
			"to confirm and provide details of the service. It has support for a number of protocols listed below as " +
			"'Available commands' including SSH and HTTP. By default, zgrab2 will accept input from stdin and output " +
			"results to stdout, with updates and logs to stderr. Please see 'zgrab2 <command> --help' for more details " +
			"on a specific command.",
		"Input is taken from stdin or --input-file, if specified. Input is CSV-formatted with 'IP, Domain, Tag, Port' " +
			"or simply 'IP' or 'Domain'. See README.md for more details.",
		"",
		"Example usages:",
		"echo '1.1.1.1' | zgrab2 tls          # Scan 1.1.1.1 with TLS",
		"echo example.com | zgrab2 http     # Scan example.com with HTTP",
	}
	parser.LongDescription = strings.Join(desc, "\n")
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
	cmd.FindOptionByLongName("port").Default = []string{strconv.Itoa(port)}
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
	err := conn.Close()
	if err != nil {
		logrus.Errorf("could not close connection to %v: %v", conn.RemoteAddr(), err)
	}
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

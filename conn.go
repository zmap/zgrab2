package zgrab2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
	"os"
	"golang.org/x/time/rate"

	"github.com/censys/cidranger"

	"github.com/sirupsen/logrus"
)

// ReadLimitExceededAction describes how the connection reacts to an attempt to read more data than permitted.
type ReadLimitExceededAction string

const (
	// ReadLimitExceededActionNotSet is a placeholder for the zero value, so that explicitly set values can be
	// distinguished from the empty default.
	ReadLimitExceededActionNotSet = ReadLimitExceededAction("")

	// ReadLimitExceededActionTruncate causes the connection to truncate at BytesReadLimit bytes and return a bogus
	// io.EOF error. The fact that a truncation took place is logged at debug level.
	ReadLimitExceededActionTruncate = ReadLimitExceededAction("truncate")

	// ReadLimitExceededActionError causes the Read call to return n, ErrReadLimitExceeded (in addition to truncating).
	ReadLimitExceededActionError = ReadLimitExceededAction("error")

	// ReadLimitExceededActionPanic causes the Read call to panic(ErrReadLimitExceeded).
	ReadLimitExceededActionPanic = ReadLimitExceededAction("panic")
)

var (
	// DefaultBytesReadLimit is the maximum number of bytes to read per connection when no explicit value is provided.
	DefaultBytesReadLimit = 256 * 1024 * 1024

	// DefaultReadLimitExceededAction is the action used when no explicit action is set.
	DefaultReadLimitExceededAction = ReadLimitExceededActionTruncate

	// DefaultSessionTimeout is the default maximum time a connection may be used when no explicit value is provided.
	DefaultSessionTimeout = 1 * time.Minute
)

// ErrReadLimitExceeded is returned / panic'd from Read if the read limit is exceeded when the
// ReadLimitExceededAction is error / panic.
var ErrReadLimitExceeded = errors.New("read limit exceeded")

var udpNetworkList = []string{
	"udp",
	"udp4",
	"udp6",
	"unixgram",
}

var ipNetworkList = []string{
	"ip",
	"ip4",
	"ip6",
}

const (
	DefaultSharedSocketBufferLength = 10
)

var (
	udpSharedSocket *SharedSocket
	udpOnce         sync.Once
	udpInitErr      error

	ipSharedSocket *SharedSocket
	ipOnce         sync.Once
	ipInitErr      error
)

// TimeoutConnection wraps an existing net.Conn connection, overriding the Read/Write methods to use the configured timeouts
// TODO: Refactor this into TimeoutConnection, BoundedReader, LoggedReader, etc
type TimeoutConnection struct {
	net.Conn
	ctx                     context.Context
	SessionTimeout          time.Duration // used to set the connection deadline, set once
	ReadTimeout             time.Duration // used to set the read deadline, set fresh for each read
	WriteTimeout            time.Duration // used to set the write deadline, set fresh for each write
	BytesRead               int
	BytesWritten            int
	BytesReadLimit          int
	ReadLimitExceededAction ReadLimitExceededAction
	Cancel                  context.CancelFunc
}

// SaturateTimeoutsToReadAndWriteTimeouts gets the minimum of the context deadline, the timeout, and the read/write timeouts
// and sets the read/write timeouts accordingly. This is necessary because the underlying connection only supports a
// deadline on reads and a deadline on writes, so we need to compute the minimum of all these to find what to set the
// underlying conn's read/write deadlines to.
func (c *TimeoutConnection) SaturateTimeoutsToReadAndWriteTimeouts() {
	// Get the minimum of the context deadline and the timeout
	minDeadline := int64(math.MaxInt64)
	if ctxDeadline, ok := c.ctx.Deadline(); ok {
		minDeadline = int64(time.Until(ctxDeadline))
	}
	if c.SessionTimeout > 0 {
		minDeadline = min(minDeadline, int64(c.SessionTimeout))
	}
	c.SessionTimeout = time.Duration(minDeadline)

	// Now we'll check read and write timeouts.
	if c.ReadTimeout > 0 {
		c.ReadTimeout = time.Duration(min(minDeadline, int64(c.ReadTimeout)))
	} else {
		c.ReadTimeout = time.Duration(minDeadline)
	}

	if c.WriteTimeout > 0 {
		c.WriteTimeout = time.Duration(min(minDeadline, int64(c.WriteTimeout)))
	} else {
		c.WriteTimeout = time.Duration(minDeadline)
	}
}

// TimeoutConnection.Read calls Read() on the underlying connection, using any configured deadlines
func (c *TimeoutConnection) Read(b []byte) (n int, err error) {
	if err = c.checkContext(); err != nil {
		return 0, err
	}
	origSize := len(b)
	if c.BytesRead+len(b) >= c.BytesReadLimit {
		b = b[0 : c.BytesReadLimit-c.BytesRead]
	}
	c.SaturateTimeoutsToReadAndWriteTimeouts()
	if err = c.Conn.SetReadDeadline(time.Now().Add(c.ReadTimeout)); err != nil {
		return 0, err
	}
	n, err = c.Conn.Read(b)
	c.BytesRead += n
	if err == nil && origSize != len(b) && n == len(b) {
		// we had to shrink the output buffer AND we used up the whole shrunk size, AND we're not at EOF
		switch c.ReadLimitExceededAction {
		case ReadLimitExceededActionTruncate:
			logrus.Debugf("Truncated read from %d bytes to %d bytes (hit limit of %d bytes)", origSize, n, c.BytesReadLimit)
			err = io.EOF
		case ReadLimitExceededActionError:
			return n, ErrReadLimitExceeded
		case ReadLimitExceededActionPanic:
			panic(ErrReadLimitExceeded)
		default:
			logrus.Fatalf("Unrecognized ReadLimitExceededAction: %s", c.ReadLimitExceededAction)
		}
	}
	return n, err
}

// TimeoutConnection.Write calls Write() on the underlying connection, using any configured deadlines.
func (c *TimeoutConnection) Write(b []byte) (n int, err error) {
	if err = c.checkContext(); err != nil {
		return 0, err
	}
	c.SaturateTimeoutsToReadAndWriteTimeouts()
	if err = c.Conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout)); err != nil {
		return 0, err
	}
	n, err = c.Conn.Write(b)
	c.BytesWritten += n
	return n, err
}

// SetReadDeadline sets an explicit ReadDeadline that will override the timeout
// for one read.
func (c *TimeoutConnection) SetReadDeadline(deadline time.Time) error {
	if err := c.checkContext(); err != nil {
		return err
	}
	if !deadline.IsZero() {
		c.ReadTimeout = time.Until(deadline)
	}
	return nil
}

// SetWriteDeadline sets an explicit WriteDeadline that will override the
// WriteDeadline for one write.
func (c *TimeoutConnection) SetWriteDeadline(deadline time.Time) error {
	if err := c.checkContext(); err != nil {
		return err
	}
	if !deadline.IsZero() {
		c.WriteTimeout = time.Until(deadline)
	}
	return nil
}

// SetDeadline sets a read / write deadline that will override the deadline for
// a single read/write.
func (c *TimeoutConnection) SetDeadline(deadline time.Time) error {
	if err := c.checkContext(); err != nil {
		return err
	}
	if !deadline.IsZero() {
		err := c.Conn.SetDeadline(deadline)
		if err != nil {
			return err
		}
	}
	return nil
}

// Close the underlying connection.
func (c *TimeoutConnection) Close() error {
	return c.Conn.Close()
}

// Check if the context has been cancelled, and if so, return an error (either the context error, or
// if the context error is nil, ErrTotalTimeout).
func (c *TimeoutConnection) checkContext() error {
	if c.ctx == nil {
		return nil
	}
	select {
	case <-c.ctx.Done():
		if err := c.ctx.Err(); err != nil {
			return err
		} else {
			return ErrTotalTimeout
		}
	default:
		return nil
	}
}

// NewTimeoutConnection returns a new TimeoutConnection with the appropriate defaults.
func NewTimeoutConnection(ctx context.Context, conn net.Conn, sessionTimeout, readTimeout, writeTimeout time.Duration, bytesReadLimit int) *TimeoutConnection {
	ret := &TimeoutConnection{
		ctx:            ctx,
		Conn:           conn,
		SessionTimeout: sessionTimeout,
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		BytesReadLimit: bytesReadLimit,
	}
	if sessionTimeout > 0 {
		ret.ctx, ret.Cancel = context.WithTimeout(ctx, sessionTimeout)
	} else {
		ret.ctx, ret.Cancel = context.WithCancel(ctx)
	}
	ret.SaturateTimeoutsToReadAndWriteTimeouts()
	return ret
}

// Dialer provides Dial and DialContext methods to get connections with the given timeout.
type Dialer struct {
	// SessionTimeout is the maximum time to wait for the entire session, after which any operations on the
	// connection will fail. Dial-specific timeouts are set on the net.Dialer.
	SessionTimeout time.Duration

	// ReadTimeout is the maximum time to wait for a Read
	ReadTimeout time.Duration

	// WriteTimeout is the maximum time to wait for a Write
	WriteTimeout time.Duration

	// Dialer is an auxiliary dialer used for DialContext (the result gets wrapped in a
	// TimeoutConnection).
	*net.Dialer

	// BytesReadLimit is the maximum number of bytes that connections dialed with this dialer will
	// read before erroring.
	BytesReadLimit int

	// ReadLimitExceededAction describes how connections dialed with this dialer deal with exceeding
	// the BytesReadLimit.
	ReadLimitExceededAction ReadLimitExceededAction

	// Blocklist of IPs we should not dial.
	Blocklist cidranger.Ranger
}

// Dialer provides Dial and DialContext methods to get connections with the given timeout.
type SharedSocket struct {
	conn  net.PacketConn
	conns []*SharedSocketConn
	mu    sync.RWMutex

	// Replace with context??
	closed       atomic.Bool // Global truth of socket being closed
	bufferLength int

	// denotes underlying network of the connection
	network string
}

type Callback func(network string, srcIP net.IP, srcPort uint, actualPacket []byte) bool

type SharedSocketConn struct {
	cb         Callback
	parent     *SharedSocket
	recvCh     chan ReadResult
	closed     atomic.Bool
	done   chan struct{}
	remoteAddr net.Addr
	readDeadline time.Time
	writeDeadline time.Time
	deadlineMu	  sync.Mutex
	readTimer 		*time.Timer
	writeTimer	 	*time.Timer

}

type SharedDialer struct {
	// SessionTimeout is the maximum time to wait for the entire session, after which any operations on the
	// connection will fail. Dial-specific timeouts are set on the net.Dialer.
	SessionTimeout time.Duration

	// ReadTimeout is the maximum time to wait for a Read
	ReadTimeout time.Duration

	// WriteTimeout is the maximum time to wait for a Write
	WriteTimeout time.Duration

	Timeout time.Duration

	*net.Resolver

	// Dialer is an auxiliary dialer used for DialContext (the result gets wrapped in a
	// TimeoutConnection).
	// *net.Dialer

	// BytesReadLimit is the maximum number of bytes that connections dialed with this dialer will
	// read before erroring.
	BytesReadLimit int

	// ReadLimitExceededAction describes how connections dialed with this dialer deal with exceeding
	// the BytesReadLimit.
	ReadLimitExceededAction ReadLimitExceededAction

	// Blocklist of IPs we should not dial.
	Blocklist cidranger.Ranger

	parent *SharedSocket
	closed atomic.Bool
}

type ReadResult struct {
	packet []byte
	n      int
	addr   net.Addr
	err    error
}

// TODO: Want user interaction with DialContext to be effectively identical
// DialContext wraps the connection returned by net.Dialer.DialContext() with a TimeoutConnection.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// potentially the user set the SessionTimeout after calling NewDialer. If so, we'll set the dialer's timeout here
	if d.SessionTimeout != 0 {
		if d.Timeout == 0 {
			d.Timeout = d.SessionTimeout
		} else {
			// if both session and dial timeout are set, use the minimum of both
			d.Timeout = min(d.Timeout, d.SessionTimeout)
		}
	}
	// Determine if address is a domain or an IP address
	var conn net.Conn
	host, port, err := net.SplitHostPort(address)
	if err == nil && net.ParseIP(host) == nil {
		// address is a domain
		conn, err = d.dialContextDomain(ctx, network, host, port)
	} else {
		// address is an IP, check blocklist
		if d.Blocklist != nil {
			ip := net.ParseIP(host)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %s", host)
			}
			if contains, _ := d.Blocklist.Contains(ip); contains {
				return nil, &ScanError{
					Status: SCAN_BLOCKLISTED_TARGET,
					Err:    fmt.Errorf("dialing blocked IP: %s", host),
				}
			}
		}
		// Check rate limits
		ip := net.ParseIP(host)
		ipAddr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, fmt.Errorf("invalid IP address: %s", host)
		}
		if err = ipRateLimiter.WaitOrCreate(ctx, ipAddr, rate.Limit(config.ServerRateLimit), config.ServerRateLimit); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, &ScanError{
					Status: SCAN_CONNECTION_TIMEOUT,
					Err:    fmt.Errorf("dialing IP %s timed out or was cancelled while waiting for rate limit token", host),
				}
			}
			return nil, fmt.Errorf("failed to wait for rate limiter for IP %s: %w", host, err)
		}

		// can proceed with dialing the IP address, not blocklisted
		conn, err = d.Dialer.DialContext(ctx, network, address)
	}

	if err != nil {
		return nil, fmt.Errorf("dial context failed: %w", err)
	}
	ret := NewTimeoutConnection(ctx, conn, d.SessionTimeout, d.ReadTimeout, d.WriteTimeout, d.BytesReadLimit)
	ret.BytesReadLimit = d.BytesReadLimit
	ret.ReadLimitExceededAction = d.ReadLimitExceededAction
	return ret, nil
}

// Equivalent of DialContext of Dialer but for SharedDialer
func (d *SharedDialer) DialContext(ctx context.Context, network, address string, callback Callback) (net.Conn, error) {

	// potentially the user set the SessionTimeout after calling NewDialer. If so, we'll set the dialer's timeout here
	if d.SessionTimeout != 0 {
		// TODO: Refactor to institute timeout on this dial connection
		if d.Timeout == 0 {
			d.Timeout = d.SessionTimeout
		} else {
			// if both session and dial timeout are set, use the minimum of both
			d.Timeout = min(d.Timeout, d.SessionTimeout)
		}
	}

	// Determine if address is a domain or an IP address
	var conn net.Conn
	host, port, err := net.SplitHostPort(address)
	if err == nil && net.ParseIP(host) == nil {
		// address is a domain
		// TODO: Add resolver and add domain support
		conn, err = d.dialContextDomain(ctx, network, host, port, callback)
	} else {
		// address is an IP, check blocklist
		if d.Blocklist != nil {
			ip := net.ParseIP(host)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %s", host)
			}
			if contains, _ := d.Blocklist.Contains(ip); contains {
				return nil, &ScanError{
					Status: SCAN_BLOCKLISTED_TARGET,
					Err:    fmt.Errorf("dialing blocked IP: %s", host),
				}
			}
		}
		// Check rate limits
		ip := net.ParseIP(host)
		ipAddr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, fmt.Errorf("invalid IP address: %s", host)
		}
		if err = ipRateLimiter.WaitOrCreate(ctx, ipAddr, rate.Limit(config.ServerRateLimit), config.ServerRateLimit); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, &ScanError{
					Status: SCAN_CONNECTION_TIMEOUT,
					Err:    fmt.Errorf("dialing IP %s timed out or was cancelled while waiting for rate limit token", host),
				}
			}
			return nil, fmt.Errorf("failed to wait for rate limiter for IP %s: %w", host, err)
		}

		// can proceed with dialing the IP address, not blocklisted
		conn, err = d.DialContextSharedDialer(ctx, network, address, callback)
	}

	if err != nil {
		return nil, fmt.Errorf("dial context failed: %w", err)
	}

	ret := NewTimeoutConnection(ctx, conn, d.SessionTimeout, d.ReadTimeout, d.WriteTimeout, d.BytesReadLimit)
	ret.BytesReadLimit = d.BytesReadLimit
	ret.ReadLimitExceededAction = d.ReadLimitExceededAction
	return ret, nil
}

func (d *SharedDialer) dialContextDomain(ctx context.Context, network, host, port string, callback Callback) (net.Conn, error) {
	// return nil, nil
	// Lookup name

	usableIPs, err := d.lookupIPs(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup IPs for domain %s: %w", host, err)
	}

	// Time-sharing mechanism across all IPs
	timeout := d.Timeout // How long to wait for all IPs
	if ctxDeadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(ctxDeadline))
	}
	singleIPTimeout := timeout / time.Duration(len(usableIPs)) // Give each IP an equal share of the timeout
	originalDialerTimeout := d.Timeout
	defer func() {
		d.Timeout = originalDialerTimeout // Restore the original timeout after dialing
	}()
	d.Timeout = singleIPTimeout // Dialer will only wait for this amount of time for each IP
	var conn net.Conn
	for _, ip := range usableIPs {
		conn, err = d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port), callback)
		if err == nil {
			return conn, nil
		}
	}
	return nil, &ScanError{
		Status: SCAN_CONNECTION_TIMEOUT,
		Err:    fmt.Errorf("failed to connect to any IPs for domain %s within timeout. Last IP errored with: %w", host, err),
	}

}

func (d *SharedDialer) lookupIPs(ctx context.Context, host string) ([]net.IP, error) {
	if err := dnsRateLimiter.Wait(ctx); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, &ScanError{
				Status: SCAN_CONNECTION_TIMEOUT,
				Err:    fmt.Errorf("dns lookup %s timed out or was cancelled while waiting for rate limit token", host),
			}
		}
		return nil, fmt.Errorf("failed to wait for rate limiter for DNS: %w", err)
	}
	ips, err := d.Resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs found for domain %s", host)
	}
	// Remove Unreachable IPs
	filteredIPs := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		isIPv4 := ip.To4() != nil
		isIPv6 := !isIPv4 && ip.To16() != nil
		if config.resolveIPv4 && isIPv4 {
			filteredIPs = append(filteredIPs, ip)
		} else if config.resolveIPv6 && isIPv6 {
			filteredIPs = append(filteredIPs, ip)
		}
		// Else, skip
	}
	if len(filteredIPs) == 0 {
		return nil, fmt.Errorf("no reachable IPs found for domain %s with IPv4=%t, IPv6=%t", host, config.resolveIPv4, config.resolveIPv6)
	}
	// Filter out blocklisted IPs
	if d.Blocklist != nil {
		newFilteredIPs := make([]net.IP, 0, len(filteredIPs))
		for _, ip := range filteredIPs {
			if contains, _ := d.Blocklist.Contains(ip); !contains {
				newFilteredIPs = append(newFilteredIPs, ip)
			}
		}
		filteredIPs = newFilteredIPs
	}
	if len(filteredIPs) == 0 {
		return nil, &ScanError{
			Status: SCAN_BLOCKLISTED_TARGET,
			Err:    fmt.Errorf("no reachable IPs found for domain %s after filtering blocklisted IPs", host),
		}
	}
	return filteredIPs, nil
}

// DialContext acts like dial, but serves as a buffer between underlying listen connection and the dial interface
func (d *SharedDialer) DialContextSharedDialer(ctx context.Context, network, address string, callback Callback) (net.Conn, error) {
	switch {
	case isUDPNetwork(network):
		addr, err := net.ResolveUDPAddr("udp", address)
		// TODO: Add error
		if err != nil {
			return nil, fmt.Errorf("invalid UDP address: %s", address)
		}
		socket, _ := getUDPSharedSocket("")
		conn, err := socket.AddConnection(network, addr, callback)
		if err != nil {
			return nil, &ScanError{
				Status: SCAN_BLOCKLISTED_TARGET,
				Err:    fmt.Errorf("dialing UDP failed: %s", address),
			}
		}
		return conn, err
	// TODO: implement IP support
	// case isIPNetwork(network):
	// addr, err := net.ResolveIPAddr("ip", address)
	// if err != nil {
	// 	return nil, fmt.Errorf("invalid IP address: %s", address)
	// }
	// conn, err := net.ListenIP(network, addr)
	// if err != nil {
	// 	return nil, &ScanError{
	// 		Status: SCAN_CONNECTION_REFUSED,
	// 		Err:    fmt.Errorf("dialing IP failed: %s", address),
	// 	}
	// }
	// return conn, err
	default:
		return nil, &ScanError{
			Status: SCAN_PROTOCOL_ERROR,
			Err:    fmt.Errorf("unable to parse protocol: %s", network),
		}
	}
}

// dialContextDomain emulates what net.Dialer.DialContext does for domains, but with additional logic to handle not
// connecting to unreachable IPs (defined as IPs that are not reachable due to IPv4/IPv6 settings) and blocklisted IPs.
// We'll:
// 1. Perform a DNS lookup for the domain to get all IPs.
// 2. Filter out IPs that are not reachable due to IPv4/IPv6 settings.
// 3. Filter out blocklisted IPs.
// 4. Calculate a timeout sharing mechanism to give each reachable IP an equal share of the timeout overall.
func (d *Dialer) dialContextDomain(ctx context.Context, network, host, port string) (net.Conn, error) {
	// Lookup name
	usableIPs, err := d.lookupIPs(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup IPs for domain %s: %w", host, err)
	}

	// Time-sharing mechanism across all IPs
	timeout := d.Timeout // How long to wait for all IPs
	if ctxDeadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(ctxDeadline))
	}
	singleIPTimeout := timeout / time.Duration(len(usableIPs)) // Give each IP an equal share of the timeout
	originalDialerTimeout := d.Timeout
	defer func() {
		d.Timeout = originalDialerTimeout // Restore the original timeout after dialing
	}()
	d.Timeout = singleIPTimeout // Dialer will only wait for this amount of time for each IP
	var conn net.Conn
	for _, ip := range usableIPs {
		conn, err = d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, &ScanError{
		Status: SCAN_CONNECTION_TIMEOUT,
		Err:    fmt.Errorf("failed to connect to any IPs for domain %s within timeout. Last IP errored with: %w", host, err),
	}

}

func (d *Dialer) lookupIPs(ctx context.Context, host string) ([]net.IP, error) {
	if err := dnsRateLimiter.Wait(ctx); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, &ScanError{
				Status: SCAN_CONNECTION_TIMEOUT,
				Err:    fmt.Errorf("dns lookup %s timed out or was cancelled while waiting for rate limit token", host),
			}
		}
		return nil, fmt.Errorf("failed to wait for rate limiter for DNS: %w", err)
	}
	ips, err := d.Resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs found for domain %s", host)
	}
	// Remove Unreachable IPs
	filteredIPs := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		isIPv4 := ip.To4() != nil
		isIPv6 := !isIPv4 && ip.To16() != nil
		if config.resolveIPv4 && isIPv4 {
			filteredIPs = append(filteredIPs, ip)
		} else if config.resolveIPv6 && isIPv6 {
			filteredIPs = append(filteredIPs, ip)
		}
		// Else, skip
	}
	if len(filteredIPs) == 0 {
		return nil, fmt.Errorf("no reachable IPs found for domain %s with IPv4=%t, IPv6=%t", host, config.resolveIPv4, config.resolveIPv6)
	}
	// Filter out blocklisted IPs
	if d.Blocklist != nil {
		newFilteredIPs := make([]net.IP, 0, len(filteredIPs))
		for _, ip := range filteredIPs {
			if contains, _ := d.Blocklist.Contains(ip); !contains {
				newFilteredIPs = append(newFilteredIPs, ip)
			}
		}
		filteredIPs = newFilteredIPs
	}
	if len(filteredIPs) == 0 {
		return nil, &ScanError{
			Status: SCAN_BLOCKLISTED_TARGET,
			Err:    fmt.Errorf("no reachable IPs found for domain %s after filtering blocklisted IPs", host),
		}
	}
	return filteredIPs, nil
}

// Dial returns a connection with the configured timeout.
func (d *Dialer) Dial(proto string, target string) (net.Conn, error) {
	return d.DialContext(context.Background(), proto, target)
}

// GetTimeoutConnectionDialer gets a Dialer that dials connections with the given timeout.
func GetTimeoutConnectionDialer(dialTimeout, sessionTimeout time.Duration) *Dialer {
	dialer := NewDialer(nil)
	dialer.Timeout = dialTimeout
	dialer.SessionTimeout = sessionTimeout
	return dialer
}

// GetTimeoutConnectionDialer gets a Shared Dialer that dials connections with the given timeout.
func GetTimeoutConnectionSharedDialer(dialTimeout, sessionTimeout time.Duration) *SharedDialer {
	dialer := NewSharedDialer(nil)
	dialer.Timeout = dialTimeout
	dialer.SessionTimeout = sessionTimeout
	return dialer
}

// SetDefaults for the Dialer.
func (d *Dialer) SetDefaults() *Dialer {
	if d.ReadLimitExceededAction == ReadLimitExceededActionNotSet {
		d.ReadLimitExceededAction = DefaultReadLimitExceededAction
	}
	if d.BytesReadLimit == 0 {
		d.BytesReadLimit = DefaultBytesReadLimit
	}
	if d.Dialer == nil {
		d.Dialer = &net.Dialer{} // initialize defaults to prevent nil pointer dereference
		if len(config.customDNSNameservers) > 0 {
			d.Dialer = &net.Dialer{}
			// this may be a single IP address or a comma-separated list of IP addresses
			ns := config.customDNSNameservers[rand.Intn(len(config.customDNSNameservers))]
			d.Resolver = &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					return d.Dialer.DialContext(ctx, network, ns)
				},
			}
		}
	}
	return d
}

// SetDefaults for the Dialer.
func (d *SharedDialer) SetDefaults() *SharedDialer {
	if d.ReadLimitExceededAction == ReadLimitExceededActionNotSet {
		d.ReadLimitExceededAction = DefaultReadLimitExceededAction
	}
	if d.BytesReadLimit == 0 {
		d.BytesReadLimit = DefaultBytesReadLimit
	}

	// TODO: Integrate support for DNS resolver
	// this may be a single IP address or a comma-separated list of IP addresses
	// ns := config.customDNSNameservers[rand.Intn(len(config.customDNSNameservers))]

	// d.Resolver = &net.Resolver{
	// 	PreferGo: true,
	// 	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
	// 		return d.DialContext(ctx, network, ns, cb)
	// 	},
	// }

	return d
}

// NewDialer creates a new Dialer with default settings.
// Blocklist, if provided, is used to prevent dialing certain IPs.
func NewDialer(value *Dialer) *Dialer {
	if value == nil {
		value = &Dialer{}
	}
	if value.Blocklist == nil {
		value.Blocklist = blocklist
	}
	return value.SetDefaults()
}

// NewDialer creates a new Dialer with default settings.
// Blocklist, if provided, is used to prevent dialing certain IPs.
func NewSharedDialer(value *SharedDialer) *SharedDialer {
	if value == nil {
		value = &SharedDialer{}
	}
	if value.Blocklist == nil {
		value.Blocklist = blocklist
	}
	return value.SetDefaults()
}

// SetRandomLocalAddr sets a random local address and port for the dialer. If either localIPs or localPorts are empty,
// the IP or port, respectively, will be un-set and the system will choose.
func (d *Dialer) SetRandomLocalAddr(network string, localIPs []net.IP, localPorts []uint16) error {
	var localIP net.IP
	if len(localIPs) != 0 {
		localIP = localIPs[rand.Intn(len(localIPs))]
	}
	var localPort int
	if len(localPorts) != 0 {
		localPort = int(localPorts[rand.Intn(len(localPorts))])
	}
	if localIP == nil && localPort == 0 {
		return nil // nothing to set
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		d.LocalAddr = &net.TCPAddr{
			IP:   localIP,
			Port: localPort,
		}
	case "udp", "udp4", "udp6":
		d.LocalAddr = &net.UDPAddr{
			IP:   localIP,
			Port: localPort,
		}
	default:
		return fmt.Errorf("unsupported network type: %s", network)
	}
	return nil
}

// SHAREDSOCKET Implementation

// Adds a connection object to the shared socket
func (s *SharedSocket) AddConnection(network string, remoteAddr net.Addr, callback Callback) (*SharedSocketConn, error) {
	// / If proposed network is not same as the Dialer's network, exit and
	// // return error about the mismatch
	if network != s.network {
		// TODO: Make more descriptive error
		return nil, &net.AddrError{
			Err:  fmt.Sprintf("mismatched network between socket and Connection object: socket is  %s, client is %s", s.network, network),
			Addr: network,
		}
	}

	// Shared Socket is already closed, return an error
	if s.closed.Load() {
		return nil, net.ErrClosed
	}

	// Expose a client connection to the client
	client_conn := &SharedSocketConn{
		cb:         	callback,
		parent:     	s,
		recvCh:     	make(chan ReadResult, s.bufferLength),
		closed:     	atomic.Bool{}, // Zero value is false
		done:   		make(chan struct{}),
		remoteAddr: 	remoteAddr,	
		readDeadline: 	time.Time{},
		writeDeadline: 	time.Time{},
		deadlineMu:	  	sync.Mutex{},
	}

	// Add this client connection
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns = append(s.conns, client_conn)

	return client_conn, nil
}

// Force close the shared socket (clear all clients)
func (s *SharedSocket) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, conn := range s.conns {
		conn.closed.Store(true)
	}
	s.closed.Store(true)
	s.conns = s.conns[:0]

	return s.conn.Close()
}

// Receives packets and muxes to respective clients
func (s *SharedSocket) ReadFromLoop() {
	for {
		b := make([]byte, 1024)
		n, addr, err := s.conn.ReadFrom(b)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
		}
		read := ReadResult{
			packet: b,
			n:      n,
			addr:   addr,
			err:    err,
		}

		var srcIP net.IP
		var srcPort uint

		// Conditional based on type of net.addr
		switch a := addr.(type) {
		case *net.UDPAddr:
			srcIP = a.IP
			srcPort = uint(a.Port)

		case *net.IPAddr:
			srcIP = a.IP
			srcPort = 0 // IP addrs have no ports, set to 0
		}

		s.mu.RLock()
		// Check the client connections to see which call back matches and then forward to that connection
		for _, conn := range s.conns {
			if conn.cb(s.network, srcIP, srcPort, b) {
				select {
				case conn.recvCh <- read:
					logrus.Debugf("Sent packet to back to %v", conn.remoteAddr)
				default:
					// Potentially add error handling here?
					logrus.Debugf("Dropping packet from remote %s, %d\n", srcIP.String(), srcPort)
				}
				break
			}
		}
		s.mu.RUnlock()
	}
}

func resetTimer(t **time.Timer, d time.Duration) <-chan time.Time {
    if *t == nil {
        *t = time.NewTimer(d)
        return (*t).C
    }
    if !(*t).Stop() {
        // timer already fired; drain if needed
        select {
        case <-(*t).C:
        default:
        }
    }
    (*t).Reset(d)
    return (*t).C
}

func getUDPSharedSocket(localAddr string) (*SharedSocket, error) {
	udpOnce.Do(func() {
		var addr *net.UDPAddr
		if localAddr != "" {
			var err error
			addr, err = net.ResolveUDPAddr("udp", localAddr)
			// TODO: Add error
			if err != nil {
				udpSharedSocket, udpInitErr = nil, fmt.Errorf("invalid UDP address: %s", localAddr)
				return
			}
		} else {
			addr = nil
		}

		var network string = "udp"
		// If localaddr is nil, OS will choose a port
		conn, err := net.ListenUDP(network, addr)

		if err != nil {
			udpSharedSocket, udpInitErr = nil, &ScanError{
				Status: SCAN_PROTOCOL_ERROR,
				Err:    fmt.Errorf("udp connection failed from %s", localAddr),
			}
			return
		}

		udpSharedSocket = &SharedSocket{
			conn:         conn,
			conns:        []*SharedSocketConn{},
			mu:           sync.RWMutex{},
			network:      network,
			bufferLength: DefaultSharedSocketBufferLength,
		}
		udpInitErr = nil

		go udpSharedSocket.ReadFromLoop()
	})

	return udpSharedSocket, udpInitErr
}

// Shared Socket Conn implementation. Acts as a translator between net.Listen and net.Dial
// (i.e. exposes an interface of net.conn, but operates on packetConn of listen)
func (c *SharedSocketConn) Read(p []byte) (int, error) {
    if c.closed.Load() || c.parent.closed.Load() {
        return 0, net.ErrClosed
    }

    dl := c.readDeadline // ideally read under a mutex if it can change concurrently
    if dl.IsZero() {
        readResult := <-c.recvCh
        n := copy(p, readResult.packet[:readResult.n])
        return n, readResult.err
    }

    remain := time.Until(dl)
    if remain <= 0 {
        return 0, os.ErrDeadlineExceeded
    }

    tc := resetTimer(&c.readTimer, remain)

    select {
    case rr := <-c.recvCh:
        n := copy(p, rr.packet[:rr.n])
        return n, rr.err
    case <-tc:
        return 0, os.ErrDeadlineExceeded
    case <-c.done:
        return 0, net.ErrClosed
    }
}

// Write function to implement net.conn
func (c *SharedSocketConn) Write(p []byte) (n int, err error) {
		if c.closed.Load() || c.parent.closed.Load() {
		return 0, net.ErrClosed
	}

	now := time.Now()
	dl := c.writeDeadline

	// If deadline exists and already expired → timeout immediately
	if !dl.IsZero() && !dl.After(now) {
		return 0, &net.OpError{
			Op:   "write",
			Net:  c.parent.network,
			Addr: c.remoteAddr,
			Err:  os.ErrDeadlineExceeded,
		}
	}

	// For UDP this usually does not block
	return c.parent.conn.WriteTo(p, c.RemoteAddr())
}

// TODO: Make it so that client close only affects per client state. Unless it is the last client, then fully close the shared socket
func (c *SharedSocketConn) Close() error {
	// Connection already closed (self or parent), do nothing
	if c.closed.Load() || c.parent.closed.Load() {
		return net.ErrClosed
	}

	c.parent.mu.Lock()
	defer c.parent.mu.Unlock()

	c.closed.Store(true)

	removeIndex := -1
	for i, conn := range c.parent.conns {
		if conn == c {
			removeIndex = i
		}
	}
	c.parent.conns[removeIndex] = c.parent.conns[len(c.parent.conns)-1]
	c.parent.conns = c.parent.conns[:len(c.parent.conns)-1]

	if len(c.parent.conns) > 0 {
		return nil
	}

	// If we have no remaining client connections, truly close the shared socket connection
	c.parent.closed.Store(true)
	return c.parent.conn.Close()
}

// Returns the local address of the parent SharedSocketDialer
func (c *SharedSocketConn) LocalAddr() net.Addr {
	return c.parent.conn.LocalAddr()
}

func (c *SharedSocketConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// TODO: Implement deadline functions on a per client basis
func (c *SharedSocketConn) SetDeadline(t time.Time) error {
	err := c.SetReadDeadline(t)
	if err != nil {
		return err
	}
	err = c.SetWriteDeadline(t)
	if err != nil {
		return err
	}
	return nil
}

// Todo: add client specific read deadline 
func (c *SharedSocketConn) SetReadDeadline(t time.Time) error {
    // c.deadlineMu.Lock()
    c.readDeadline = t
    // c.deadlineMu.Unlock()
    return nil
}

func (c *SharedSocketConn) SetWriteDeadline(t time.Time) error {
	// c.deadlineMu.Lock()
    c.writeDeadline = t
    // c.deadlineMu.Unlock()
    return nil
}

func isUDPNetwork(network string) bool {
	for _, i := range udpNetworkList {
		if network == i {
			return true
		}
	}
	return false
}

func isIPNetwork(network string) bool {
	for _, i := range ipNetworkList {
		if len(network) < len(i) {
			continue
		}
		if network[:len(i)] == i && (len(network) == len(i) || network[len(i)] == ':') {
			return true
		}
	}
	return false
}

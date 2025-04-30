package zgrab2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"time"

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
		minDeadline = int64(ctxDeadline.Sub(time.Now()))
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
	if err := c.checkContext(); err != nil {
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
	if err := c.checkContext(); err != nil {
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
		err := c.Conn.SetReadDeadline(deadline)
		if err != nil {
			return err
		}
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
		err := c.Conn.SetWriteDeadline(deadline)
		if err != nil {
			return err
		}
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
func NewTimeoutConnection(ctx context.Context, conn net.Conn, timeout, readTimeout, writeTimeout time.Duration, bytesReadLimit int) *TimeoutConnection {
	ret := &TimeoutConnection{
		ctx:            ctx,
		Conn:           conn,
		SessionTimeout: timeout,
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		BytesReadLimit: bytesReadLimit,
	}
	ret.ctx, ret.Cancel = context.WithTimeout(ctx, timeout)
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
}

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
	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dial context failed: %v", err)
	}
	ret := NewTimeoutConnection(ctx, conn, d.SessionTimeout, d.ReadTimeout, d.WriteTimeout, d.BytesReadLimit)
	ret.BytesReadLimit = d.BytesReadLimit
	ret.ReadLimitExceededAction = d.ReadLimitExceededAction
	return ret, nil
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

// SetDefaults for the Dialer.
func (d *Dialer) SetDefaults() *Dialer {
	if d.ReadLimitExceededAction == ReadLimitExceededActionNotSet {
		d.ReadLimitExceededAction = DefaultReadLimitExceededAction
	}
	if d.BytesReadLimit == 0 {
		d.BytesReadLimit = DefaultBytesReadLimit
	}
	if d.Dialer == nil {
		d.Dialer = &net.Dialer{}
		// Use custom DNS as default if set
		if config.CustomDNS != "" {
			d.Dialer.Resolver = &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					return net.Dial(network, config.CustomDNS)
				},
			}
		}
	}
	return d
}

// NewDialer creates a new Dialer with default settings.
func NewDialer(value *Dialer) *Dialer {
	if value == nil {
		value = &Dialer{}
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

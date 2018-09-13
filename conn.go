package zgrab2

import (
	"context"
	"net"
	"time"
)

// TimeoutConnection wraps an existing net.Conn connection, overriding the Read/Write methods to use the configured timeouts
type TimeoutConnection struct {
	net.Conn
	ctx                   context.Context
	Timeout               time.Duration
	ReadTimeout           time.Duration
	WriteTimeout          time.Duration
	explicitReadDeadline  bool
	explicitWriteDeadline bool
	explicitDeadline      bool
}

// TimeoutConnection.Read calls Read() on the underlying connection, using any configured deadlines
func (c *TimeoutConnection) Read(b []byte) (n int, err error) {
	if err := c.checkContext(); err != nil {
		return 0, err
	}
	if c.explicitReadDeadline || c.explicitDeadline {
		c.explicitReadDeadline = false
		c.explicitDeadline = false
	} else if readTimeout := c.getTimeout(c.ReadTimeout); readTimeout > 0 {
		if err = c.Conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

// TimeoutConnection.Write calls Write() on the underlying connection, using any configured deadlines.
func (c *TimeoutConnection) Write(b []byte) (n int, err error) {
	if err := c.checkContext(); err != nil {
		return 0, err
	}
	if c.explicitWriteDeadline || c.explicitDeadline {
		c.explicitWriteDeadline = false
		c.explicitDeadline = false
	} else if writeTimeout := c.getTimeout(c.WriteTimeout); writeTimeout > 0 {
		if err = c.Conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(b)
}

// SetReadDeadline sets an explicit ReadDeadline that will override the timeout
// for one read. Use deadline = 0 to clear the deadline.
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
	c.explicitReadDeadline = !deadline.IsZero()
	return nil
}

// SetWriteDeadline sets an explicit WriteDeadline that will override the
// WriteDeadline for one write. Use deadline = 0 to clear the deadline.
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
	c.explicitWriteDeadline = deadline.IsZero()
	return nil
}

// SetDeadline sets a read / write deadline that will override the deadline for
// a single read/write. Use deadline = 0 to clear the deadline.
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
	c.explicitDeadline = deadline.IsZero()
	return nil
}

// GetTimeoutDialer returns a Dialer function that dials with the given timeout
func GetTimeoutDialer(timeout time.Duration) func(string, string) (net.Conn, error) {
	return func(proto, target string) (net.Conn, error) {
		return DialTimeoutConnection(proto, target, timeout)
	}
}

// Close the underlying connection.
func (c *TimeoutConnection) Close() error {
	return c.Conn.Close()
}

// Get the timeout for the given field, falling back to the global timeout.
func (c *TimeoutConnection) getTimeout(field time.Duration) time.Duration {
	if field == 0 {
		return c.Timeout
	}
	return field
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

// DialTimeoutConnection dials the target and returns a net.Conn that uses the configured timeouts for Read/Write operations.
func DialTimeoutConnection(proto string, target string, timeout time.Duration) (net.Conn, error) {
	var conn net.Conn
	var err error
	if timeout > 0 {
		conn, err = net.DialTimeout(proto, target, timeout)
	} else {
		conn, err = net.Dial(proto, target)
	}
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, err
	}
	ctx, _ := context.WithTimeout(context.Background(), timeout)
	return &TimeoutConnection{
		Conn:         conn,
		Timeout:      timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		ctx:          ctx,
	}, nil
}

// Dialer provides Dial and DialContext methods to get connections with the given timeout.
type Dialer struct {
	// Timeout is the maximum time to wait for the entire session, after which any operations on the
	// connection will fail.
	Timeout time.Duration

	// ConnectTimeout is the maximum time to wait for a connection.
	ConnectTimeout time.Duration

	// ReadTimeout is the maximum time to wait for a Read
	ReadTimeout time.Duration

	// WriteTimeout is the maximum time to wait for a Write
	WriteTimeout time.Duration

	// Dialer is an auxiliary dialer used for DialContext (the result gets wrapped in a TimeoutConnection).
	Dialer *net.Dialer
}

func (d *Dialer) getTimeout(field time.Duration) time.Duration {
	if field == 0 {
		return d.Timeout
	}
	return field
}

// DialContext wraps the connection returned by net.Dialer.DialContext() with a TimeoutConnection.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.Timeout != 0 {
		ctx, _ = context.WithTimeout(ctx, d.Timeout)
	}
	// ensure that our aux dialer is up-to-date; copied from http/transport.go
	d.Dialer.Timeout = d.getTimeout(d.ConnectTimeout)
	d.Dialer.KeepAlive = d.Timeout
	dialContext, cancelDial := context.WithTimeout(ctx, d.Dialer.Timeout)
	defer cancelDial()
	ret, err := d.Dialer.DialContext(dialContext, network, address)
	if err != nil {
		return nil, err
	}
	return &TimeoutConnection{
		ctx:          ctx,
		Conn:         ret,
		ReadTimeout:  d.ReadTimeout,
		WriteTimeout: d.WriteTimeout,
		Timeout:      d.Timeout,
	}, nil
}

// Dial returns a connection with the configured timeout.
func (d *Dialer) Dial(proto string, target string) (net.Conn, error) {
	return DialTimeoutConnection(proto, target, d.Timeout)
}

// GetTimeoutConnectionDialer gets a Dialer that dials connections with the given timeout.
func GetTimeoutConnectionDialer(timeout time.Duration) *Dialer {
	return &Dialer{
		Timeout: timeout,
		Dialer: &net.Dialer{
			Timeout:   timeout,
			KeepAlive: timeout,
			DualStack: true,
		},
	}
}

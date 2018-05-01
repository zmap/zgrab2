package zgrab2

import (
	"net"
	"time"
	"context"
)

// TimeoutConnection wraps an existing net.Conn connection, overriding the Read/Write methods to use the configured timeouts
type TimeoutConnection struct {
	net.Conn
	Timeout time.Duration
}

// TimeoutConnection.Read calls Read() on the underlying connection, using any configured deadlines
func (c *TimeoutConnection) Read(b []byte) (n int, err error) {
	if c.Timeout > 0 {
		if err = c.Conn.SetReadDeadline(time.Now().Add(c.Timeout)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

// TimeoutConnection.Write calls Write() on the underlying connection, using any configured deadlines
func (c *TimeoutConnection) Write(b []byte) (n int, err error) {
	if c.Timeout > 0 {
		if err = c.Conn.SetWriteDeadline(time.Now().Add(c.Timeout)); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(b)
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
	return &TimeoutConnection{
		Conn:    conn,
		Timeout: timeout,
	}, nil
}

// Dialer provides Dial and DialContext methods to get connections with the given timeout.
type Dialer struct {
	// Timeout is the maximum time to wait for a connection or I/O.
	Timeout time.Duration

	// dialer is an auxiliary dialer used for DialContext (the result gets wrapped in a TimeoutConnection).
	Dialer *net.Dialer
}

// DialContext wraps the connection returned by net.Dialer.DialContext() with a TimeoutConnection.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// ensure that our aux dialer is up-to-date
	d.Dialer.Timeout = d.Timeout
	d.Dialer.KeepAlive = d.Timeout
	ret, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &TimeoutConnection{
		Conn:    ret,
		Timeout: d.Timeout,
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
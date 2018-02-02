package zgrab2

import (
	"net"
	"time"
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

// GetTimeoutDialer returns a Dialer function that dials with the given timeout
func GetTimeoutDialer(timeout time.Duration) func(string, string) (net.Conn, error) {
	return func(proto, target string) (net.Conn, error) {
		return DialTimeoutConnection(proto, target, timeout)
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
	return &TimeoutConnection{
		Conn:    conn,
		Timeout: timeout,
	}, nil
}

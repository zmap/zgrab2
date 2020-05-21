package smtp

import (
	"net"
	"regexp"
	"fmt"
	"io"

	"github.com/zmap/zgrab2"
)

// This is the regex used in zgrab.
// Corner cases like "200 OK\r\nthis is not valid at all\x00\x01\x02\x03\r\n" will be matched.
var smtpEndRegex = regexp.MustCompile(`(?:^\d\d\d\s.*\r\n$)|(?:^\d\d\d-[\s\S]*\r\n\d\d\d\s.*\r\n$)`)

const readBufferSize int = 0x10000

// Connection wraps the state and access to the SMTP connection.
type Connection struct {
	Conn net.Conn
}

// Verify that an SMTP code was returned, and that it is a successful one!
func VerifySMTPContents(n int, ret []byte) (string, error){
	s := string(ret[:n])
	code, err := getSMTPCode(s)
	if err != nil {
		return s, err
	}
	if code < 200 || code >= 300 {
		return s, zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, fmt.Errorf("SMTP returned error code %d", code))
	}
	return s, nil
}

// ReadResponse reads from the connection until it matches the smtpEndRegex. Copied from the original zgrab.
// TODO: Catch corner cases
func (conn *Connection) ReadResponse() (string, error) {
	ret := make([]byte, readBufferSize)
	n, err := zgrab2.ReadUntilRegex(conn.Conn, ret, smtpEndRegex)
	if err != nil && err != io.EOF && !zgrab2.IsTimeoutError(err) {
		return "", err
	}
	return VerifySMTPContents(n, ret)
}

// SendCommand sends a command, followed by a CRLF, then wait for / read the server's response.
func (conn *Connection) SendCommand(cmd string) (string, error) {
	if _, err := conn.Conn.Write([]byte(cmd + "\r\n")); err != nil {
		return "", err
	}
	return conn.ReadResponse()
}

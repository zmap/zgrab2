package imap

import (
	"net"
	"regexp"
	"io"

	"github.com/zmap/zgrab2"
)

// This is the regex used in zgrab.
var imapStatusEndRegex = regexp.MustCompile(`\r\n$`)

const readBufferSize int = 0x10000

// Connection wraps the state and access to the SMTP connection.
type Connection struct {
	Conn net.Conn
}

// ReadResponse reads from the connection until it matches the imapEndRegex. Copied from the original zgrab.
// TODO: Catch corner cases
func (conn *Connection) ReadResponse() (string, error) {
	ret := make([]byte, readBufferSize)
	n, err := zgrab2.ReadUntilRegex(conn.Conn, ret, imapStatusEndRegex)
	if err != nil && err != io.EOF && !zgrab2.IsTimeoutError(err) {
		return "", err
	}
	return string(ret[:n]), nil
}

// SendCommand sends a command, followed by a CRLF, then wait for / read the server's response.
func (conn *Connection) SendCommand(cmd string) (string, error) {
	if _, err := conn.Conn.Write([]byte(cmd + "\r\n")); err != nil {
		return "", err
	}
	return conn.ReadResponse()
}

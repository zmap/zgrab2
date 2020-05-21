package imap

import (
	"net"
	"regexp"
	"strings"
	"errors"
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

// Verify banner begins with a valid IMAP response and handle it
func VerifyIMAPContents(n int, ret []byte) (string, error) {
	s := string(ret[:n])
	if strings.HasPrefix(s, "* OK"){
		return s, nil
	}
	if strings.HasPrefix(s, "* NO"){
		return s, zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR, errors.New("IMAP reported error"))
	}
	if strings.HasPrefix(s, "* BAD"){
		return s, zgrab2.NewScanError(zgrab2.SCAN_UNKNOWN_ERROR, errors.New("IMAP request was malformed"))
	}
	return s, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, errors.New("Invalid response for IMAP"))
}

// ReadResponse reads from the connection until it matches the imapEndRegex. Copied from the original zgrab.
// TODO: Catch corner cases
func (conn *Connection) ReadResponse() (string, error) {
	ret := make([]byte, readBufferSize)
	n, err := zgrab2.ReadUntilRegex(conn.Conn, ret, imapStatusEndRegex)
	if err != nil && err != io.EOF && !zgrab2.IsTimeoutError(err) {
		return "", err
	}
	return VerifyIMAPContents(n, ret)
}

// SendCommand sends a command, followed by a CRLF, then wait for / read the server's response.
func (conn *Connection) SendCommand(cmd string) (string, error) {
	if _, err := conn.Conn.Write([]byte(cmd + "\r\n")); err != nil {
		return "", err
	}
	return conn.ReadResponse()
}

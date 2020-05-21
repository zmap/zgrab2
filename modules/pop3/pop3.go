// Scanner for POP3 protocol
// https://www.ietf.org/rfc/rfc1939.txt

package pop3

import (
	"net"
	"regexp"
	"errors"
	"strings"
	"io"

	"github.com/zmap/zgrab2"
)

// This is the regex used in zgrab.
var pop3EndRegex = regexp.MustCompile(`(?:\r\n\.\r\n$)|(?:\r\n$)`)

const readBufferSize int = 0x10000

// Connection wraps the state and access to the SMTP connection.
type Connection struct {
	Conn net.Conn
}

// Verifies that a POP3 banner begins with a valid status indicator
func VerifyPOP3Contents(n int, ret []byte) (string, error) {
	s := string(ret[0:n])
	iword := strings.Index(s, " ")
	if iword > 2 {
		subst := s[:iword]
		if subst == "+OK" {
			return s, nil
		}
		if subst == "+ERR" {
			return s, zgrab2.NewScanError(zgrab2.SCAN_APPLICATION_ERROR,
																		errors.New("POP3 Reported Error"))
		}
	}
	return s, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR,
																errors.New("Invalid response for POP3"))
}

// ReadResponse reads from the connection until it matches the pop3EndRegex. Copied from the original zgrab.
// TODO: Catch corner cases
func (conn *Connection) ReadResponse() (string, error) {
	ret := make([]byte, readBufferSize)
	n, err := zgrab2.ReadUntilRegex(conn.Conn, ret, pop3EndRegex)
	// Don't quit for timeouts since we might have gotten relevant data still
	if err != nil && err != io.EOF && !zgrab2.IsTimeoutError(err) {
		return "", err
	}
	return VerifyPOP3Contents(n, ret)
}

// SendCommand sends a command, followed by a CRLF, then wait for / read the server's response.
func (conn *Connection) SendCommand(cmd string) (string, error) {
	if _, err := conn.Conn.Write([]byte(cmd + "\r\n")); err != nil {
		return "", err
	}
	return conn.ReadResponse()
}

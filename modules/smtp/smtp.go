package smtp

import (
	"net"
	"regexp"
	"../.."
)

// This is the regex used in zgrab.
// Corner cases like "200 OK\r\nthis is not valid at all\x00\x01\x02\x03\r\n" will be matched.
var smtpEndRegex = regexp.MustCompile(`(?:^\d\d\d\s.*\r\n$)|(?:^\d\d\d-[\s\S]*\r\n\d\d\d\s.*\r\n$)`)

const readBufferSize int = 0x10000

type Connection struct {
	Conn net.Conn
}

func (conn *Connection) readResponse() (string, error) {
	ret := make([]byte, readBufferSize)
	n, err := zgrab2.ReadUntilRegex(conn.Conn, ret, smtpEndRegex)
	if err != nil {
		return "", nil
	}
	return string(ret[0:n]), nil
}

func (conn *Connection) SendCommand(cmd string) (string, error) {
	if _, err := conn.Conn.Write([]byte(cmd + "\r\n")); err != nil {
		return "",  err
	}
	return conn.readResponse()
}
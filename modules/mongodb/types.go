package mongodb

import (
	"encoding/binary"
	"fmt"
	"github.com/zmap/zgrab2"
	"io"
)

const (
	OP_REPLY        = 1
	OP_UPDATE       = 2001
	OP_INSERT       = 2002
	RESERVED        = 2003
	OP_QUERY        = 2004
	OP_GET_MORE     = 2005
	OP_DELETE       = 2006
	OP_KILL_CURSORS = 2007
	OP_COMMAND      = 2010
	OP_COMMANDREPLY = 2011
	OP_MSG          = 2013

	QUERY_RESERVED    = 1
	QUERY_TAILABLEC   = 2
	QUERY_SLAVEOK     = 4
	QUERY_OPLOGREPLAY = 8
	QUERY_NOCTIMEOUT  = 16
	QUERY_AWAITDATA   = 32
	QUERY_EXHAUST     = 64
	QUERY_PARTIAL     = 128

	QUERY_RESP_CUR_NOTFOUND = 1
	QUERY_RESP_FAILED       = 2
	QUERY_RESP_SHARD_STALE  = 4
	QUERY_RESP_AWAIT_CAP    = 8

	MSGHEADER_LEN = 16
)

// Connection holds the state for a single connection within a scan.
type Connection struct {
	scanner *Scanner
	conn    interface {
		io.Reader
		io.Writer
	}
}

// ReadMsg reads a full MongoDB message from the connection.
func (conn *Connection) ReadMsg() ([]byte, error) {
	var msglen_buf [4]byte
	_, err := io.ReadFull(conn.conn, msglen_buf[:])
	if err != nil {
		return nil, err
	}
	msglen := binary.LittleEndian.Uint32(msglen_buf[:])
	if msglen < 4 || msglen > 5125 {
		// msglen is length of message which includes msglen itself; Less than
		// four is invalid. More than a few K probably mean this isn't actually
		// a mongodb server.
		return nil, fmt.Errorf("Server sent invalid message: msglen = %d", msglen)
	}
	msg_buf := make([]byte, msglen)
	// Extra copy to make result look like spec (only four bytes)
	binary.LittleEndian.PutUint32(msg_buf[0:], msglen)
	_, err = io.ReadFull(conn.conn, msg_buf[4:])
	if err != nil {
		return nil, err
	}
	return msg_buf, nil
}

// Write writes a full message to the connection.
func (conn *Connection) Write(data []byte) error {
	n, err := conn.conn.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return &zgrab2.ScanError{Status: zgrab2.SCAN_CONNECTION_CLOSED, Err: io.ErrShortWrite}
	}
	return nil
}

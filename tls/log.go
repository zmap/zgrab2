package tls

import (
	"github.com/zmap/zcrypto/tls"
)

type Connection struct {
	tls.Conn
	Flags *Flags
	Log   *Log
}

type Log struct {
	// TODO include TLSFlags?
	HandshakeLog *tls.ServerHandshake `json:"handshake_log"`
}

func (z *Connection) GetLog() *Log {
	if z.Log == nil {
		z.Log = &Log{}
	}

	return z.Log
}

func (z *Connection) Handshake() error {
	log := z.GetLog()
	defer func() {
		log.HandshakeLog = z.Conn.GetHandshakeLog()
	}()
	return z.Conn.Handshake()

}

// Close the underlying connection.
func (conn *Connection) Close() error {
	return conn.Conn.Close()
}

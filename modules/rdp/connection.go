package rdp

import (
	"bytes"
	"net"

	"github.com/pkg/errors"

	"github.com/zmap/zgrab2"
)

var (
	initMsg           = []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}
	additionalInitMsg = []byte{0x03, 0x00, 0x00, 0x2a, 0x25, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x3a, 0x20, 0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68, 0x3d, 0x6e, 0x6d, 0x61, 0x70, 0x0d, 0x0a, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}

	rdpIndicator = []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34}
)

type connection struct {
	regularConn net.Conn
	tlsConn     *zgrab2.TLSConnection
}

func (c *connection) initAndGetBanner() ([]byte, error) {
	if err := c.send(initMsg, false); err != nil {
		return nil, errors.Wrap(err, "error sendInitMsg")
	}

	res, err := zgrab2.ReadAvailable(c.regularConn)
	if err != nil || len(res) == 0 {
		if err := c.send(additionalInitMsg, false); err != nil {
			return nil, errors.Wrap(err, "error sendInitMsg")
		}

		res, err = zgrab2.ReadAvailable(c.regularConn)
		if err != nil {
			return nil, errors.Wrap(err, "error zgrab2.ReadAvailable second try")
		}
	}

	return res, nil
}

func (c *connection) setTLSConnectionAndGetTLSLog(tlsConnection *zgrab2.TLSConnection) (*zgrab2.TLSLog, error) {
	if err := tlsConnection.Handshake(); err != nil {
		return nil, errors.Wrap(err, "error tlsConnection.Handshake")
	}

	c.tlsConn = tlsConnection
	return tlsConnection.GetLog(), nil
}

func (c *connection) getNTLMInfo() (NTLMInfo, error) {
	if err := c.send(getNTLMInfoRequest(), true); err != nil {
		return NTLMInfo{}, errors.Wrap(err, "error send")
	}

	res, err := zgrab2.ReadAvailable(c.tlsConn)
	if err != nil {
		return NTLMInfo{}, errors.Wrap(err, "error ReadAvailable")
	}

	return newNTLMInfo(res), nil
}

func (c *connection) send(msg []byte, withTLS bool) error {
	conn := c.regularConn
	if withTLS {
		conn = c.tlsConn
	}

	if _, err := conn.Write(msg); err != nil {
		return err
	}

	return nil
}

func getNTLMInfoRequest() []byte {
	return bytes.Join([][]byte{
		{0x30, 0x37, 0xA0, 0x03, 0x02, 0x01, 0x60, 0xA1, 0x30, 0x30, 0x2E, 0x30, 0x2C, 0xA0, 0x2A, 0x04, 0x28},
		[]byte("NTLMSSP"),
		{0x00, 0x01, 0x00, 0x00, 0x00, 0xF7, 0xBA, 0xDB, 0xE2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}, []byte{})
}

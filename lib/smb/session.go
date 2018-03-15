/*
* MIT License
*
* Copyright (c) 2017 stacktitan
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
 */

package smb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"

	"github.com/zmap/zgrab2/lib/smb/encoder"
)

type Session struct {
	IsSigningRequired bool
	IsAuthenticated   bool
	debug             bool
	securityMode      uint16
	messageID         uint64
	sessionID         uint64
	conn              net.Conn
	dialect           uint16
	options           Options
	trees             map[string]uint32
}

type Options struct {
	Host        string
	Port        int
	Workstation string
	Domain      string
	User        string
	Password    string
	Hash        string
}

func GetSMBBanner(logStruct *SMBLog, conn net.Conn) (err error) {
	opt := Options{}

	s := &Session{
		IsSigningRequired: false,
		IsAuthenticated:   false,
		debug:             false,
		securityMode:      0,
		messageID:         0,
		sessionID:         0,
		dialect:           0,
		conn:              conn,
		options:           opt,
		trees:             make(map[string]uint32),
	}

	err = s.NegotiateProtocol(logStruct)
	return err

}

func (s *Session) NegotiateProtocol(logStruct *SMBLog) error {
	negReq := s.NewNegotiateReq()
	buf, err := s.send(negReq, logStruct)
	if err != nil {
		return err
	}

	negRes := NewNegotiateRes()
	if err := encoder.Unmarshal(buf, &negRes); err != nil {
		s.Debug("Raw:\n"+hex.Dump(buf), err)
	}

	if negRes.Header.Status != StatusOk {
		return nil
	}

	s.conn.Close()
	return nil
}

func (s *Session) send(req interface{}, logStruct *SMBLog) (res []byte, err error) {
	buf, err := encoder.Marshal(req)
	if err != nil {
		s.Debug("", err)
		return nil, err
	}

	b := new(bytes.Buffer)
	if err = binary.Write(b, binary.BigEndian, uint32(len(buf))); err != nil {
		s.Debug("", err)
		return
	}

	rw := bufio.NewReadWriter(bufio.NewReader(s.conn), bufio.NewWriter(s.conn))
	if _, err = rw.Write(append(b.Bytes(), buf...)); err != nil {
		s.Debug("", err)
		return
	}
	rw.Flush()

	var size uint32
	if err = binary.Read(rw, binary.BigEndian, &size); err != nil {
		s.Debug("", err)
		return
	}
	if size > 0x00FFFFFF {
		return nil, errors.New("invalid NetBIOS Session message")
	}

	data := make([]byte, size)
	l, err := io.ReadFull(rw, data)
	if err != nil {
		s.Debug("", err)
		return nil, err
	}

	if uint32(l) != size || len(data) < 4 {
		return nil, errors.New("message size invalid")
	}

	//First four bytes contain protocol ID
	protID := data[0:4]
	switch string(protID) {
	default:
		return nil, errors.New("protocol not implemented")
	case ProtocolSmb:
		logStruct.SupportV1 = true
	}

	s.messageID++
	return data, nil
}

func (s *Session) Debug(msg string, err error) {
	if s.debug {
		log.Println("[ DEBUG ] ", msg)
	}
}

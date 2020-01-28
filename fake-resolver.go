// Fake DNS lookups
// Inspired by the golang dnsclient_unix_test.go code
//
package zgrab2

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"time"
)

func NewFakeResolver(ipstr string) (*net.Resolver, error) {
	ip := net.ParseIP(ipstr)
	if len(ip) < 4 {
		return nil, fmt.Errorf("Fake resolver can't use non-IP '%s'", ipstr)
	}
	var d net.Dialer
	fDNS := FakeDNSServer{
		IP:         ip,
		realDialer: d.DialContext,
	}
	fDNS.names = make(map[string]bool)
	return &net.Resolver{
		PreferGo: true,
		Dial:     fDNS.DialContext,
	}, nil
}

type FakeDNSServer struct {
	IP         net.IP
	cnt        int
	names      map[string]bool
	latch      bool
	realDialer func(ctx context.Context, network, address string) (net.Conn, error)
}

func (f *FakeDNSServer) fakeDNS(_, s string, q dnsmessage.Message,
	deadline time.Time) (r dnsmessage.Message, err error) {

	if f.cnt > 0 && !f.names[q.Questions[0].Name.String()] {
		f.latch = true
	} else {
		f.cnt++
		f.names[q.Questions[0].Name.String()] = true
	}

	r = dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       q.ID,
			Response: true,
		},
		Questions: q.Questions,
	}
	ipv6 := f.IP.To16()
	ipv4 := f.IP.To4()
	switch t := q.Questions[0].Type; {
	case t == dnsmessage.TypeA && ipv4 != nil:
		var ip [4]byte
		copy(ip[:], []byte(ipv4))
		r.Answers = []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:   q.Questions[0].Name,
					Type:   dnsmessage.TypeA,
					Class:  dnsmessage.ClassINET,
					Length: 4,
				},
				Body: &dnsmessage.AResource{
					A: ip,
				},
			},
		}
	case t == dnsmessage.TypeAAAA && ipv4 == nil:
		var ip [16]byte
		copy(ip[:], []byte(ipv6))
		r.Answers = []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:   q.Questions[0].Name,
					Type:   dnsmessage.TypeAAAA,
					Class:  dnsmessage.ClassINET,
					Length: 16,
				},
				Body: &dnsmessage.AAAAResource{
					AAAA: ip,
				},
			},
		}
	default:
		r.Header.RCode = dnsmessage.RCodeNameError
	}

	return r, nil
}

func (f *FakeDNSServer) DialContext(ctx context.Context, n, s string) (net.Conn, error) {
	if f.latch {
		return f.realDialer(ctx, n, s)
	} else {
		return &fakeDNSPacketConn{fakeDNSConn: fakeDNSConn{server: f, n: n, s: s}}, nil
	}
}

type fakeDNSConn struct {
	net.Conn
	server *FakeDNSServer
	n      string
	s      string
	q      dnsmessage.Message
	t      time.Time
	buf    []byte
}

func (fc *fakeDNSConn) Read(b []byte) (int, error) {
	if len(fc.buf) > 0 {
		n := copy(b, fc.buf)
		fc.buf = fc.buf[n:]
		return n, nil
	}

	resp, err := fc.server.fakeDNS(fc.n, fc.s, fc.q, fc.t)
	if err != nil {
		return 0, err
	}

	bb := make([]byte, 2, 514)
	bb, err = resp.AppendPack(bb)
	if err != nil {
		return 0, fmt.Errorf("cannot marshal DNS message: %v", err)
	}

	bb = bb[2:]
	if len(b) < len(bb) {
		return 0, errors.New("read would fragment DNS message")
	}

	copy(b, bb)
	return len(bb), nil
}

func (fc *fakeDNSConn) Write(b []byte) (int, error) {
	if fc.q.Unpack(b) != nil {
		return 0, fmt.Errorf("cannot unmarshal DNS message fake %s (%d)", fc.n, len(b))
	}
	return len(b), nil
}

func (fc *fakeDNSConn) SetDeadline(t time.Time) error {
	fc.t = t
	return nil
}

func (fc *fakeDNSConn) Close() error {
	return nil
}

type fakeDNSPacketConn struct {
	net.PacketConn
	fakeDNSConn
}

func (f *fakeDNSPacketConn) SetDeadline(t time.Time) error {
	return f.fakeDNSConn.SetDeadline(t)
}

func (f *fakeDNSPacketConn) Close() error {
	return f.fakeDNSConn.Close()
}

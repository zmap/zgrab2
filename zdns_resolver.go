package zgrab2

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zdns/v2/src/zdns"
	"golang.org/x/net/dns/dnsmessage"
	// You may need to import the package that provides constants for DNS types/classes.
)

type zdnsResolverPool struct {
	sync.RWMutex
	pool      chan *zdns.Resolver
	resolvers []*zdns.Resolver // to keep track of resolvers so we can ensure we close them when done
	hasClosed bool
}

var pool *zdnsResolverPool

func newZDNSResolverPool(size int, zdnsResolverConfig *zdns.ResolverConfig) (*zdnsResolverPool, error) {
	if zdnsResolverConfig == nil {
		return nil, fmt.Errorf("ZDNS resolver config must be provided")
	}

	pool = &zdnsResolverPool{
		RWMutex:   sync.RWMutex{},
		pool:      make(chan *zdns.Resolver, size),
		resolvers: make([]*zdns.Resolver, 0, size),
		hasClosed: false,
	}

	for i := 0; i < size; i++ {
		resolver, err := zdns.InitResolver(zdnsResolverConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize ZDNS resolver: %v", err)
		}
		pool.pool <- resolver
		pool.resolvers = append(pool.resolvers, resolver)
	}

	return pool, nil
}

func (p *zdnsResolverPool) checkOut() *zdns.Resolver {
	p.RLock()
	defer p.RUnlock()
	res, ok := <-p.pool
	if !ok {
		log.Warn("resolver pool is closed")
		return nil
	}
	return res
}

func (p *zdnsResolverPool) checkIn(resolver *zdns.Resolver) {
	p.RLock()
	defer p.RUnlock()
	if p.hasClosed {
		resolver.Close()
	} else {
		// return to pool
		p.pool <- resolver
	}
}

func (p *zdnsResolverPool) close() {
	p.Lock()
	defer p.Unlock()
	close(p.pool)
	// Close all resolvers in the pool
	for _, resolver := range p.resolvers {
		resolver := resolver
		go func() {
			if resolver != nil {
				resolver.Close()
			}
		}()
	}
	p.hasClosed = true
}

// FakeDNSServer now uses an external ZDNS resolver for lookups.
type zdnsServer struct{}

// NewFakeResolverWithZDNS creates a new net.Resolver that uses the FakeDNSServer
// which in turn uses the ZDNS lookup for actual DNS resolution.
// TODO Phillip this has a bit of overhead in that it creates a new resolver for each lookup. But handling this properly will require some thread-saftey work to do correctly. Let's see what performance we get with this.
func NewFakeResolverWithZDNS() *net.Resolver {
	fDNS := zdnsServer{}
	return &net.Resolver{
		PreferGo: true, // Forces use of Go's internal resolver (and our custom Dial)
		Dial:     fDNS.DialContext,
	}
}

// fakeDNS performs the external lookup using ZDNS. It extracts the question,
// issues a lookup via the ZDNS resolver, and then constructs a DNS message
// with the returned answers.
func (f *zdnsServer) fakeDNS(address string, dmsg dnsmessage.Message) (dnsmessage.Message, error) {
	// Start constructing the response.
	r := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       dmsg.ID,
			Response: true,
		},
		Questions: dmsg.Questions,
	}

	// We only support a single question.
	if len(dmsg.Questions) == 0 {
		r.Header.RCode = dnsmessage.RCodeFormatError
		return r, errors.New("no DNS question found")
	}

	qname := dmsg.Questions[0].Name.String()
	if len(qname) > 0 && qname[len(qname)-1] == '.' {
		qname = qname[:len(qname)-1]
	}

	dnsQuestion := &zdns.Question{
		Name:  qname,
		Type:  uint16(dmsg.Questions[0].Type),
		Class: uint16(dns.ClassINET), // usually IN (Internet)
	}

	// Perform the external lookup. Adjust context/timeout as needed.
	//f.Lock() // TODO Phillip this is a hack to avoid concurrent access to the resolver. It appears that per net.Resolver.goLookupIPCNAMEOrder,
	// the net.Dialer is multi-threaded. Therefore we should likely have a pool of zdns.Resolver objects that can be checked in and out here.
	resolver := pool.checkOut()
	if resolver == nil {
		log.Warn("No available ZDNS resolver in pool")
		r.Header.RCode = dnsmessage.RCodeServerFailure
		return r, errors.New("no available ZDNS resolver in pool")
	}
	result, _, status, err := resolver.IterativeLookup(context.Background(), dnsQuestion)
	if err != nil {
		log.Printf("Error during external lookup for %s: %v", qname, err)
		r.Header.RCode = dnsmessage.RCodeServerFailure
		return r, err
	}
	pool.checkIn(resolver)
	if status != "NOERROR" {
		r.Header.RCode = dnsmessage.RCodeNameError
		return r, nil
	}

	// Check that there is a result
	if result == nil || len(result.Answers) == 0 {
		r.Header.RCode = dnsmessage.RCodeNameError
		return r, nil
	}

	// Iterate over each answer and convert it to a dnsmessage.Resource.
	for _, ans := range result.Answers {
		castAnswer, ok := ans.(zdns.Answer)
		if !ok {
			log.Warnf("Answer is not of type zdns.Answer: %T", ans)
			continue
		}
		ip := net.ParseIP(castAnswer.Answer)
		if ip == nil {
			//log.Warnf("Answer's IP is not valid: %s", castAnswer.Answer)
			continue
		}
		if castAnswer.Type == "A" {
			if ipv4 := ip.To4(); ipv4 != nil {
				var ipArr [4]byte
				copy(ipArr[:], ipv4)
				r.Answers = append(r.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:   dmsg.Questions[0].Name,
						Type:   dnsmessage.TypeA,
						Class:  dnsmessage.ClassINET,
						Length: 4,
					},
					Body: &dnsmessage.AResource{A: ipArr},
				})
			}
		} else if castAnswer.Type == "AAAA" {
			if ipv6 := ip.To16(); ipv6 != nil && ip.To4() == nil {
				var ipArr [16]byte
				copy(ipArr[:], ipv6)
				r.Answers = append(r.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:   dmsg.Questions[0].Name,
						Type:   dnsmessage.TypeAAAA,
						Class:  dnsmessage.ClassINET,
						Length: 16,
					},
					Body: &dnsmessage.AAAAResource{AAAA: ipArr},
				})
			}
		} else {
			log.Warnf("Unsupported answer type: %s", castAnswer.Type)
			continue
		}
	}

	// If no answers were added, signal a name error.
	if len(r.Answers) == 0 {
		r.Header.RCode = dnsmessage.RCodeNameError
	}

	return r, nil
}

// DialContext is used by net.Resolver. It returns a fake DNS connection
// that only supports DNS message exchange.
func (f *zdnsServer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn := &zdnsPacketConn{
		zdnsConn: zdnsConn{
			server:  f,
			network: network,
			address: address,
		},
	}
	return conn, nil
}

// fakeDNSConn implements net.Conn and holds the DNS message.
type zdnsConn struct {
	net.Conn
	server  *zdnsServer
	network string
	address string
	dmsg    dnsmessage.Message
}

// Read marshals the DNS response (from our external lookup) into the provided byte slice.
func (fc *zdnsConn) Read(b []byte) (int, error) {
	resp, err := fc.server.fakeDNS(fc.address, fc.dmsg)
	if err != nil {
		return 0, err
	}

	// Pack the DNS message. The first two bytes are the length.
	bb := make([]byte, 2, 514)
	bb, err = resp.AppendPack(bb)
	if err != nil {
		return 0, fmt.Errorf("cannot marshal DNS message: %v", err)
	}

	// Skip the length header for the UDP-like read.
	bb = bb[2:]
	if len(b) < len(bb) {
		return 0, errors.New("read would fragment DNS message")
	}

	copy(b, bb)
	return len(bb), nil
}

// Write unmarshals the DNS query into our fake connection.
func (fc *zdnsConn) Write(b []byte) (int, error) {
	if err := fc.dmsg.Unpack(b); err != nil {
		return 0, fmt.Errorf("cannot unmarshal DNS message on %s (%d bytes): %v", fc.network, len(b), err)
	}
	return len(b), nil
}

func (fc *zdnsConn) SetDeadline(deadline time.Time) error {
	return nil
}

func (fc *zdnsConn) Close() error {
	return nil
}

// fakeDNSPacketConn wraps fakeDNSConn to satisfy net.PacketConn.
type zdnsPacketConn struct {
	net.PacketConn
	zdnsConn
}

func (f *zdnsPacketConn) SetDeadline(deadline time.Time) error {
	return nil
}

func (f *zdnsPacketConn) Close() error {
	return f.zdnsConn.Close()
}

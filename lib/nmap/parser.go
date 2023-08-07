package nmap

import (
	"bufio"
	"bytes"
	"fmt"
	"io"

	"github.com/zmap/zgrab2/lib/nmap/template"
)

func ParseServiceProbes(in io.Reader) ([]ServiceProbe, error) {
	var p parser
	err := p.parse(in)
	return p.probes, err
}

type parsingError struct{ err error }

func (e *parsingError) check(ok bool, err error) bool {
	if err != nil && e.err == nil {
		e.err = err
	}
	return e.err == nil && ok
}

type parser struct {
	probes []ServiceProbe
}

type b []byte

func (p *parser) addProbe(probe ServiceProbe) {
	p.probes = append(p.probes, probe)
}

func (p *parser) addMatch(match Match) {
	if len(p.probes) > 0 {
		probe := &p.probes[len(p.probes)-1]
		probe.Matches = append(probe.Matches, match)
	}
}

func (p *parser) parse(in io.Reader) error {
	s := bufio.NewScanner(in)
	for lineNum := 1; s.Scan(); lineNum++ {
		if err := p.parseLine(s.Bytes()); err != nil {
			return fmt.Errorf("line=%v: %v", lineNum, err)
		}
	}
	return s.Err()
}

func (p *parser) parseLine(s []byte) error {
	var e parsingError
	switch {
	case len(s) == 0:
	case e.check(p.tryComment(s)):
	case e.check(p.tryProbe(s)):
	case e.check(p.tryMatch(s)):
	case e.check(p.trySoftmatch(s)):
	case e.check(p.tryExclude(s)):
	case e.check(p.tryFallback(s)):
	case e.check(p.tryPorts(s)):
	case e.check(p.trySSLPorts(s)):
	case e.check(p.tryRarity(s)):
	case e.check(p.tryTCPWrappedMs(s)):
	case e.check(p.tryTotalWaitMs(s)):
	case e.err == nil:
		return fmt.Errorf("unknown directive: %q", s)
	}
	return e.err
}

func (p *parser) tryComment(s []byte) (bool, error) {
	return bytes.HasPrefix(s, b("#")), nil
}

func (p *parser) tryProbe(s []byte) (bool, error) {
	var found bool
	if s, found = bytes.CutPrefix(s, b("Probe")); !found {
		return false, nil
	}
	s = skipSpace(s)

	var protocol Protocol
	if protocol, s = cutProtocol(s); protocol == UnknownProtocol {
		return false, fmt.Errorf("unsupported probe protocol")
	}
	s = skipSpace(s)

	var name []byte
	if name, s = cutUntilSpace(s); len(name) == 0 {
		return false, fmt.Errorf("probe name expected")
	}
	s = skipSpace(s)

	var probestring []byte
	if probestring, s, found = cutQuotedWithPrefix(s, b("q")); !found {
		return false, fmt.Errorf("probe string expected")
	}
	s = skipSpace(s)

	s, noPayload := bytes.CutPrefix(s, b("no-payload"))

	p.addProbe(ServiceProbe{
		Name:        string(name),
		Protocol:    protocol,
		ProbeString: string(probestring),
		NoPayload:   noPayload,
	})
	return true, nil
}

func (p *parser) tryMatch(s []byte) (bool, error) {
	if s, found := bytes.CutPrefix(s, b("match")); found {
		s = skipSpace(s)
		service, pattern, info, err := parseMatch(s)
		if err != nil {
			return true, err
		}
		p.addMatch(Match{
			Service:      string(service),
			MatchPattern: pattern,
			Info:         info,
		})
		return true, nil
	}
	return false, nil
}

func (p *parser) trySoftmatch(s []byte) (bool, error) {
	if s, found := bytes.CutPrefix(s, b("softmatch")); found {
		s = skipSpace(s)
		service, pattern, info, err := parseMatch(s)
		if err != nil {
			return true, err
		}
		p.addMatch(Match{
			Service:      string(service),
			MatchPattern: pattern,
			Info:         info,
			Soft:         true,
		})
		return true, nil
	}
	return false, nil
}

func parseMatch(s []byte) (service []byte, pattern MatchPattern, info Info[Template], err error) {
	if service, s = cutUntilSpace(s); len(service) == 0 {
		return service, pattern, info, fmt.Errorf("service name expected")
	}
	s = skipSpace(s)

	if pattern, s, err = cutMatchPattern(s); err != nil {
		return service, pattern, info, fmt.Errorf("match pattern expected: %v", err)
	}
	s = skipSpace(s)

	if info, err = parseInfo(s); err != nil {
		return service, pattern, info, fmt.Errorf("version info expected: %v", err)
	}
	return service, pattern, info, nil
}

func (p *parser) tryExclude(s []byte) (bool, error) {
	// Dummy implementation
	return bytes.HasPrefix(s, b("Exclude")), nil
}

func (p *parser) tryFallback(s []byte) (bool, error) {
	// Dummy implementation
	return bytes.HasPrefix(s, b("fallback")), nil
}

func (p *parser) tryPorts(s []byte) (bool, error) {
	// Dummy implementation
	return bytes.HasPrefix(s, b("ports")), nil
}

func (p *parser) trySSLPorts(s []byte) (bool, error) {
	// Dummy implementation
	return bytes.HasPrefix(s, b("sslports")), nil
}

func (p *parser) tryRarity(s []byte) (bool, error) {
	// Dummy implementation
	return bytes.HasPrefix(s, b("rarity")), nil
}

func (p *parser) tryTCPWrappedMs(s []byte) (bool, error) {
	// Dummy implementation
	return bytes.HasPrefix(s, b("tcpwrappedms")), nil
}

func (p *parser) tryTotalWaitMs(s []byte) (bool, error) {
	// Dummy implementation
	return bytes.HasPrefix(s, b("totalwaitms")), nil
}

func cutProtocol(s []byte) (Protocol, []byte) {
	if tail, found := bytes.CutPrefix(s, b("TCP")); found {
		return TCP, tail
	}
	if tail, found := bytes.CutPrefix(s, b("UDP")); found {
		return UDP, tail
	}
	return UnknownProtocol, s
}

func cutQuoted(s []byte) (value, tail []byte, found bool) {
	for i := 1; i < len(s); i++ {
		if s[0] == s[i] {
			return s[1:i], s[i+1:], true
		}
	}
	return nil, s, false
}

func cutQuotedWithPrefix(s, prefix []byte) (value, tail []byte, found bool) {
	if tail, found := bytes.CutPrefix(s, prefix); found {
		return cutQuoted(tail)
	}
	return nil, s, false
}

func cutMatchPattern(s []byte) (p MatchPattern, tail []byte, err error) {
	if regex, tail, found := cutQuotedWithPrefix(s, b("m")); found {
		var flags []byte
		for len(tail) > 0 && (tail[0] == 'i' || tail[0] == 's') {
			flags = append(flags, tail[0])
			tail = tail[1:]
		}
		return MatchPattern{
			Regex: string(regex),
			Flags: string(flags),
		}, tail, nil
	}
	return MatchPattern{}, s, fmt.Errorf("not match m/[regex]/ syntax")
}

func parseInfo(s []byte) (info Info[Template], err error) {
	var value []byte
	var found bool
	for {
		if len(s) == 0 {
			return info, nil
		} else if value, s, found = cutQuotedWithPrefix(s, b("p")); found {
			info.VendorProductName = template.Parse(value)
		} else if value, s, found = cutQuotedWithPrefix(s, b("v")); found {
			info.Version = template.Parse(value)
		} else if value, s, found = cutQuotedWithPrefix(s, b("i")); found {
			info.Info = template.Parse(value)
		} else if value, s, found = cutQuotedWithPrefix(s, b("h")); found {
			info.Hostname = template.Parse(value)
		} else if value, s, found = cutQuotedWithPrefix(s, b("o")); found {
			info.OS = template.Parse(value)
		} else if value, s, found = cutQuotedWithPrefix(s, b("d")); found {
			info.DeviceType = template.Parse(value)
		} else if value, s, found = cutCPE(s); found {
			info.CPE = append(info.CPE, template.Parse(value))
		} else {
			return info, fmt.Errorf("unknown signature: %q", s)
		}
		s = skipSpace(s)
	}
}

func cutCPE(s []byte) (value, tail []byte, found bool) {
	if value, tail, found = cutQuotedWithPrefix(s, b("cpe:")); found {
		value = append(b("cpe:/"), value...)
		tail, _ = bytes.CutPrefix(tail, b("a"))
		return value, tail, true
	}
	return nil, s, false
}

var asciiSpace = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}

func skipSpace(s []byte) []byte {
	i := 0
	for i < len(s) && asciiSpace[s[i]] != 0 {
		i++
	}
	return s[i:]
}

func cutUntilSpace(s []byte) (head, tail []byte) {
	i := 0
	for i < len(s) && asciiSpace[s[i]] == 0 {
		i++
	}
	return s[:i], s[i:]
}

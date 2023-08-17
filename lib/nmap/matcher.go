package nmap

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
)

var MatchTimeout = time.Second

type Matcher struct {
	Protocol Protocol
	Probe    string
	Service  string
	Info[Template]
	Soft bool
	re   *regexp2.Regexp
}

func MakeMatcher(probe ServiceProbe, match Match) (*Matcher, error) {
	var opts regexp2.RegexOptions
	if strings.Contains(match.Flags, "i") {
		opts |= regexp2.IgnoreCase
	}
	if strings.Contains(match.Flags, "s") {
		opts |= regexp2.Singleline
	}
	re, err := regexp2.Compile(match.Regex, opts)
	if err != nil {
		return nil, err
	}
	re.MatchTimeout = time.Second

	return &Matcher{
		Protocol: probe.Protocol,
		Probe:    probe.Name,
		Service:  match.Service,
		Info:     match.Info,
		Soft:     match.Soft,
		re:       re,
	}, err
}

func (m *Matcher) MatchBytes(input []byte) MatchResult {
	return m.MatchRunes(intoRunes(input))
}

func (m *Matcher) MatchRunes(input []rune) MatchResult {
	match, err := m.re.FindRunesMatch(input)
	return MatchResult{match, err}
}

func intoRunes(input []byte) []rune {
	runes := make([]rune, 0, len(input))
	for len(input) > 0 {
		if r, size := utf8.DecodeRune(input); r != utf8.RuneError {
			runes = append(runes, r)
			input = input[size:]
		} else {
			runes = append(runes, rune(input[0]))
			input = input[1:]
		}
	}
	return runes
}

type MatchResult struct {
	match *regexp2.Match
	err   error
}

func (r MatchResult) Found() bool { return r.match != nil && r.err == nil }
func (r MatchResult) Err() error  { return r.err }

func (r MatchResult) Render(tmpl Info[Template]) Info[string] {
	if r.Found() {
		var cpe []string
		for _, tmpl := range tmpl.CPE {
			cpe = append(cpe, tmpl.Render(r.match))
		}
		return Info[string]{
			VendorProductName: tmpl.VendorProductName.Render(r.match),
			Version:           tmpl.Version.Render(r.match),
			Info:              tmpl.Info.Render(r.match),
			Hostname:          tmpl.Hostname.Render(r.match),
			OS:                tmpl.OS.Render(r.match),
			DeviceType:        tmpl.DeviceType.Render(r.match),
			CPE:               cpe,
		}
	}
	return Info[string]{}
}

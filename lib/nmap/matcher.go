package nmap

import (
	"strings"

	"github.com/dlclark/regexp2"
)

type Matcher struct {
	Protocol Protocol
	Probe    string
	Service  string
	VersionInfo
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
	return &Matcher{
		Protocol:    probe.Protocol,
		Probe:       probe.Name,
		Service:     match.Service,
		VersionInfo: match.VersionInfo,
		Soft:        match.Soft,
		re:          re,
	}, err
}

func (m *Matcher) MatchRunes(input []rune) MatchResult {
	match, err := m.re.FindRunesMatch(input)
	return MatchResult{match, err}
}

type MatchResult struct {
	match *regexp2.Match
	err   error
}

func (r MatchResult) Found() bool { return r.match != nil && r.err == nil }
func (r MatchResult) Err() error  { return r.err }

func (r MatchResult) Render(v VersionInfo) VersionInfo {
	if r.Found() {
		replacer := r.newReplacer()
		var cpe []string
		for _, value := range v.CPE {
			cpe = append(cpe, replacer.Replace(value))
		}
		return VersionInfo{
			VendorProductName: replacer.Replace(v.VendorProductName),
			Version:           replacer.Replace(v.Version),
			Info:              replacer.Replace(v.Info),
			Hostname:          replacer.Replace(v.Hostname),
			OS:                replacer.Replace(v.OS),
			DeviceType:        replacer.Replace(v.DeviceType),
			CPE:               cpe,
		}
	}
	return v
}

func (r MatchResult) newReplacer() strings.Replacer {
	groups := r.match.Groups()
	oldnew := make([]string, 0, 2*len(groups))
	for i := 1; i < len(groups); i++ {
		group := groups[i]

		name := "$" + group.Name
		oldnew = append(oldnew, name, group.String())
	}
	return *strings.NewReplacer(oldnew...)
}

func (v *VersionInfo) merge(with VersionInfo) {
	v.VendorProductName = or(v.VendorProductName, with.VendorProductName)
	v.Version = or(v.Version, with.Version)
	v.Info = or(v.Info, with.Info)
	v.Hostname = or(v.Hostname, with.Hostname)
	v.OS = or(v.OS, with.OS)
	v.DeviceType = or(v.DeviceType, with.DeviceType)
	v.CPE = append(v.CPE, with.CPE...)
}

func or[T comparable](value ...T) T {
	var zero T
	for _, value := range value {
		if value != zero {
			return value
		}
	}
	return zero
}

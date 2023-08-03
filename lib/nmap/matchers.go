package nmap

import (
	"io"
	"os"
)

type Matchers []*Matcher

func (ms *Matchers) Load(in io.Reader) error {
	probes, err := ParseServiceProbes(in)
	if err != nil {
		return err
	}

	var matchers Matchers
	for _, probe := range probes {
		for _, match := range probe.Matches {
			m, err := MakeMatcher(probe, match)
			if err != nil {
				return err
			}
			matchers = append(matchers, m)
		}
	}

	*ms = matchers
	return nil
}

func (ms Matchers) Filter(fn func(*Matcher) bool) Matchers {
	var filtered []*Matcher
	for _, m := range ms {
		if fn(m) {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

func (ms Matchers) MatchBytes(input []byte) (bool, VersionInfo, error) {
	runes := []rune(string(input))
	return ms.MatchRunes(runes)
}

func (ms Matchers) MatchRunes(input []rune) (bool, VersionInfo, error) {
	var info VersionInfo
	for _, m := range ms {
		r := m.MatchRunes(input)
		if err := r.Err(); err != nil {
			return false, info, err
		}
		if r.Found() {
			info.merge(r.Render(m.VersionInfo))
			if !m.Soft {
				return true, info, nil
			}
		}
	}
	return false, info, nil
}

var globalMatchers Matchers

func LoadServiceProbes(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return globalMatchers.Load(f)
}

func SelectMatchers(filter func(*Matcher) bool) Matchers {
	return globalMatchers.Filter(filter)
}

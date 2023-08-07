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

func (ms Matchers) MatchBytes(input []byte) (bool, Info[string], error) {
	return ms.MatchRunes(intoRunes(input))
}

func (ms Matchers) MatchRunes(input []rune) (bool, Info[string], error) {
	var info Info[string]
	for _, m := range ms {
		r := m.MatchRunes(input)
		if err := r.Err(); err != nil {
			return false, info, err
		}
		if r.Found() {
			info = mergeInfo(info, r.Render(m.Info))
			if !m.Soft {
				return true, info, nil
			}
		}
	}
	return false, info, nil
}

func mergeInfo[T comparable](a, b Info[T]) Info[T] {
	return Info[T]{
		VendorProductName: or(a.VendorProductName, b.VendorProductName),
		Version:           or(a.Version, b.Version),
		Info:              or(a.Info, b.Info),
		Hostname:          or(a.Hostname, b.Hostname),
		OS:                or(a.OS, b.OS),
		DeviceType:        or(a.DeviceType, b.DeviceType),
		CPE:               append(a.CPE, b.CPE...),
	}
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

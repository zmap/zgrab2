package nmap

import (
	"io"
	"os"
	"path/filepath"
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

// Filter matchers using GLOB-pattern.
// Matchers are identified with `<probe>/<service>` name.
func (ms Matchers) FilterGlob(patterns ...string) Matchers {
	if len(patterns) == 0 {
		return nil
	}
	return ms.Filter(func(m *Matcher) bool {
		name := m.Probe + "/" + m.Service
		for _, pattern := range patterns {
			if ok, err := filepath.Match(pattern, name); ok && err == nil {
				return true
			}
		}
		return false
	})
}

type ExtractResult struct {
	Probe     string `json:"probe"`
	Service   string `json:"service"`
	Regex     string `json:"regex"`
	SoftMatch bool   `json:"softmatch"`
	Info[string]
}

func (ms Matchers) ExtractInfoFromBytes(input []byte) ([]ExtractResult, error) {
	return ms.ExtractInfoFromRunes(intoRunes(input))
}

func (ms Matchers) ExtractInfoFromRunes(input []rune) (result []ExtractResult, err error) {
	for _, m := range ms {
		r := m.MatchRunes(input)
		if err := r.Err(); err != nil {
			return nil, err
		}
		if r.Found() {
			result = append(result, ExtractResult{
				Probe:     m.Probe,
				Service:   m.Service,
				Regex:     m.re.String(),
				SoftMatch: m.Soft,
				Info:      r.Render(m.Info),
			})
		}
	}
	return result, nil
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

func SelectMatchersGlob(patterns ...string) Matchers {
	return globalMatchers.FilterGlob(patterns...)
}

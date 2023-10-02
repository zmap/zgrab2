package nmap

import (
	"errors"
	"io"
	"os"

	"github.com/gobwas/glob"
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
func (ms Matchers) FilterGlob(pattern string) Matchers {
	compiled, err := glob.Compile("{" + pattern + "}")
	if err != nil {
		return nil
	}
	return ms.Filter(func(m *Matcher) bool {
		name := m.Probe + "/" + m.Service
		return compiled.Match(name)
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

func (ms Matchers) ExtractInfoFromRunes(input []rune) ([]ExtractResult, error) {
	var result []ExtractResult
	var errs []error
	for _, m := range ms {
		r := m.MatchRunes(input)
		if err := r.Err(); err != nil {
			errs = append(errs, err)
			continue
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
	return result, errors.Join(errs...)
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

func SelectMatchersGlob(pattern string) Matchers {
	return globalMatchers.FilterGlob(pattern)
}

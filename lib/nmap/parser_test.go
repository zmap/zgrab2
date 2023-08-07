package nmap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCutProtocol(t *testing.T) {
	test := func(proto Protocol, tail, s string) {
		t.Helper()
		p, ss := cutProtocol([]byte(s))
		require.Equal(t, proto, p)
		require.Equal(t, tail, string(ss))
	}
	test(UnknownProtocol, "", "")
	test(UnknownProtocol, "...", "...")
	test(TCP, "...", "TCP...")
	test(UDP, "...", "UDP...")
}

func TestCutUntilSpace(t *testing.T) {
	test := func(value, tail, s string) {
		t.Helper()
		v, ss := cutUntilSpace([]byte(s))
		require.Equal(t, value, string(v), "in value")
		require.Equal(t, tail, string(ss), "in tail")
	}
	test("", "", "")
	test("A", "", "A")
	test("", " A", " A")
}

func TestCutQuoted(t *testing.T) {
	test := func(value, tail string, found bool, s string) {
		t.Helper()
		v, ss, f := cutQuoted([]byte(s))
		require.Equal(t, value, string(v), "in value")
		require.Equal(t, tail, string(ss), "in tail")
		require.Equal(t, found, f)
	}
	test("", "", false, "")
	test("", "/", false, "/")
	test("", "/...", false, "/...")
	test("", "...", true, "//...")
	test("VALUE", "...", true, "/VALUE/...")
}

func TestCutMatchPattern(t *testing.T) {
	test := func(regex, flags, tail, s string) {
		t.Helper()
		p, ss, err := cutMatchPattern([]byte(s))
		require.NoError(t, err)
		require.Equal(t, regex, p.Regex, "in regex")
		require.Equal(t, flags, p.Flags, "in flags")
		require.Equal(t, tail, string(ss), "in tail")
	}
	test("", "", "", "m//")
	test("", "", " ", "m// ")
	test("REGEX", "", " ", "m/REGEX/ ")
	test("REGEX", "i", " ", "m/REGEX/i ")
	test("REGEX", "s", " ", "m/REGEX/s ")
	test("REGEX", "is", " ", "m/REGEX/is ")
}

func TestCutVersionInfoCPE(t *testing.T) {
	test := func(value, tail string, found bool, s string) {
		t.Helper()
		v, ss, f := cutVersionInfoCPE([]byte(s))
		require.Equal(t, value, string(v), "in value")
		require.Equal(t, tail, string(ss), "in tail")
		require.Equal(t, found, f)
	}
	test("", "", false, "")
	test("VALUE", "...", true, "cpe:/VALUE/...")
	test("VALUE", "...", true, "cpe:/VALUE/a...")
}

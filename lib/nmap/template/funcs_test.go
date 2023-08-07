package template

import (
	"strconv"
	"testing"

	"github.com/dlclark/regexp2"
	"github.com/stretchr/testify/require"
)

var itoa = strconv.Itoa

func TestBuiltinFuncs(t *testing.T) {
	re := regexp2.MustCompile("(.+)\n(.+)\n(.+)", regexp2.None)
	m, err := re.FindStringMatch("AAABBC\nA\x00B\x10C\n\x11\x22\x33")
	require.NoError(t, err)
	require.True(t, m != nil)

	test := func(template, output string) {
		t.Helper()
		tmpl := Parse([]byte(template))
		require.Equal(t, output, tmpl.Render(m))
	}

	test(`$1`, "AAABBC")
	test(`$2`, "A\x00B\x10C")
	test(`$3`, "\x11\x22\x33")

	test(`$SUBST(1,"A","a")`, "aaaBBC")
	test(`$P(1)/$P(2)`, "AAABBC/ABC")
	test(`$I(3)/$I(3,">")/$I(3,"<")`, "0/"+itoa(0x112233)+"/"+itoa(0x332211))
}

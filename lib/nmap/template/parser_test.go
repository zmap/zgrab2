package template

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	test := func(s string, tokens ...Token) {
		t.Helper()
		tmpl := Parse([]byte(s))
		require.Equal(t, Template(tokens), tmpl)
	}
	test("")
	test("T1", Term("T1"))
	test("$T1", Term("$T1"))
	test("T1$", Term("T1$"))
	test("T1$T2", Term("T1$T2"))
	test("$", Term("$"))
	test("$$", Term("$$"))
	test("$10", Group("10"))
	test("$10$2", Group("10"), Group("2"))
	test("$10$T", Group("10"), Term("$T"))
	test("$T$10", Term("$T"), Group("10"))
	test("$10$", Group("10"), Term("$"))
	test("$$10", Term("$"), Group("10"))
	test("FN()", Term("FN()"))
	test("$FN()", Func("FN"))
	test("$FN(", Term("$FN("))
	test("$FN(A1)", Func("FN", "A1"))
	test("$FN(A1", Term("$FN(A1"))
	test("$FN(A1,", Term("$FN(A1,"))
	test("$FN(A1,)", Func("FN", "A1", ""))
	test("$FN(,A2)", Func("FN", "", "A2"))
	test("$FN(,)", Func("FN", "", ""))
	test("_$1_$F1()_$2_$F2(A1)_",
		Term("_"), Group("1"), Term("_"), Func("F1"), Term("_"),
		Group("2"), Term("_"), Func("F2", "A1"), Term("_"))
}

func TestCutFunc(t *testing.T) {
	test := func(name string, args []string, tail string, found bool, s string) {
		t.Helper()
		n, as, ss, f := cutFunc([]byte(s))
		require.Equal(t, name, string(n), "in name")
		require.Equal(t, args, as, "in args")
		require.Equal(t, tail, string(ss), "in tail")
		require.Equal(t, found, f)
	}

	test("", nil, ``, false, ``)
	test("", nil, `...`, false, `...`)
	test("", nil, `()...`, false, `()...`)
	test("", nil, `FN(...`, false, `FN(...`)
	test("", nil, `FN(A1...`, false, `FN(A1...`)
	test("", nil, `FN(A1,...`, false, `FN(A1,...`)
	test("", nil, `FN(""A1)...`, false, `FN(""A1)...`)
	test("", nil, `FN("""")...`, false, `FN("""")...`)
	test("", nil, `FN(`, false, `FN(`)
	test("", nil, `FN(A1`, false, `FN(A1`)
	test("", nil, `FN(A1,`, false, `FN(A1,`)

	test("FN", nil, "...", true, `FN()...`)
	test("FN", []string{"A1"}, "...", true, `FN(A1)...`)
	test("FN", []string{"A1", "A2"}, "...", true, `FN(A1,A2)...`)
	test("FN", []string{"A1", "A2"}, "...", true, `FN(A1,"A2")...`)
	test("FN", []string{"A,1", "A)2"}, "...", true, `FN("A,1","A)2")...`)
	test("FN", []string{"", "A2", ""}, "...", true, `FN(,A2,)...`)
	test("FN", []string{"", "A2", ""}, "...", true, `FN("",A2,"")...`)
	test("FN", []string{`"A1`}, "...", true, `FN("A1)...`)
	test("FN", []string{`A1"`}, "...", true, `FN(A1")...`)
	test("FN", []string{`A1""`}, "...", true, `FN(A1"")...`)
}

func TestCutDigits(t *testing.T) {
	test := func(digits, tail string, s string) {
		t.Helper()
		ds, ss := cutDigits([]byte(s))
		require.Equal(t, digits, string(ds), "in digits")
		require.Equal(t, tail, string(ss), "in tail")
	}
	test("", "", "")
	test("", "...", "...")
	test("1", "...", "1...")
	test("1234567890", "...", "1234567890...")
}

func TestCutUntilAny(t *testing.T) {
	test := func(head, tail string, found bool, s string, anyOf ...byte) {
		t.Helper()
		h, ss, f := cutUntilAny([]byte(s), anyOf...)
		require.Equal(t, head, string(h), "in head")
		require.Equal(t, tail, string(ss), "in tail")
		require.Equal(t, found, f)
	}
	test("", "", false, "", '.', ':')
	test("", "...", true, "...", '.', ':')
	test("", ":::", true, ":::", '.', ':')
	test("HEAD", "...", true, "HEAD...", '.', ':')
	test("HEAD", ":::", true, "HEAD:::", '.', ':')
	test("HEAD", "", false, "HEAD", '.', ':')
}

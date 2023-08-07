package template

import (
	"strconv"
	"strings"
	"unicode"

	"github.com/dlclark/regexp2"
)

type funcFn func(*regexp2.Match, ...string) string

var builtinFuncs = map[string]funcFn{
	"SUBST": subst,
	"P":     printable,
	"I":     asInt,
}

func subst(match *regexp2.Match, args ...string) string {
	if len(args) >= 3 {
		if g := match.GroupByName(args[0]); g != nil {
			return strings.ReplaceAll(g.String(), args[1], args[2])
		}
	}
	return ""
}

func printable(match *regexp2.Match, args ...string) (result string) {
	if len(args) >= 1 {
		if g := match.GroupByName(args[0]); g != nil {
			for _, rune := range g.String() {
				if unicode.IsPrint(rune) {
					result += string(rune)
				}
			}
		}
	}
	return result
}

func asInt(match *regexp2.Match, args ...string) string {
	var n uint64
	if len(args) >= 2 {
		if g := match.GroupByName(args[0]); g != nil {
			switch args[1] {
			case ">":
				n = asIntBE(g.String())
			case "<":
				n = asIntLE(g.String())
			}
		}
	}
	return strconv.FormatUint(n, 10)
}

func asIntBE(s string) (result uint64) {
	for i := 0; i < len(s); i++ {
		result = (result << 8) | uint64(s[i])
	}
	return result
}

func asIntLE(s string) (result uint64) {
	for i := len(s) - 1; i >= 0; i-- {
		result = (result << 8) | uint64(s[i])
	}
	return result
}

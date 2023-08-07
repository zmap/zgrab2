package template

import (
	"strings"

	"github.com/dlclark/regexp2"
)

type Template []Token

type Token struct {
	kind  tokenKind
	value string
	args  []string
}

type tokenKind int

const (
	tokenTerm  tokenKind = iota // Terminal token contains a literal string value.
	tokenGroup                  // Group token references a capturing group, example: $1, $2.
	tokenFunc                   // Function token, example: $SUBST(...)
)

func Term(s string) Token                    { return Token{kind: tokenTerm, value: s} }
func Group(index string) Token               { return Token{kind: tokenGroup, value: index} }
func Func(name string, args ...string) Token { return Token{kind: tokenFunc, value: name, args: args} }

func (tmpl Template) Render(match *regexp2.Match) string {
	var b strings.Builder
	for _, token := range tmpl {
		b.WriteString(token.Render(match))
	}
	return b.String()
}

func (token Token) Render(match *regexp2.Match) string {
	switch token.kind {
	case tokenTerm:
		return token.value
	case tokenGroup:
		return token.renderGroup(match)
	case tokenFunc:
		return token.renderFunc(match)
	}
	return ""
}

func (token Token) renderGroup(match *regexp2.Match) string {
	if g := match.GroupByName(token.value); g != nil {
		return g.String()
	}
	return ""
}

func (token Token) renderFunc(match *regexp2.Match) string {
	if fn, found := builtinFuncs[token.value]; found {
		return fn(match, token.args...)
	}
	return ""
}

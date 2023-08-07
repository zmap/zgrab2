package template

import (
	"bytes"
)

type parser struct {
	tokens []Token
}

func Parse(s []byte) Template {
	var p parser
	p.parse(s)
	return Template(p.tokens)
}

func (p *parser) parse(s []byte) {
	i := 0
	for i < len(s) {
		if token, tail, found := cutMacro(s[i:]); found {
			p.addTerm(s[:i])
			p.addToken(token)
			s, i = tail, 0
		} else {
			i++
		}
	}
	p.addTerm(s[:i])
}

func (p *parser) addTerm(s []byte) {
	if len(s) > 0 {
		p.tokens = append(p.tokens, Term(string(s)))
	}
}

func (p *parser) addToken(token Token) {
	p.tokens = append(p.tokens, token)
}

func cutMacro(s []byte) (token Token, tail []byte, found bool) {
	if tail, found := bytes.CutPrefix(s, []byte{'$'}); found {
		// Try to parse as a reference to capturing group ($1, $2, ...)
		if digits, tail := cutDigits(tail); len(digits) > 0 {
			return Group(string(digits)), tail, true
		}
		// Try to parse as a function
		if name, args, tail, found := cutFunc(tail); found {
			return Func(string(name), args...), tail, true
		}
	}
	return Token{}, s, false
}

func cutFunc(s []byte) (name []byte, args []string, tail []byte, found bool) {
	if name, tail, found := bytes.Cut(s, []byte{'('}); found && len(name) > 0 {
		args, tail := cutFuncArgs(tail)
		if tail, found := bytes.CutPrefix(tail, []byte{')'}); found {
			return name, args, tail, true
		}
	}
	return nil, nil, s, false
}

func cutFuncArgs(s []byte) (args []string, tail []byte) {
	if len(s) == 0 || s[0] == ')' {
		return args, s
	}
	for {
		var arg []byte
		arg, s = cutFuncArg(s)
		args = append(args, string(arg))

		if len(s) > 0 && s[0] == ',' {
			s = s[1:]
			continue
		}
		return args, s
	}
}

func cutFuncArg(s []byte) (value, tail []byte) {
	if value, tail, found := cutQuoted(s, '"'); found {
		return value, tail
	}
	value, tail, _ = cutUntilAny(s, ',', ')')
	return value, tail
}

func cutDigits(s []byte) (digits, tail []byte) {
	i := 0
	for i < len(s) && '0' <= s[i] && s[i] <= '9' {
		i++
	}
	return s[:i], s[i:]
}

func cutQuoted(s []byte, quote byte) (value, tail []byte, found bool) {
	if len(s) > 0 && s[0] == quote {
		if value, tail, found = bytes.Cut(s[1:], []byte{quote}); found {
			return value, tail, true
		}
	}
	return nil, s, false
}

func cutUntilAny(s []byte, anyOf ...byte) (head, tail []byte, found bool) {
	for i := 0; i < len(s); i++ {
		for ii := 0; ii < len(anyOf); ii++ {
			if s[i] == anyOf[ii] {
				return s[:i], s[i:], true
			}
		}
	}
	return s, nil, false
}

// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

var writeSetCookiesTests = []struct {
	Cookie *Cookie
	Raw    string
}{
	{
		&Cookie{Name: "cookie-1", Value: "v$1"},
		"cookie-1=v$1",
	},
	{
		&Cookie{Name: "cookie-2", Value: "two", MaxAge: 3600},
		"cookie-2=two; Max-Age=3600",
	},
	{
		&Cookie{Name: "cookie-3", Value: "three", Domain: ".example.com"},
		"cookie-3=three; Domain=example.com",
	},
	{
		&Cookie{Name: "cookie-4", Value: "four", Path: "/restricted/"},
		"cookie-4=four; Path=/restricted/",
	},
	{
		&Cookie{Name: "cookie-5", Value: "five", Domain: "wrong;bad.abc"},
		"cookie-5=five",
	},
	{
		&Cookie{Name: "cookie-6", Value: "six", Domain: "bad-.abc"},
		"cookie-6=six",
	},
	{
		&Cookie{Name: "cookie-7", Value: "seven", Domain: "127.0.0.1"},
		"cookie-7=seven; Domain=127.0.0.1",
	},
	{
		&Cookie{Name: "cookie-8", Value: "eight", Domain: "::1"},
		"cookie-8=eight",
	},
	{
		&Cookie{Name: "cookie-9", Value: "expiring", Expires: time.Unix(1257894000, 0)},
		"cookie-9=expiring; Expires=Tue, 10 Nov 2009 23:00:00 GMT",
	},
	// According to IETF 6265 Section 5.1.1.5, the year cannot be less than 1601
	{
		&Cookie{Name: "cookie-10", Value: "expiring-1601", Expires: time.Date(1601, 1, 1, 1, 1, 1, 1, time.UTC)},
		"cookie-10=expiring-1601; Expires=Mon, 01 Jan 1601 01:01:01 GMT",
	},
	{
		&Cookie{Name: "cookie-11", Value: "invalid-expiry", Expires: time.Date(1600, 1, 1, 1, 1, 1, 1, time.UTC)},
		"cookie-11=invalid-expiry",
	},
	// The "special" cookies have values containing commas or spaces which
	// are disallowed by RFC 6265 but are common in the wild.
	{
		&Cookie{Name: "special-1", Value: "a z"},
		`special-1=a z`,
	},
	{
		&Cookie{Name: "special-2", Value: " z"},
		`special-2=" z"`,
	},
	{
		&Cookie{Name: "special-3", Value: "a "},
		`special-3="a "`,
	},
	{
		&Cookie{Name: "special-4", Value: " "},
		`special-4=" "`,
	},
	{
		&Cookie{Name: "special-5", Value: "a,z"},
		`special-5=a,z`,
	},
	{
		&Cookie{Name: "special-6", Value: ",z"},
		`special-6=",z"`,
	},
	{
		&Cookie{Name: "special-7", Value: "a,"},
		`special-7="a,"`,
	},
	{
		&Cookie{Name: "special-8", Value: ","},
		`special-8=","`,
	},
	{
		&Cookie{Name: "empty-value", Value: ""},
		`empty-value=`,
	},
	{
		nil,
		``,
	},
	{
		&Cookie{Name: ""},
		``,
	},
	{
		&Cookie{Name: "\t"},
		``,
	},
}

func TestWriteSetCookies(t *testing.T) {
	defer log.SetOutput(os.Stderr)
	var logbuf bytes.Buffer
	log.SetOutput(&logbuf)

	for i, tt := range writeSetCookiesTests {
		if g, e := tt.Cookie.String(), tt.Raw; g != e {
			t.Errorf("Test %d, expecting:\n%s\nGot:\n%s\n", i, e, g)
			continue
		}
	}

	if got, sub := logbuf.String(), "dropping domain attribute"; !strings.Contains(got, sub) {
		t.Errorf("Expected substring %q in log output. Got:\n%s", sub, got)
	}
}

type headerOnlyResponseWriter Header

func (ho headerOnlyResponseWriter) Header() Header {
	return Header(ho)
}

func (ho headerOnlyResponseWriter) Write([]byte) (int, error) {
	panic("NOIMPL")
}

func (ho headerOnlyResponseWriter) WriteHeader(int) {
	panic("NOIMPL")
}

func TestSetCookie(t *testing.T) {
	m := make(Header)
	SetCookie(headerOnlyResponseWriter(m), &Cookie{Name: "cookie-1", Value: "one", Path: "/restricted/"})
	SetCookie(headerOnlyResponseWriter(m), &Cookie{Name: "cookie-2", Value: "two", MaxAge: 3600})
	if l := len(m["Set-Cookie"]); l != 2 {
		t.Fatalf("expected %d cookies, got %d", 2, l)
	}
	if g, e := m["Set-Cookie"][0], "cookie-1=one; Path=/restricted/"; g != e {
		t.Errorf("cookie #1: want %q, got %q", e, g)
	}
	if g, e := m["Set-Cookie"][1], "cookie-2=two; Max-Age=3600"; g != e {
		t.Errorf("cookie #2: want %q, got %q", e, g)
	}
}

var addCookieTests = []struct {
	Cookies []*Cookie
	Raw     string
}{
	{
		[]*Cookie{},
		"",
	},
	{
		[]*Cookie{{Name: "cookie-1", Value: "v$1"}},
		"cookie-1=v$1",
	},
	{
		[]*Cookie{
			{Name: "cookie-1", Value: "v$1"},
			{Name: "cookie-2", Value: "v$2"},
			{Name: "cookie-3", Value: "v$3"},
		},
		"cookie-1=v$1; cookie-2=v$2; cookie-3=v$3",
	},
}

func TestAddCookie(t *testing.T) {
	for i, tt := range addCookieTests {
		req, _ := NewRequest("GET", "http://example.com/", nil)
		for _, c := range tt.Cookies {
			req.AddCookie(c)
		}
		if g := req.Header.Get("Cookie"); g != tt.Raw {
			t.Errorf("Test %d:\nwant: %s\n got: %s\n", i, tt.Raw, g)
			continue
		}
	}
}

var readSetCookiesTests = []struct {
	Header  Header
	Cookies []*Cookie
}{
	{
		Header{"Set-Cookie": {"Cookie-1=v$1"}},
		[]*Cookie{{Name: "Cookie-1", Value: "v$1", Raw: "Cookie-1=v$1"}},
	},
	{
		Header{"Set-Cookie": {"NID=99=YsDT5i3E-CXax-; expires=Wed, 23-Nov-2011 01:05:03 GMT; path=/; domain=.google.ch; HttpOnly"}},
		[]*Cookie{{
			Name:       "NID",
			Value:      "99=YsDT5i3E-CXax-",
			Path:       "/",
			Domain:     ".google.ch",
			HttpOnly:   true,
			Expires:    time.Date(2011, 11, 23, 1, 5, 3, 0, time.UTC),
			RawExpires: "Wed, 23-Nov-2011 01:05:03 GMT",
			Raw:        "NID=99=YsDT5i3E-CXax-; expires=Wed, 23-Nov-2011 01:05:03 GMT; path=/; domain=.google.ch; HttpOnly",
		}},
	},
	{
		Header{"Set-Cookie": {".ASPXAUTH=7E3AA; expires=Wed, 07-Mar-2012 14:25:06 GMT; path=/; HttpOnly"}},
		[]*Cookie{{
			Name:       ".ASPXAUTH",
			Value:      "7E3AA",
			Path:       "/",
			Expires:    time.Date(2012, 3, 7, 14, 25, 6, 0, time.UTC),
			RawExpires: "Wed, 07-Mar-2012 14:25:06 GMT",
			HttpOnly:   true,
			Raw:        ".ASPXAUTH=7E3AA; expires=Wed, 07-Mar-2012 14:25:06 GMT; path=/; HttpOnly",
		}},
	},
	{
		Header{"Set-Cookie": {"ASP.NET_SessionId=foo; path=/; HttpOnly"}},
		[]*Cookie{{
			Name:     "ASP.NET_SessionId",
			Value:    "foo",
			Path:     "/",
			HttpOnly: true,
			Raw:      "ASP.NET_SessionId=foo; path=/; HttpOnly",
		}},
	},
	// Make sure we can properly read back the Set-Cookie headers we create
	// for values containing spaces or commas:
	{
		Header{"Set-Cookie": {`special-1=a z`}},
		[]*Cookie{{Name: "special-1", Value: "a z", Raw: `special-1=a z`}},
	},
	{
		Header{"Set-Cookie": {`special-2=" z"`}},
		[]*Cookie{{Name: "special-2", Value: " z", Raw: `special-2=" z"`}},
	},
	{
		Header{"Set-Cookie": {`special-3="a "`}},
		[]*Cookie{{Name: "special-3", Value: "a ", Raw: `special-3="a "`}},
	},
	{
		Header{"Set-Cookie": {`special-4=" "`}},
		[]*Cookie{{Name: "special-4", Value: " ", Raw: `special-4=" "`}},
	},
	{
		Header{"Set-Cookie": {`special-5=a,z`}},
		[]*Cookie{{Name: "special-5", Value: "a,z", Raw: `special-5=a,z`}},
	},
	{
		Header{"Set-Cookie": {`special-6=",z"`}},
		[]*Cookie{{Name: "special-6", Value: ",z", Raw: `special-6=",z"`}},
	},
	{
		Header{"Set-Cookie": {`special-7=a,`}},
		[]*Cookie{{Name: "special-7", Value: "a,", Raw: `special-7=a,`}},
	},
	{
		Header{"Set-Cookie": {`special-8=","`}},
		[]*Cookie{{Name: "special-8", Value: ",", Raw: `special-8=","`}},
	},

	// TODO(bradfitz): users have reported seeing this in the
	// wild, but do browsers handle it? RFC 6265 just says "don't
	// do that" (section 3) and then never mentions header folding
	// again.
	// Header{"Set-Cookie": {"ASP.NET_SessionId=foo; path=/; HttpOnly, .ASPXAUTH=7E3AA; expires=Wed, 07-Mar-2012 14:25:06 GMT; path=/; HttpOnly"}},
}

func toJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%#v", v)
	}
	return string(b)
}

func TestReadSetCookies(t *testing.T) {
	for i, tt := range readSetCookiesTests {
		for n := 0; n < 2; n++ { // to verify readSetCookies doesn't mutate its input
			c := readSetCookies(tt.Header)
			if !reflect.DeepEqual(c, tt.Cookies) {
				t.Errorf("#%d readSetCookies: have\n%s\nwant\n%s\n", i, toJSON(c), toJSON(tt.Cookies))
				continue
			}
		}
	}
}

var readCookiesTests = []struct {
	Header  Header
	Filter  string
	Cookies []*Cookie
}{
	{
		Header{"Cookie": {"Cookie-1=v$1", "c2=v2"}},
		"",
		[]*Cookie{
			{Name: "Cookie-1", Value: "v$1"},
			{Name: "c2", Value: "v2"},
		},
	},
	{
		Header{"Cookie": {"Cookie-1=v$1", "c2=v2"}},
		"c2",
		[]*Cookie{
			{Name: "c2", Value: "v2"},
		},
	},
	{
		Header{"Cookie": {"Cookie-1=v$1; c2=v2"}},
		"",
		[]*Cookie{
			{Name: "Cookie-1", Value: "v$1"},
			{Name: "c2", Value: "v2"},
		},
	},
	{
		Header{"Cookie": {"Cookie-1=v$1; c2=v2"}},
		"c2",
		[]*Cookie{
			{Name: "c2", Value: "v2"},
		},
	},
	{
		Header{"Cookie": {`Cookie-1="v$1"; c2="v2"`}},
		"",
		[]*Cookie{
			{Name: "Cookie-1", Value: "v$1"},
			{Name: "c2", Value: "v2"},
		},
	},
}

func TestReadCookies(t *testing.T) {
	for i, tt := range readCookiesTests {
		for n := 0; n < 2; n++ { // to verify readCookies doesn't mutate its input
			c := readCookies(tt.Header, tt.Filter)
			if !reflect.DeepEqual(c, tt.Cookies) {
				t.Errorf("#%d readCookies:\nhave: %s\nwant: %s\n", i, toJSON(c), toJSON(tt.Cookies))
				continue
			}
		}
	}
}

func TestSetCookieDoubleQuotes(t *testing.T) {
	res := &Response{Header: Header{}}
	res.Header.Add("Set-Cookie", `quoted0=none; max-age=30`)
	res.Header.Add("Set-Cookie", `quoted1="cookieValue"; max-age=31`)
	res.Header.Add("Set-Cookie", `quoted2=cookieAV; max-age="32"`)
	res.Header.Add("Set-Cookie", `quoted3="both"; max-age="33"`)
	got := res.Cookies()
	want := []*Cookie{
		{Name: "quoted0", Value: "none", MaxAge: 30},
		{Name: "quoted1", Value: "cookieValue", MaxAge: 31},
		{Name: "quoted2", Value: "cookieAV"},
		{Name: "quoted3", Value: "both"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d cookies, want %d", len(got), len(want))
	}
	for i, w := range want {
		g := got[i]
		if g.Name != w.Name || g.Value != w.Value || g.MaxAge != w.MaxAge {
			t.Errorf("cookie #%d:\ngot  %v\nwant %v", i, g, w)
		}
	}
}

func TestCookieSanitizeValue(t *testing.T) {
	defer log.SetOutput(os.Stderr)
	var logbuf bytes.Buffer
	log.SetOutput(&logbuf)

	tests := []struct {
		in, want string
	}{
		{"foo", "foo"},
		{"foo;bar", "foobar"},
		{"foo\\bar", "foobar"},
		{"foo\"bar", "foobar"},
		{"\x00\x7e\x7f\x80", "\x7e"},
		{`"withquotes"`, "withquotes"},
		{"a z", "a z"},
		{" z", `" z"`},
		{"a ", `"a "`},
	}
	for _, tt := range tests {
		if got := sanitizeCookieValue(tt.in); got != tt.want {
			t.Errorf("sanitizeCookieValue(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}

	if got, sub := logbuf.String(), "dropping invalid bytes"; !strings.Contains(got, sub) {
		t.Errorf("Expected substring %q in log output. Got:\n%s", sub, got)
	}
}

func TestCookieSanitizePath(t *testing.T) {
	defer log.SetOutput(os.Stderr)
	var logbuf bytes.Buffer
	log.SetOutput(&logbuf)

	tests := []struct {
		in, want string
	}{
		{"/path", "/path"},
		{"/path with space/", "/path with space/"},
		{"/just;no;semicolon\x00orstuff/", "/justnosemicolonorstuff/"},
	}
	for _, tt := range tests {
		if got := sanitizeCookiePath(tt.in); got != tt.want {
			t.Errorf("sanitizeCookiePath(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}

	if got, sub := logbuf.String(), "dropping invalid bytes"; !strings.Contains(got, sub) {
		t.Errorf("Expected substring %q in log output. Got:\n%s", sub, got)
	}
}

func BenchmarkCookieString(b *testing.B) {
	const wantCookieString = `cookie-9=i3e01nf61b6t23bvfmplnanol3; Path=/restricted/; Domain=example.com; Expires=Tue, 10 Nov 2009 23:00:00 GMT; Max-Age=3600`
	c := &Cookie{
		Name:    "cookie-9",
		Value:   "i3e01nf61b6t23bvfmplnanol3",
		Expires: time.Unix(1257894000, 0),
		Path:    "/restricted/",
		Domain:  ".example.com",
		MaxAge:  3600,
	}
	var benchmarkCookieString string
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkCookieString = c.String()
	}
	if have, want := benchmarkCookieString, wantCookieString; have != want {
		b.Fatalf("Have: %v Want: %v", have, want)
	}
}

func BenchmarkReadSetCookies(b *testing.B) {
	header := Header{
		"Set-Cookie": {
			"NID=99=YsDT5i3E-CXax-; expires=Wed, 23-Nov-2011 01:05:03 GMT; path=/; domain=.google.ch; HttpOnly",
			".ASPXAUTH=7E3AA; expires=Wed, 07-Mar-2012 14:25:06 GMT; path=/; HttpOnly",
		},
	}
	wantCookies := []*Cookie{
		{
			Name:       "NID",
			Value:      "99=YsDT5i3E-CXax-",
			Path:       "/",
			Domain:     ".google.ch",
			HttpOnly:   true,
			Expires:    time.Date(2011, 11, 23, 1, 5, 3, 0, time.UTC),
			RawExpires: "Wed, 23-Nov-2011 01:05:03 GMT",
			Raw:        "NID=99=YsDT5i3E-CXax-; expires=Wed, 23-Nov-2011 01:05:03 GMT; path=/; domain=.google.ch; HttpOnly",
		},
		{
			Name:       ".ASPXAUTH",
			Value:      "7E3AA",
			Path:       "/",
			Expires:    time.Date(2012, 3, 7, 14, 25, 6, 0, time.UTC),
			RawExpires: "Wed, 07-Mar-2012 14:25:06 GMT",
			HttpOnly:   true,
			Raw:        ".ASPXAUTH=7E3AA; expires=Wed, 07-Mar-2012 14:25:06 GMT; path=/; HttpOnly",
		},
	}
	var c []*Cookie
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c = readSetCookies(header)
	}
	if !reflect.DeepEqual(c, wantCookies) {
		b.Fatalf("readSetCookies:\nhave: %s\nwant: %s\n", toJSON(c), toJSON(wantCookies))
	}
}

func BenchmarkReadCookies(b *testing.B) {
	header := Header{
		"Cookie": {
			`de=; client_region=0; rpld1=0:hispeed.ch|20:che|21:zh|22:zurich|23:47.36|24:8.53|; rpld0=1:08|; backplane-channel=newspaper.com:1471; devicetype=0; osfam=0; rplmct=2; s_pers=%20s_vmonthnum%3D1472680800496%2526vn%253D1%7C1472680800496%3B%20s_nr%3D1471686767664-New%7C1474278767664%3B%20s_lv%3D1471686767669%7C1566294767669%3B%20s_lv_s%3DFirst%2520Visit%7C1471688567669%3B%20s_monthinvisit%3Dtrue%7C1471688567677%3B%20gvp_p5%3Dsports%253Ablog%253Aearly-lead%2520-%2520184693%2520-%252020160820%2520-%2520u-s%7C1471688567681%3B%20gvp_p51%3Dwp%2520-%2520sports%7C1471688567684%3B; s_sess=%20s_wp_ep%3Dhomepage%3B%20s._ref%3Dhttps%253A%252F%252Fwww.google.ch%252F%3B%20s_cc%3Dtrue%3B%20s_ppvl%3Dsports%25253Ablog%25253Aearly-lead%252520-%252520184693%252520-%25252020160820%252520-%252520u-lawyer%252C12%252C12%252C502%252C1231%252C502%252C1680%252C1050%252C2%252CP%3B%20s_ppv%3Dsports%25253Ablog%25253Aearly-lead%252520-%252520184693%252520-%25252020160820%252520-%252520u-s-lawyer%252C12%252C12%252C502%252C1231%252C502%252C1680%252C1050%252C2%252CP%3B%20s_dslv%3DFirst%2520Visit%3B%20s_sq%3Dwpninewspapercom%253D%252526pid%25253Dsports%2525253Ablog%2525253Aearly-lead%25252520-%25252520184693%25252520-%2525252020160820%25252520-%25252520u-s%252526pidt%25253D1%252526oid%25253Dhttps%2525253A%2525252F%2525252Fwww.newspaper.com%2525252F%2525253Fnid%2525253Dmenu_nav_homepage%252526ot%25253DA%3B`,
		},
	}
	wantCookies := []*Cookie{
		{Name: "de", Value: ""},
		{Name: "client_region", Value: "0"},
		{Name: "rpld1", Value: "0:hispeed.ch|20:che|21:zh|22:zurich|23:47.36|24:8.53|"},
		{Name: "rpld0", Value: "1:08|"},
		{Name: "backplane-channel", Value: "newspaper.com:1471"},
		{Name: "devicetype", Value: "0"},
		{Name: "osfam", Value: "0"},
		{Name: "rplmct", Value: "2"},
		{Name: "s_pers", Value: "%20s_vmonthnum%3D1472680800496%2526vn%253D1%7C1472680800496%3B%20s_nr%3D1471686767664-New%7C1474278767664%3B%20s_lv%3D1471686767669%7C1566294767669%3B%20s_lv_s%3DFirst%2520Visit%7C1471688567669%3B%20s_monthinvisit%3Dtrue%7C1471688567677%3B%20gvp_p5%3Dsports%253Ablog%253Aearly-lead%2520-%2520184693%2520-%252020160820%2520-%2520u-s%7C1471688567681%3B%20gvp_p51%3Dwp%2520-%2520sports%7C1471688567684%3B"},
		{Name: "s_sess", Value: "%20s_wp_ep%3Dhomepage%3B%20s._ref%3Dhttps%253A%252F%252Fwww.google.ch%252F%3B%20s_cc%3Dtrue%3B%20s_ppvl%3Dsports%25253Ablog%25253Aearly-lead%252520-%252520184693%252520-%25252020160820%252520-%252520u-lawyer%252C12%252C12%252C502%252C1231%252C502%252C1680%252C1050%252C2%252CP%3B%20s_ppv%3Dsports%25253Ablog%25253Aearly-lead%252520-%252520184693%252520-%25252020160820%252520-%252520u-s-lawyer%252C12%252C12%252C502%252C1231%252C502%252C1680%252C1050%252C2%252CP%3B%20s_dslv%3DFirst%2520Visit%3B%20s_sq%3Dwpninewspapercom%253D%252526pid%25253Dsports%2525253Ablog%2525253Aearly-lead%25252520-%25252520184693%25252520-%2525252020160820%25252520-%25252520u-s%252526pidt%25253D1%252526oid%25253Dhttps%2525253A%2525252F%2525252Fwww.newspaper.com%2525252F%2525253Fnid%2525253Dmenu_nav_homepage%252526ot%25253DA%3B"},
	}
	var c []*Cookie
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c = readCookies(header, "")
	}
	if !reflect.DeepEqual(c, wantCookies) {
		b.Fatalf("readCookies:\nhave: %s\nwant: %s\n", toJSON(c), toJSON(wantCookies))
	}
}

// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"encoding/json"
	"io"
	"net/textproto"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/zmap/zgrab2/lib/http/httptrace"

	"golang.org/x/net/http/httpguts"

	"github.com/zmap/zgrab2/lib/http/internal/ascii"
)

var knownHeaders = map[string]bool{
	"accept":                      true,
	"accept_charset":              true,
	"accept_encoding":             true,
	"accept_language":             true,
	"accept_patch":                true,
	"accept_ranges":               true,
	"access_control_allow_origin": true,
	"age":                         true,
	"allow":                       true,
	"alt_svc":                     true,
	"alternate_protocol":          true,
	"authorization":               true,
	"cache_control":               true,
	"connection":                  true,
	"content_disposition":         true,
	"content_encoding":            true,
	"content_language":            true,
	"content_length":              true,
	"content_location":            true,
	"content_md5":                 true,
	"content_range":               true,
	"content_security_policy":     true,
	"content_type":                true,
	"cookie":                      true,
	"date":                        true,
	"etag":                        true,
	"expect":                      true,
	"expires":                     true,
	"from":                        true,
	"host":                        true,
	"if_match":                    true,
	"if_modified_since":           true,
	"if_none_match":               true,
	"if_unmodified_since":         true,
	"last_modified":               true,
	"link":                        true,
	"location":                    true,
	"max_forwards":                true,
	"p3p":                         true,
	"pragma":                      true,
	"proxy_agent":                 true,
	"proxy_authenticate":          true,
	"proxy_authorization":         true,
	"public_key_pins":             true,
	"range":                       true,
	"referer":                     true,
	"refresh":                     true,
	"retry_after":                 true,
	"server":                      true,
	"set_cookie":                  true,
	"status":                      true,
	"strict_transport_security":   true,
	"trailer":                     true,
	"transfer_encoding":           true,
	"upgrade":                     true,
	"user_agent":                  true,
	"vary":                        true,
	"via":                         true,
	"warning":                     true,
	"www_authenticate":            true,
	"x_content_duration":          true,
	"x_content_security_policy":   true,
	"x_content_type_options":      true,
	"x_forwarded_for":             true,
	"x_frame_options":             true,
	"x_powered_by":                true,
	"x_real_ip":                   true,
	"x_ua_compatible":             true,
	"x_webkit_csp":                true,
	"x_xss_protection":            true,
}

// A Header represents the key-value pairs in an HTTP header.
//
// The keys should be in canonical form, as returned by
// [CanonicalHeaderKey].
type Header map[string][]string

// Add adds the key, value pair to the header.
// It appends to any existing values associated with key.
// The key is case insensitive; it is canonicalized by
// [CanonicalHeaderKey].
func (h Header) Add(key, value string) {
	textproto.MIMEHeader(h).Add(key, value)
}

// Set sets the header entries associated with key to the
// single element value. It replaces any existing values
// associated with key. The key is case insensitive; it is
// canonicalized by [textproto.CanonicalMIMEHeaderKey].
// To use non-canonical keys, assign to the map directly.
func (h Header) Set(key, value string) {
	textproto.MIMEHeader(h).Set(key, value)
}

// Get gets the first value associated with the given key. If
// there are no values associated with the key, Get returns "".
// It is case insensitive; [textproto.CanonicalMIMEHeaderKey] is
// used to canonicalize the provided key. Get assumes that all
// keys are stored in canonical form. To use non-canonical keys,
// access the map directly.
func (h Header) Get(key string) string {
	return textproto.MIMEHeader(h).Get(key)
}

// Values returns all values associated with the given key.
// It is case insensitive; [textproto.CanonicalMIMEHeaderKey] is
// used to canonicalize the provided key. To use non-canonical
// keys, access the map directly.
// The returned slice is not a copy.
func (h Header) Values(key string) []string {
	return textproto.MIMEHeader(h).Values(key)
}

// get is like Get, but key must already be in CanonicalHeaderKey form.
func (h Header) get(key string) string {
	if v := h[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// has reports whether h has the provided key defined, even if it's
// set to 0-length slice.
func (h Header) has(key string) bool {
	_, ok := h[key]
	return ok
}

// Del deletes the values associated with key.
// The key is case insensitive; it is canonicalized by
// [CanonicalHeaderKey].
func (h Header) Del(key string) {
	textproto.MIMEHeader(h).Del(key)
}

// Write writes a header in wire format.
func (h Header) Write(w io.Writer) error {
	return h.write(w, nil)
}

func (h Header) write(w io.Writer, trace *httptrace.ClientTrace) error {
	return h.writeSubset(w, nil, trace)
}

// Clone returns a copy of h or nil if h is nil.
func (h Header) Clone() Header {
	if h == nil {
		return nil
	}

	// Find total number of values.
	nv := 0
	for _, vv := range h {
		nv += len(vv)
	}
	sv := make([]string, nv) // shared backing array for headers' values
	h2 := make(Header, len(h))
	for k, vv := range h {
		if vv == nil {
			// Preserve nil values. ReverseProxy distinguishes
			// between nil and zero-length header values.
			h2[k] = nil
			continue
		}
		n := copy(sv, vv)
		h2[k] = sv[:n:n]
		sv = sv[n:]
	}
	return h2
}

var timeFormats = []string{
	TimeFormat,
	time.RFC850,
	time.ANSIC,
}

// ParseTime parses a time header (such as the Date: header),
// trying each of the three formats allowed by HTTP/1.1:
// [TimeFormat], [time.RFC850], and [time.ANSIC].
func ParseTime(text string) (t time.Time, err error) {
	for _, layout := range timeFormats {
		t, err = time.Parse(layout, text)
		if err == nil {
			return
		}
	}
	return
}

var headerNewlineToSpace = strings.NewReplacer("\n", " ", "\r", " ")

// stringWriter implements WriteString on a Writer.
type stringWriter struct {
	w io.Writer
}

func (w stringWriter) WriteString(s string) (n int, err error) {
	return w.w.Write([]byte(s))
}

type keyValues struct {
	key    string
	values []string
}

// headerSorter contains a slice of keyValues sorted by keyValues.key.
type headerSorter struct {
	kvs []keyValues
}

var headerSorterPool = sync.Pool{
	New: func() any { return new(headerSorter) },
}

// sortedKeyValues returns h's keys sorted in the returned kvs
// slice. The headerSorter used to sort is also returned, for possible
// return to headerSorterCache.
func (h Header) sortedKeyValues(exclude map[string]bool) (kvs []keyValues, hs *headerSorter) {
	hs = headerSorterPool.Get().(*headerSorter)
	if cap(hs.kvs) < len(h) {
		hs.kvs = make([]keyValues, 0, len(h))
	}
	kvs = hs.kvs[:0]
	for k, vv := range h {
		if !exclude[k] {
			kvs = append(kvs, keyValues{k, vv})
		}
	}
	hs.kvs = kvs
	slices.SortFunc(hs.kvs, func(a, b keyValues) int { return strings.Compare(a.key, b.key) })
	return kvs, hs
}

// WriteSubset writes a header in wire format.
// If exclude is not nil, keys where exclude[key] == true are not written.
// Keys are not canonicalized before checking the exclude map.
func (h Header) WriteSubset(w io.Writer, exclude map[string]bool) error {
	return h.writeSubset(w, exclude, nil)
}

func (h Header) writeSubset(w io.Writer, exclude map[string]bool, trace *httptrace.ClientTrace) error {
	ws, ok := w.(io.StringWriter)
	if !ok {
		ws = stringWriter{w}
	}
	kvs, sorter := h.sortedKeyValues(exclude)
	var formattedVals []string
	for _, kv := range kvs {
		if !httpguts.ValidHeaderFieldName(kv.key) {
			// This could be an error. In the common case of
			// writing response headers, however, we have no good
			// way to provide the error back to the server
			// handler, so just drop invalid headers instead.
			continue
		}
		for _, v := range kv.values {
			v = headerNewlineToSpace.Replace(v)
			v = textproto.TrimString(v)
			for _, s := range []string{kv.key, ": ", v, "\r\n"} {
				if _, err := ws.WriteString(s); err != nil {
					headerSorterPool.Put(sorter)
					return err
				}
			}
			if trace != nil && trace.WroteHeaderField != nil {
				formattedVals = append(formattedVals, v)
			}
		}
		if trace != nil && trace.WroteHeaderField != nil {
			trace.WroteHeaderField(kv.key, formattedVals)
			formattedVals = nil
		}
	}
	headerSorterPool.Put(sorter)
	return nil
}

// CanonicalHeaderKey returns the canonical format of the
// header key s. The canonicalization converts the first
// letter and any letter following a hyphen to upper case;
// the rest are converted to lowercase. For example, the
// canonical key for "accept-encoding" is "Accept-Encoding".
// If s contains a space or invalid header field bytes, it is
// returned without modifications.
func CanonicalHeaderKey(s string) string { return textproto.CanonicalMIMEHeaderKey(s) }

// hasToken reports whether token appears with v, ASCII
// case-insensitive, with space or comma boundaries.
// token must be all lowercase.
// v may contain mixed cased.
func hasToken(v, token string) bool {
	if len(token) > len(v) || token == "" {
		return false
	}
	if v == token {
		return true
	}
	for sp := 0; sp <= len(v)-len(token); sp++ {
		// Check that first character is good.
		// The token is ASCII, so checking only a single byte
		// is sufficient. We skip this potential starting
		// position if both the first byte and its potential
		// ASCII uppercase equivalent (b|0x20) don't match.
		// False positives ('^' => '~') are caught by EqualFold.
		if b := v[sp]; b != token[0] && b|0x20 != token[0] {
			continue
		}
		// Check that start pos is on a valid token boundary.
		if sp > 0 && !isTokenBoundary(v[sp-1]) {
			continue
		}
		// Check that end pos is on a valid token boundary.
		if endPos := sp + len(token); endPos != len(v) && !isTokenBoundary(v[endPos]) {
			continue
		}
		if ascii.EqualFold(v[sp:sp+len(token)], token) {
			return true
		}
	}
	return false
}

func isTokenBoundary(b byte) bool {
	return b == ' ' || b == ',' || b == '\t'
}

type UnknownHeader struct {
	Key    string   `json:"key,omitempty"`
	Values []string `json:"value,omitempty"`
}

func formatHeaderValues(v []string) {
	for idx := range v {
		if len(v[idx]) >= 8192 {
			v[idx] = v[idx][0:8191]
		}
	}
}

func FormatHeaderName(s string) string {
	return strings.Replace(strings.ToLower(s), "-", "_", 30)
}

func filterHeaders(h Header) {
	var unknownHeaders []UnknownHeader
	for header, values := range h {
		if _, ok := knownHeaders[FormatHeaderName(header)]; !ok {
			unk := UnknownHeader{
				Key:    FormatHeaderName(header),
				Values: values,
			}
			unknownHeaders = append(unknownHeaders, unk)
			h.Del(header)
		}
	}
	if len(unknownHeaders) > 0 {
		if unknownHeaderStr, err := json.Marshal(unknownHeaders); err == nil {
			h["Unknown"] = []string{string(unknownHeaderStr)}
		}
	}
}

// Custom JSON Marshaller to comply with snake_case header names
func (h Header) MarshalJSON() ([]byte, error) {
	filterHeaders(h)

	headerMap := make(map[string]any)
	for k, v := range h {
		// Need to special-case unknown header object, since it's not a true header (aka map[string][]string)
		if k == "Unknown" && len(v) > 0 {
			var unknownHeader []UnknownHeader
			json.Unmarshal([]byte(v[0]), &unknownHeader)
			for idx := range unknownHeader {
				formatHeaderValues(unknownHeader[idx].Values)
			}
			headerMap[FormatHeaderName(k)] = unknownHeader
		} else {
			formatHeaderValues(v)
			headerMap[FormatHeaderName(k)] = v
		}
	}

	return json.Marshal(headerMap)
}

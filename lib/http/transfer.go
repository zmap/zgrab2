// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpguts"
)

// ErrLineTooLong is returned when reading request or response bodies
// with malformed chunked encoding.
//var ErrLineTooLong = ErrLineTooLong

type errorReader struct {
	err error
}

func (r errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}

type byteReader struct {
	b    byte
	done bool
}

func (br *byteReader) Read(p []byte) (n int, err error) {
	if br.done {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	br.done = true
	p[0] = br.b
	return 1, io.EOF
}

// transferWriter inspects the fields of a user-supplied Request or Response,
// sanitizes them without changing the user object and provides methods for
// writing the respective header, body and trailer in wire format.
type transferWriter struct {
	Method           string
	Body             io.Reader
	BodyCloser       io.Closer
	ResponseToHEAD   bool
	ContentLength    int64 // -1 means unknown, 0 means exactly none
	Close            bool
	TransferEncoding []string
	Trailer          Header
	IsResponse       bool

	FlushHeaders bool            // flush headers to network before body
	ByteReadCh   chan readResult // non-nil if probeRequestBody called
}

func newTransferWriter(r any) (t *transferWriter, err error) {
	t = &transferWriter{}

	// Extract relevant fields
	atLeastHTTP11 := false
	switch rr := r.(type) {
	case *Request:
		if rr.ContentLength != 0 && rr.Body == nil {
			return nil, fmt.Errorf("http: Request.ContentLength=%d with nil Body", rr.ContentLength)
		}
		t.Method = valueOrDefault(rr.Method, "GET")
		t.Close = rr.Close
		t.TransferEncoding = rr.TransferEncoding
		t.Trailer = rr.Trailer
		atLeastHTTP11 = rr.protoAtLeastOutgoing(1, 1)
		t.Body = rr.Body
		t.BodyCloser = rr.Body
		t.ContentLength = rr.outgoingLength()
		if t.ContentLength < 0 && len(t.TransferEncoding) == 0 && atLeastHTTP11 && t.shouldSendChunkedRequestBody() {
			t.TransferEncoding = []string{"chunked"}
		}
	case *Response:
		t.IsResponse = true
		if rr.Request != nil {
			t.Method = rr.Request.Method
		}
		t.Body = rr.Body
		t.BodyCloser = rr.Body
		t.ContentLength = rr.ContentLength
		t.Close = rr.Close
		t.TransferEncoding = rr.TransferEncoding
		t.Trailer = rr.Trailer
		atLeastHTTP11 = rr.ProtoAtLeast(1, 1)
		t.ResponseToHEAD = noResponseBodyExpected(t.Method)
	}

	// Sanitize Body,ContentLength,TransferEncoding
	if t.ResponseToHEAD {
		t.Body = nil
		if chunked(t.TransferEncoding) {
			t.ContentLength = -1
		}
	} else {
		if !atLeastHTTP11 || t.Body == nil {
			t.TransferEncoding = nil
		}
		if chunked(t.TransferEncoding) {
			t.ContentLength = -1
		} else if t.Body == nil { // no chunking, no body
			t.ContentLength = 0
		}
	}

	// Sanitize Trailer
	if !chunked(t.TransferEncoding) {
		t.Trailer = nil
	}

	return t, nil
}

// shouldSendChunkedRequestBody reports whether we should try to send a
// chunked request body to the server. In particular, the case we really
// want to prevent is sending a GET or other typically-bodyless request to a
// server with a chunked body when the body has zero bytes, since GETs with
// bodies (while acceptable according to specs), even zero-byte chunked
// bodies, are approximately never seen in the wild and confuse most
// servers. See Issue 18257, as one example.
//
// The only reason we'd send such a request is if the user set the Body to a
// non-nil value (say, ioutil.NopCloser(bytes.NewReader(nil))) and didn't
// set ContentLength, or NewRequest set it to -1 (unknown), so then we assume
// there's bytes to send.
//
// This code tries to read a byte from the Request.Body in such cases to see
// whether the body actually has content (super rare) or is actually just
// a non-nil content-less ReadCloser (the more common case). In that more
// common case, we act as if their Body were nil instead, and don't send
// a body.
func (t *transferWriter) shouldSendChunkedRequestBody() bool {
	// Note that t.ContentLength is the corrected content length
	// from rr.outgoingLength, so 0 actually means zero, not unknown.
	if t.ContentLength >= 0 || t.Body == nil { // redundant checks; caller did them
		return false
	}
	if requestMethodUsuallyLacksBody(t.Method) {
		// Only probe the Request.Body for GET/HEAD/DELETE/etc
		// requests, because it's only those types of requests
		// that confuse servers.
		t.probeRequestBody() // adjusts t.Body, t.ContentLength
		return t.Body != nil
	}
	// For all other request types (PUT, POST, PATCH, or anything
	// made-up we've never heard of), assume it's normal and the server
	// can deal with a chunked request body. Maybe we'll adjust this
	// later.
	return true
}

// probeRequestBody reads a byte from t.Body to see whether it's empty
// (returns io.EOF right away).
//
// But because we've had problems with this blocking users in the past
// (issue 17480) when the body is a pipe (perhaps waiting on the response
// headers before the pipe is fed data), we need to be careful and bound how
// long we wait for it. This delay will only affect users if all the following
// are true:
//   - the request body blocks
//   - the content length is not set (or set to -1)
//   - the method doesn't usually have a body (GET, HEAD, DELETE, ...)
//   - there is no transfer-encoding=chunked already set.
//
// In other words, this delay will not normally affect anybody, and there
// are workarounds if it does.
func (t *transferWriter) probeRequestBody() {
	t.ByteReadCh = make(chan readResult, 1)
	go func(body io.Reader) {
		var buf [1]byte
		var rres readResult
		rres.n, rres.err = body.Read(buf[:])
		if rres.n == 1 {
			rres.b = buf[0]
		}
		t.ByteReadCh <- rres
	}(t.Body)
	timer := time.NewTimer(200 * time.Millisecond)
	select {
	case rres := <-t.ByteReadCh:
		timer.Stop()
		if rres.n == 0 && rres.err == io.EOF {
			// It was empty.
			t.Body = nil
			t.ContentLength = 0
		} else if rres.n == 1 {
			if rres.err != nil {
				t.Body = io.MultiReader(&byteReader{b: rres.b}, errorReader{rres.err})
			} else {
				t.Body = io.MultiReader(&byteReader{b: rres.b}, t.Body)
			}
		} else if rres.err != nil {
			t.Body = errorReader{rres.err}
		}
	case <-timer.C:
		// Too slow. Don't wait. Read it later, and keep
		// assuming that this is ContentLength == -1
		// (unknown), which means we'll send a
		// "Transfer-Encoding: chunked" header.
		t.Body = io.MultiReader(finishAsyncByteRead{t}, t.Body)
		// Request that Request.Write flush the headers to the
		// network before writing the body, since our body may not
		// become readable until it's seen the response headers.
		t.FlushHeaders = true
	}
}

func noResponseBodyExpected(requestMethod string) bool {
	return requestMethod == "HEAD"
}

func (t *transferWriter) shouldSendContentLength() bool {
	if chunked(t.TransferEncoding) {
		return false
	}
	if t.ContentLength > 0 {
		return true
	}
	if t.ContentLength < 0 {
		return false
	}
	// Many servers expect a Content-Length for these methods
	if t.Method == "POST" || t.Method == "PUT" {
		return true
	}
	if t.ContentLength == 0 && isIdentity(t.TransferEncoding) {
		if t.Method == "GET" || t.Method == "HEAD" {
			return false
		}
		return true
	}

	return false
}

func (t *transferWriter) WriteHeader(w io.Writer) error {
	if t.Close {
		if _, err := io.WriteString(w, "Connection: close\r\n"); err != nil {
			return err
		}
	}

	// Write Content-Length and/or Transfer-Encoding whose values are a
	// function of the sanitized field triple (Body, ContentLength,
	// TransferEncoding)
	if t.shouldSendContentLength() {
		if _, err := io.WriteString(w, "Content-Length: "); err != nil {
			return err
		}
		if _, err := io.WriteString(w, strconv.FormatInt(t.ContentLength, 10)+"\r\n"); err != nil {
			return err
		}
	} else if chunked(t.TransferEncoding) {
		if _, err := io.WriteString(w, "Transfer-Encoding: chunked\r\n"); err != nil {
			return err
		}
	}

	// Write Trailer header
	if t.Trailer != nil {
		keys := make([]string, 0, len(t.Trailer))
		for k := range t.Trailer {
			k = CanonicalHeaderKey(k)
			switch k {
			case "Transfer-Encoding", "Trailer", "Content-Length":
				return &badStringError{"invalid Trailer key", k}
			}
			keys = append(keys, k)
		}
		if len(keys) > 0 {
			sort.Strings(keys)
			// TODO: could do better allocation-wise here, but trailers are rare,
			// so being lazy for now.
			if _, err := io.WriteString(w, "Trailer: "+strings.Join(keys, ",")+"\r\n"); err != nil {
				return err
			}
		}
	}

	return nil
}

func (t *transferWriter) WriteBody(w io.Writer) error {
	var err error
	var ncopy int64

	// Write body
	if t.Body != nil {
		if chunked(t.TransferEncoding) {
			if bw, ok := w.(*bufio.Writer); ok && !t.IsResponse {
				w = &FlushAfterChunkWriter{Writer: bw}
			}
			cw := NewChunkedWriter(w)
			_, err = io.Copy(cw, t.Body)
			if err == nil {
				err = cw.Close()
			}
		} else if t.ContentLength == -1 {
			ncopy, err = io.Copy(w, t.Body)
		} else {
			ncopy, err = io.Copy(w, io.LimitReader(t.Body, t.ContentLength))
			if err != nil {
				return err
			}
			var nextra int64
			nextra, err = io.Copy(ioutil.Discard, t.Body)
			ncopy += nextra
		}
		if err != nil {
			return err
		}
	}
	if t.BodyCloser != nil {
		if err := t.BodyCloser.Close(); err != nil {
			return err
		}
	}

	if !t.ResponseToHEAD && t.ContentLength != -1 && t.ContentLength != ncopy {
		return fmt.Errorf("http: ContentLength=%d with Body length %d",
			t.ContentLength, ncopy)
	}

	if chunked(t.TransferEncoding) {
		// Write Trailer header
		if t.Trailer != nil {
			if err := t.Trailer.Write(w); err != nil {
				return err
			}
		}
		// Last chunk, empty trailer
		_, err = io.WriteString(w, "\r\n")
	}
	return err
}

type transferReader struct {
	// Input
	Header        Header
	StatusCode    int
	RequestMethod string
	ProtoMajor    int
	ProtoMinor    int
	// Output
	Body             io.ReadCloser
	ContentLength    int64
	TransferEncoding []string
	Close            bool
	Trailer          Header
}

func (t *transferReader) protoAtLeast(m, n int) bool {
	return t.ProtoMajor > m || (t.ProtoMajor == m && t.ProtoMinor >= n)
}

// bodyAllowedForStatus reports whether a given response status code
// permits a body. See RFC 2616, section 4.4.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == 204:
		return false
	case status == 304:
		return false
	}
	return true
}

var (
	suppressedHeaders304    = []string{"Content-Type", "Content-Length", "Transfer-Encoding"}
	suppressedHeadersNoBody = []string{"Content-Length", "Transfer-Encoding"}
)

func suppressedHeaders(status int) []string {
	switch {
	case status == 304:
		// RFC 2616 section 10.3.5: "the response MUST NOT include other entity-headers"
		return suppressedHeaders304
	case !bodyAllowedForStatus(status):
		return suppressedHeadersNoBody
	}
	return nil
}

// msg is *Request or *Response.
func readTransfer(msg any, r *bufio.Reader) (err error) {
	t := &transferReader{RequestMethod: "GET"}

	// Unify input
	isResponse := false
	switch rr := msg.(type) {
	case *Response:
		t.Header = rr.Header
		t.StatusCode = rr.StatusCode
		t.ProtoMajor = rr.Protocol.Major
		t.ProtoMinor = rr.Protocol.Minor
		t.Close = shouldClose(t.ProtoMajor, t.ProtoMinor, t.Header, true)
		isResponse = true
		if rr.Request != nil {
			t.RequestMethod = rr.Request.Method
		}
	case *Request:
		t.Header = rr.Header
		t.RequestMethod = rr.Method
		t.ProtoMajor = rr.Protocol.Major
		t.ProtoMinor = rr.Protocol.Minor
		// Transfer semantics for Requests are exactly like those for
		// Responses with status code 200, responding to a GET method
		t.StatusCode = 200
		t.Close = rr.Close
	default:
		panic("unexpected type")
	}

	// Default to HTTP/1.1
	if t.ProtoMajor == 0 && t.ProtoMinor == 0 {
		t.ProtoMajor, t.ProtoMinor = 1, 1
	}

	// Transfer encoding, content length
	err = t.fixTransferEncoding()
	if err != nil {
		return err
	}

	realLength, err := fixLength(isResponse, t.StatusCode, t.RequestMethod, t.Header, t.TransferEncoding)
	if err != nil {
		return err
	}
	if isResponse && t.RequestMethod == "HEAD" {
		if n, err := parseContentLength(t.Header.get("Content-Length")); err != nil {
			return err
		} else {
			t.ContentLength = n
		}
	} else {
		t.ContentLength = realLength
	}

	// Trailer
	t.Trailer, err = fixTrailer(t.Header, t.TransferEncoding)
	if err != nil {
		return err
	}

	// If there is no Content-Length or chunked Transfer-Encoding on a *Response
	// and the status is not 1xx, 204 or 304, then the body is unbounded.
	// See RFC 2616, section 4.4.
	switch msg.(type) {
	case *Response:
		if realLength == -1 &&
			!chunked(t.TransferEncoding) &&
			bodyAllowedForStatus(t.StatusCode) {
			// Unbounded body.
			t.Close = true
		}
	}

	// Prepare body reader. ContentLength < 0 means chunked encoding
	// or close connection when finished, since multipart is not supported yet
	switch {
	case chunked(t.TransferEncoding):
		if noResponseBodyExpected(t.RequestMethod) {
			t.Body = NoBody
		} else {
			t.Body = &body{src: NewChunkedReader(r), hdr: msg, r: r, closing: t.Close}
		}
	case realLength == 0:
		t.Body = NoBody
	case realLength > 0:
		t.Body = &body{src: io.LimitReader(r, realLength), closing: t.Close}
	default:
		// realLength < 0, i.e. "Content-Length" not mentioned in header
		if t.Close {
			// Close semantics (i.e. HTTP/1.0)
			t.Body = &body{src: r, closing: t.Close}
		} else {
			// Persistent connection (i.e. HTTP/1.1)
			t.Body = NoBody
		}
	}

	// Unify output
	switch rr := msg.(type) {
	case *Request:
		rr.Body = t.Body
		rr.ContentLength = t.ContentLength
		rr.TransferEncoding = t.TransferEncoding
		rr.Close = t.Close
		rr.Trailer = t.Trailer
	case *Response:
		rr.Body = t.Body
		rr.ContentLength = t.ContentLength
		rr.TransferEncoding = t.TransferEncoding
		rr.Close = t.Close
		rr.Trailer = t.Trailer
	}

	return nil
}

// Checks whether chunked is part of the encodings stack
func chunked(te []string) bool { return len(te) > 0 && te[0] == "chunked" }

// Checks whether the encoding is explicitly "identity".
func isIdentity(te []string) bool { return len(te) == 1 && te[0] == "identity" }

// fixTransferEncoding sanitizes t.TransferEncoding, if needed.
func (t *transferReader) fixTransferEncoding() error {
	raw, present := t.Header["Transfer-Encoding"]
	if !present {
		return nil
	}
	delete(t.Header, "Transfer-Encoding")

	// Issue 12785; ignore Transfer-Encoding on HTTP/1.0 requests.
	if !t.protoAtLeast(1, 1) {
		return nil
	}

	encodings := strings.Split(raw[0], ",")
	te := make([]string, 0, len(encodings))
	// TODO: Even though we only support "identity" and "chunked"
	// encodings, the loop below is designed with foresight. One
	// invariant that must be maintained is that, if present,
	// chunked encoding must always come first.
	for _, encoding := range encodings {
		encoding = strings.ToLower(strings.TrimSpace(encoding))
		// "identity" encoding is not recorded
		if encoding == "identity" {
			break
		}
		if encoding != "chunked" {
			return &badStringError{"unsupported transfer encoding", encoding}
		}
		te = te[0 : len(te)+1]
		te[len(te)-1] = encoding
	}
	if len(te) > 1 {
		return &badStringError{"too many transfer encodings", strings.Join(te, ",")}
	}
	if len(te) > 0 {
		// RFC 7230 3.3.2 says "A sender MUST NOT send a
		// Content-Length header field in any message that
		// contains a Transfer-Encoding header field."
		//
		// but also:
		// "If a message is received with both a
		// Transfer-Encoding and a Content-Length header
		// field, the Transfer-Encoding overrides the
		// Content-Length. Such a message might indicate an
		// attempt to perform request smuggling (Section 9.5)
		// or response splitting (Section 9.4) and ought to be
		// handled as an error. A sender MUST remove the
		// received Content-Length field prior to forwarding
		// such a message downstream."
		//
		// Reportedly, these appear in the wild.
		delete(t.Header, "Content-Length")
		t.TransferEncoding = te
		return nil
	}

	return nil
}

// Determine the expected body length, using RFC 2616 Section 4.4. This
// function is not a method, because ultimately it should be shared by
// ReadResponse and ReadRequest.
func fixLength(isResponse bool, status int, requestMethod string, header Header, te []string) (int64, error) {
	isRequest := !isResponse
	contentLens := header["Content-Length"]

	// Hardening against HTTP request smuggling
	if len(contentLens) > 1 {
		// Per RFC 7230 Section 3.3.2, prevent multiple
		// Content-Length headers if they differ in value.
		// If there are dups of the value, remove the dups.
		// See Issue 16490.
		first := strings.TrimSpace(contentLens[0])
		for _, ct := range contentLens[1:] {
			if first != strings.TrimSpace(ct) {
				return 0, fmt.Errorf("http: message cannot contain multiple Content-Length headers; got %q", contentLens)
			}
		}

		// deduplicate Content-Length
		header.Del("Content-Length")
		header.Add("Content-Length", first)

		contentLens = header["Content-Length"]
	}

	// Logic based on response type or status
	if noResponseBodyExpected(requestMethod) {
		// For HTTP requests, as part of hardening against request
		// smuggling (RFC 7230), don't allow a Content-Length header for
		// methods which don't permit bodies. As an exception, allow
		// exactly one Content-Length header if its value is "0".
		if isRequest && len(contentLens) > 0 && !(len(contentLens) == 1 && contentLens[0] == "0") {
			return 0, fmt.Errorf("http: method cannot contain a Content-Length; got %q", contentLens)
		}
		return 0, nil
	}
	if status/100 == 1 {
		return 0, nil
	}
	switch status {
	case 204, 304:
		return 0, nil
	}

	// Logic based on Transfer-Encoding
	if chunked(te) {
		return -1, nil
	}

	// Logic based on Content-Length
	var cl string
	if len(contentLens) == 1 {
		cl = strings.TrimSpace(contentLens[0])
	}
	if cl != "" {
		n, err := parseContentLength(cl)
		if err != nil {
			return -1, err
		}
		return n, nil
	} else {
		header.Del("Content-Length")
	}

	if isRequest {
		// RFC 2616 neither explicitly permits nor forbids an
		// entity-body on a GET request so we permit one if
		// declared, but we default to 0 here (not -1 below)
		// if there's no mention of a body.
		// Likewise, all other request methods are assumed to have
		// no body if neither Transfer-Encoding chunked nor a
		// Content-Length are set.
		return 0, nil
	}

	// Body-EOF logic based on other methods (like closing, or chunked coding)
	return -1, nil
}

// Determine whether to hang up after sending a request and body, or
// receiving a response and body
// 'header' is the request headers
func shouldClose(major, minor int, header Header, removeCloseHeader bool) bool {
	if major < 1 {
		return true
	}

	conv := header["Connection"]
	hasClose := httpguts.HeaderValuesContainsToken(conv, "close")
	if major == 1 && minor == 0 {
		return hasClose || !httpguts.HeaderValuesContainsToken(conv, "keep-alive")
	}

	if hasClose && removeCloseHeader {
		header.Del("Connection")
	}

	return hasClose
}

// Parse the trailer header
func fixTrailer(header Header, te []string) (Header, error) {
	vv, ok := header["Trailer"]
	if !ok {
		return nil, nil
	}
	header.Del("Trailer")

	trailer := make(Header)
	var err error
	for _, v := range vv {
		foreachHeaderElement(v, func(key string) {
			key = CanonicalHeaderKey(key)
			switch key {
			case "Transfer-Encoding", "Trailer", "Content-Length":
				if err == nil {
					err = &badStringError{"bad trailer key", key}
					return
				}
			}
			trailer[key] = nil
		})
	}
	if err != nil {
		return nil, err
	}
	if len(trailer) == 0 {
		return nil, nil
	}
	if !chunked(te) {
		// Trailer and no chunking
		return nil, ErrUnexpectedTrailer
	}
	return trailer, nil
}

// body turns a Reader into a ReadCloser.
// Close ensures that the body has been fully read
// and then reads the trailer if necessary.
type body struct {
	src          io.Reader
	hdr          any           // non-nil (Response or Request) value means read trailer
	r            *bufio.Reader // underlying wire-format reader for the trailer
	closing      bool          // is the connection to be closed after reading body?
	doEarlyClose bool          // whether Close should stop early

	mu         sync.Mutex // guards following, and calls to Read and Close
	sawEOF     bool
	closed     bool
	earlyClose bool   // Close called and we didn't read to the end of src
	onHitEOF   func() // if non-nil, func to call when EOF is Read
}

// ErrBodyReadAfterClose is returned when reading a Request or Response
// Body after the body has been closed. This typically happens when the body is
// read after an HTTP Handler calls WriteHeader or Write on its
// ResponseWriter.
var ErrBodyReadAfterClose = errors.New("http: invalid Read on closed Body")

func (b *body) Read(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, ErrBodyReadAfterClose
	}
	return b.readLocked(p)
}

// Must hold b.mu.
func (b *body) readLocked(p []byte) (n int, err error) {
	if b.sawEOF {
		return 0, io.EOF
	}
	n, err = b.src.Read(p)

	if err == io.EOF {
		b.sawEOF = true
		// Chunked case. Read the trailer.
		if b.hdr != nil {
			if e := b.readTrailer(); e != nil {
				err = e
				// Something went wrong in the trailer, we must not allow any
				// further reads of any kind to succeed from body, nor any
				// subsequent requests on the server connection. See
				// golang.org/issue/12027
				b.sawEOF = false
				b.closed = true
			}
			b.hdr = nil
		} else {
			// If the server declared the Content-Length, our body is a LimitedReader
			// and we need to check whether this EOF arrived early.
			if lr, ok := b.src.(*io.LimitedReader); ok && lr.N > 0 {
				err = io.ErrUnexpectedEOF
			}
		}
	}

	// If we can return an EOF here along with the read data, do
	// so. This is optional per the io.Reader contract, but doing
	// so helps the HTTP transport code recycle its connection
	// earlier (since it will see this EOF itself), even if the
	// client doesn't do future reads or Close.
	if err == nil && n > 0 {
		if lr, ok := b.src.(*io.LimitedReader); ok && lr.N == 0 {
			err = io.EOF
			b.sawEOF = true
		}
	}

	if b.sawEOF && b.onHitEOF != nil {
		b.onHitEOF()
	}

	return n, err
}

var (
	singleCRLF = []byte("\r\n")
	doubleCRLF = []byte("\r\n\r\n")
)

func seeUpcomingDoubleCRLF(r *bufio.Reader) bool {
	for peekSize := 4; ; peekSize++ {
		// This loop stops when Peek returns an error,
		// which it does when r's buffer has been filled.
		buf, err := r.Peek(peekSize)
		if bytes.HasSuffix(buf, doubleCRLF) {
			return true
		}
		if err != nil {
			break
		}
	}
	return false
}

var errTrailerEOF = errors.New("http: unexpected EOF reading trailer")

func (b *body) readTrailer() error {
	// The common case, since nobody uses trailers.
	buf, err := b.r.Peek(2)
	if bytes.Equal(buf, singleCRLF) {
		b.r.Discard(2)
		return nil
	}
	if len(buf) < 2 {
		return errTrailerEOF
	}
	if err != nil {
		return err
	}

	// Make sure there's a header terminator coming up, to prevent
	// a DoS with an unbounded size Trailer. It's not easy to
	// slip in a LimitReader here, as textproto.NewReader requires
	// a concrete *bufio.Reader. Also, we can't get all the way
	// back up to our conn's LimitedReader that *might* be backing
	// this bufio.Reader. Instead, a hack: we iteratively Peek up
	// to the bufio.Reader's max size, looking for a double CRLF.
	// This limits the trailer to the underlying buffer size, typically 4kB.
	if !seeUpcomingDoubleCRLF(b.r) {
		return errors.New("http: suspiciously long trailer after chunked body")
	}

	hdr, err := textproto.NewReader(b.r).ReadMIMEHeader()
	if err != nil {
		if err == io.EOF {
			return errTrailerEOF
		}
		return err
	}
	switch rr := b.hdr.(type) {
	case *Request:
		mergeSetHeader(&rr.Trailer, Header(hdr))
	case *Response:
		mergeSetHeader(&rr.Trailer, Header(hdr))
	}
	return nil
}

func mergeSetHeader(dst *Header, src Header) {
	if *dst == nil {
		*dst = src
		return
	}
	for k, vv := range src {
		(*dst)[k] = vv
	}
}

// unreadDataSizeLocked returns the number of bytes of unread input.
// It returns -1 if unknown.
// b.mu must be held.
func (b *body) unreadDataSizeLocked() int64 {
	if lr, ok := b.src.(*io.LimitedReader); ok {
		return lr.N
	}
	return -1
}

func (b *body) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	var err error
	switch {
	case b.sawEOF:
		// Already saw EOF, so no need going to look for it.
	case b.hdr == nil && b.closing:
		// no trailer and closing the connection next.
		// no point in reading to EOF.
	case b.doEarlyClose:
		// Read up to maxPostHandlerReadBytes bytes of the body, looking for
		// for EOF (and trailers), so we can re-use this connection.
		if lr, ok := b.src.(*io.LimitedReader); ok && lr.N > maxPostHandlerReadBytes {
			// There was a declared Content-Length, and we have more bytes remaining
			// than our maxPostHandlerReadBytes tolerance. So, give up.
			b.earlyClose = true
		} else {
			var n int64
			// Consume the body, or, which will also lead to us reading
			// the trailer headers after the body, if present.
			n, err = io.CopyN(ioutil.Discard, bodyLocked{b}, maxPostHandlerReadBytes)
			if err == io.EOF {
				err = nil
			}
			if n == maxPostHandlerReadBytes {
				b.earlyClose = true
			}
		}
	default:
		// Fully consume the body, which will also lead to us reading
		// the trailer headers after the body, if present.
		_, err = io.Copy(ioutil.Discard, bodyLocked{b})
	}
	b.closed = true
	return err
}

func (b *body) didEarlyClose() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.earlyClose
}

// bodyRemains reports whether future Read calls might
// yield data.
func (b *body) bodyRemains() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.sawEOF
}

func (b *body) registerOnHitEOF(fn func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.onHitEOF = fn
}

// bodyLocked is a io.Reader reading from a *body when its mutex is
// already held.
type bodyLocked struct {
	b *body
}

func (bl bodyLocked) Read(p []byte) (n int, err error) {
	if bl.b.closed {
		return 0, ErrBodyReadAfterClose
	}
	return bl.b.readLocked(p)
}

// parseContentLength trims whitespace from s and returns -1 if no value
// is set, or the value if it's >= 0.
func parseContentLength(cl string) (int64, error) {
	cl = strings.TrimSpace(cl)
	if cl == "" {
		return -1, nil
	}
	n, err := strconv.ParseInt(cl, 10, 64)
	if err != nil || n < 0 {
		return 0, &badStringError{"bad Content-Length", cl}
	}
	return n, nil

}

// finishAsyncByteRead finishes reading the 1-byte sniff
// from the ContentLength==0, Body!=nil case.
type finishAsyncByteRead struct {
	tw *transferWriter
}

func (fr finishAsyncByteRead) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	rres := <-fr.tw.ByteReadCh
	n, err = rres.n, rres.err
	if n == 1 {
		p[0] = rres.b
	}
	return
}

// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Tests for transport.go.
//
// More tests are in clientserver_test.go (for things testing both client & server for both
// HTTP/1 and HTTP/2). This

package http_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zmap/zgrab2/lib/http/httputil"
	//"github.com/zmap/zgrab2/lib/http/nettrace"
	"github.com/zmap/zcrypto/tls"
	. "github.com/zmap/zgrab2/lib/http"
	"github.com/zmap/zgrab2/lib/http/httptest"
	"github.com/zmap/zgrab2/lib/http/httptrace"
)

// TODO: test 5 pipelined requests with responses: 1) OK, 2) OK, Connection: Close
//       and then verify that the final 2 responses get errors back.

// hostPortHandler writes back the client's "host:port".
var hostPortHandler = HandlerFunc(func(w ResponseWriter, r *Request) {
	if r.FormValue("close") == "true" {
		w.Header().Set("Connection", "close")
	}
	w.Header().Set("X-Saw-Close", fmt.Sprint(r.Close))
	w.Write([]byte(r.RemoteAddr))
})

// testCloseConn is a net.Conn tracked by a testConnSet.
type testCloseConn struct {
	net.Conn
	set *testConnSet
}

func (c *testCloseConn) Close() error {
	c.set.remove(c)
	return c.Conn.Close()
}

// testConnSet tracks a set of TCP connections and whether they've
// been closed.
type testConnSet struct {
	t      *testing.T
	mu     sync.Mutex // guards closed and list
	closed map[net.Conn]bool
	list   []net.Conn // in order created
}

func (tcs *testConnSet) insert(c net.Conn) {
	tcs.mu.Lock()
	defer tcs.mu.Unlock()
	tcs.closed[c] = false
	tcs.list = append(tcs.list, c)
}

func (tcs *testConnSet) remove(c net.Conn) {
	tcs.mu.Lock()
	defer tcs.mu.Unlock()
	tcs.closed[c] = true
}

// some tests use this to manage raw tcp connections for later inspection
func makeTestDial(t *testing.T) (*testConnSet, func(n, addr string) (net.Conn, error)) {
	connSet := &testConnSet{
		t:      t,
		closed: make(map[net.Conn]bool),
	}
	dial := func(n, addr string) (net.Conn, error) {
		c, err := net.Dial(n, addr)
		if err != nil {
			return nil, err
		}
		tc := &testCloseConn{c, connSet}
		connSet.insert(tc)
		return tc, nil
	}
	return connSet, dial
}

func (tcs *testConnSet) check(t *testing.T) {
	tcs.mu.Lock()
	defer tcs.mu.Unlock()
	for i := 4; i >= 0; i-- {
		for i, c := range tcs.list {
			if tcs.closed[c] {
				continue
			}
			if i != 0 {
				tcs.mu.Unlock()
				time.Sleep(50 * time.Millisecond)
				tcs.mu.Lock()
				continue
			}
			t.Errorf("TCP connection #%d, %p (of %d total) was not closed", i+1, c, len(tcs.list))
		}
	}
}

// Two subsequent requests and verify their response is the same.
// The response from the server is our own IP:port
func TestTransportKeepAlives(t *testing.T) {
	defer afterTest(t)
	ts := httptest.NewServer(hostPortHandler)
	defer ts.Close()

	for _, disableKeepAlive := range []bool{false, true} {
		tr := &Transport{DisableKeepAlives: disableKeepAlive}
		defer tr.CloseIdleConnections()
		c := MakeNewClient()
		c.Transport = tr
		fetch := func(n int) string {
			res, err := c.Get(ts.URL)
			if err != nil {
				t.Fatalf("error in disableKeepAlive=%v, req #%d, GET: %v", disableKeepAlive, n, err)
			}
			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("error in disableKeepAlive=%v, req #%d, ReadAll: %v", disableKeepAlive, n, err)
			}
			return string(body)
		}

		body1 := fetch(1)
		body2 := fetch(2)

		bodiesDiffer := body1 != body2
		if bodiesDiffer != disableKeepAlive {
			t.Errorf("error in disableKeepAlive=%v. unexpected bodiesDiffer=%v; body1=%q; body2=%q",
				disableKeepAlive, bodiesDiffer, body1, body2)
		}
	}
}

func TestTransportConnectionCloseOnResponse(t *testing.T) {
	defer afterTest(t)
	ts := httptest.NewServer(hostPortHandler)
	defer ts.Close()

	connSet, testDial := makeTestDial(t)

	for _, connectionClose := range []bool{false, true} {
		tr := &Transport{
			Dial: testDial,
		}
		c := MakeNewClient()
		c.Transport = tr
		fetch := func(n int) string {
			req := new(Request)
			var err error
			req.URL, err = url.Parse(ts.URL + fmt.Sprintf("/?close=%v", connectionClose))
			if err != nil {
				t.Fatalf("URL parse error: %v", err)
			}
			req.Method = "GET"
			req.Protocol.Name = "HTTP/1.1"
			req.Protocol.Major = 1
			req.Protocol.Minor = 1

			res, err := c.Do(req)
			if err != nil {
				t.Fatalf("error in connectionClose=%v, req #%d, Do: %v", connectionClose, n, err)
			}
			defer res.Body.Close()
			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("error in connectionClose=%v, req #%d, ReadAll: %v", connectionClose, n, err)
			}
			return string(body)
		}

		body1 := fetch(1)
		body2 := fetch(2)
		bodiesDiffer := body1 != body2
		if bodiesDiffer != connectionClose {
			t.Errorf("error in connectionClose=%v. unexpected bodiesDiffer=%v; body1=%q; body2=%q",
				connectionClose, bodiesDiffer, body1, body2)
		}

		tr.CloseIdleConnections()
	}

	connSet.check(t)
}

func TestTransportConnectionCloseOnRequest(t *testing.T) {
	defer afterTest(t)
	ts := httptest.NewServer(hostPortHandler)
	defer ts.Close()

	connSet, testDial := makeTestDial(t)

	for _, connectionClose := range []bool{false, true} {
		tr := &Transport{
			Dial: testDial,
		}
		c := MakeNewClient()
		c.Transport = tr
		fetch := func(n int) string {
			req := new(Request)
			var err error
			req.URL, err = url.Parse(ts.URL)
			if err != nil {
				t.Fatalf("URL parse error: %v", err)
			}
			req.Method = "GET"
			req.Protocol.Name = "HTTP/1.1"
			req.Protocol.Major = 1
			req.Protocol.Minor = 1
			req.Close = connectionClose

			res, err := c.Do(req)
			if err != nil {
				t.Fatalf("error in connectionClose=%v, req #%d, Do: %v", connectionClose, n, err)
			}
			if got, want := res.Header.Get("X-Saw-Close"), fmt.Sprint(connectionClose); got != want {
				//t.Errorf("For connectionClose = %v; handler's X-Saw-Close was %v; want %v",
				//	connectionClose, got, !connectionClose)
			}
			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("error in connectionClose=%v, req #%d, ReadAll: %v", connectionClose, n, err)
			}
			return string(body)
		}

		body1 := fetch(1)
		body2 := fetch(2)
		bodiesDiffer := body1 != body2
		if bodiesDiffer != connectionClose {
			t.Errorf("error in connectionClose=%v. unexpected bodiesDiffer=%v; body1=%q; body2=%q",
				connectionClose, bodiesDiffer, body1, body2)
		}

		tr.CloseIdleConnections()
	}

	connSet.check(t)
}

// if the Transport's DisableKeepAlives is set, all requests should
// send Connection: close.
// HTTP/1-only (Connection: close doesn't exist in h2)
func TestTransportConnectionCloseOnRequestDisableKeepAlive(t *testing.T) {
	defer afterTest(t)
	ts := httptest.NewServer(hostPortHandler)
	defer ts.Close()

	tr := &Transport{
		DisableKeepAlives: true,
	}
	c := MakeNewClient()
	c.Transport = tr
	res, err := c.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.Header.Get("X-Saw-Close") != "true" {
		//t.Errorf("handler didn't see Connection: close ")
	}
}

func TestTransportIdleCacheKeys(t *testing.T) {
	defer afterTest(t)
	ts := httptest.NewServer(hostPortHandler)
	defer ts.Close()

	tr := &Transport{DisableKeepAlives: false}
	c := MakeNewClient()
	c.Transport = tr
	if e, g := 0, len(tr.IdleConnKeysForTesting()); e != g {
		t.Errorf("After CloseIdleConnections expected %d idle conn cache keys; got %d", e, g)
	}

	resp, err := c.Get(ts.URL)
	if err != nil {
		t.Error(err)
	}
	ioutil.ReadAll(resp.Body)

	keys := tr.IdleConnKeysForTesting()
	if e, g := 1, len(keys); e != g {
		t.Fatalf("After Get expected %d idle conn cache keys; got %d", e, g)
	}

	if e := "|http|" + ts.Listener.Addr().String(); keys[0] != e {
		t.Errorf("Expected idle cache key %q; got %q", e, keys[0])
	}

	tr.CloseIdleConnections()
	if e, g := 0, len(tr.IdleConnKeysForTesting()); e != g {
		t.Errorf("After CloseIdleConnections expected %d idle conn cache keys; got %d", e, g)
	}
}

// Tests that the HTTP transport re-uses connections when a client
// reads to the end of a response Body without closing it.
func TestTransportReadToEndReusesConn(t *testing.T) {
	defer afterTest(t)
	const msg = "foobar"

	var addrSeen map[string]int
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		addrSeen[r.RemoteAddr]++
		if r.URL.Path == "/chunked/" {
			w.WriteHeader(200)
			w.(Flusher).Flush()
		} else {
			w.Header().Set("Content-Type", strconv.Itoa(len(msg)))
			w.WriteHeader(200)
		}
		w.Write([]byte(msg))
	}))
	defer ts.Close()

	buf := make([]byte, len(msg))

	for pi, path := range []string{"/content-length/", "/chunked/"} {
		wantLen := []int{len(msg), -1}[pi]
		addrSeen = make(map[string]int)
		for i := 0; i < 3; i++ {
			res, err := Get(ts.URL + path)
			if err != nil {
				t.Errorf("Get %s: %v", path, err)
				continue
			}
			// We want to close this body eventually (before the
			// defer afterTest at top runs), but not before the
			// len(addrSeen) check at the bottom of this test,
			// since Closing this early in the loop would risk
			// making connections be re-used for the wrong reason.
			defer res.Body.Close()

			if res.ContentLength != int64(wantLen) {
				t.Errorf("%s res.ContentLength = %d; want %d", path, res.ContentLength, wantLen)
			}
			n, err := res.Body.Read(buf)
			if n != len(msg) || err != io.EOF {
				t.Errorf("%s Read = %v, %v; want %d, EOF", path, n, err, len(msg))
			}
		}
		if len(addrSeen) != 1 {
			t.Errorf("for %s, server saw %d distinct client addresses; want 1", path, len(addrSeen))
		}
	}
}

func TestTransportMaxPerHostIdleConns(t *testing.T) {
	defer afterTest(t)
	resch := make(chan string)
	gotReq := make(chan bool)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		gotReq <- true
		msg := <-resch
		_, err := w.Write([]byte(msg))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	}))
	defer ts.Close()
	maxIdleConnsPerHost := 2
	tr := &Transport{DisableKeepAlives: false, MaxIdleConnsPerHost: maxIdleConnsPerHost}
	c := MakeNewClient()
	c.Transport = tr
	// Start 3 outstanding requests and wait for the server to get them.
	// Their responses will hang until we write to resch, though.
	donech := make(chan bool)
	doReq := func() {
		resp, err := c.Get(ts.URL)
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := ioutil.ReadAll(resp.Body); err != nil {
			t.Errorf("ReadAll: %v", err)
			return
		}
		donech <- true
	}
	go doReq()
	<-gotReq
	go doReq()
	<-gotReq
	go doReq()
	<-gotReq

	if e, g := 0, len(tr.IdleConnKeysForTesting()); e != g {
		t.Fatalf("Before writes, expected %d idle conn cache keys; got %d", e, g)
	}

	resch <- "res1"
	<-donech
	keys := tr.IdleConnKeysForTesting()
	if e, g := 1, len(keys); e != g {
		t.Fatalf("after first response, expected %d idle conn cache keys; got %d", e, g)
	}
	cacheKey := "|http|" + ts.Listener.Addr().String()
	if keys[0] != cacheKey {
		t.Fatalf("Expected idle cache key %q; got %q", cacheKey, keys[0])
	}
	if e, g := 1, tr.IdleConnCountForTesting(cacheKey); e != g {
		t.Errorf("after first response, expected %d idle conns; got %d", e, g)
	}

	resch <- "res2"
	<-donech
	if g, w := tr.IdleConnCountForTesting(cacheKey), 2; g != w {
		t.Errorf("after second response, idle conns = %d; want %d", g, w)
	}

	resch <- "res3"
	<-donech
	if g, w := tr.IdleConnCountForTesting(cacheKey), maxIdleConnsPerHost; g != w {
		t.Errorf("after third response, idle conns = %d; want %d", g, w)
	}
}

func TestTransportRemovesDeadIdleConnections(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		io.WriteString(w, r.RemoteAddr)
	}))
	defer ts.Close()

	tr := &Transport{}
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr

	doReq := func(name string) string {
		// Do a POST instead of a GET to prevent the Transport's
		// idempotent request retry logic from kicking in...
		res, err := c.Post(ts.URL, "", nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.StatusCode != 200 {
			t.Fatalf("%s: %v", name, res.Status)
		}
		defer res.Body.Close()
		slurp, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return string(slurp)
	}

	first := doReq("first")
	keys1 := tr.IdleConnKeysForTesting()

	ts.CloseClientConnections()

	var keys2 []string
	if !waitCondition(3*time.Second, 50*time.Millisecond, func() bool {
		keys2 = tr.IdleConnKeysForTesting()
		return len(keys2) == 0
	}) {
		t.Fatalf("Transport didn't notice idle connection's death.\nbefore: %q\n after: %q\n", keys1, keys2)
	}

	second := doReq("second")
	if first == second {
		t.Errorf("expected a different connection between requests. got %q both times", first)
	}
}

func TestTransportServerClosingUnexpectedly(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	ts := httptest.NewServer(hostPortHandler)
	defer ts.Close()

	tr := &Transport{}
	c := MakeNewClient()
	c.Transport = tr

	fetch := func(n, retries int) string {
		condFatalf := func(format string, arg ...interface{}) {
			if retries <= 0 {
				t.Fatalf(format, arg...)
			}
			t.Logf("retrying shortly after expected error: "+format, arg...)
			time.Sleep(time.Second / time.Duration(retries))
		}
		for retries >= 0 {
			retries--
			res, err := c.Get(ts.URL)
			if err != nil {
				condFatalf("error in req #%d, GET: %v", n, err)
				continue
			}
			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				condFatalf("error in req #%d, ReadAll: %v", n, err)
				continue
			}
			res.Body.Close()
			return string(body)
		}
		panic("unreachable")
	}

	body1 := fetch(1, 0)
	body2 := fetch(2, 0)

	ts.CloseClientConnections() // surprise!

	// This test has an expected race. Sleeping for 25 ms prevents
	// it on most fast machines, causing the next fetch() call to
	// succeed quickly. But if we do get errors, fetch() will retry 5
	// times with some delays between.
	time.Sleep(25 * time.Millisecond)

	body3 := fetch(3, 5)

	if body1 != body2 {
		t.Errorf("expected body1 and body2 to be equal")
	}
	if body2 == body3 {
		t.Errorf("expected body2 and body3 to be different")
	}
}

// Test for https://golang.org/issue/2616 (appropriate issue number)
// This fails pretty reliably with GOMAXPROCS=100 or something high.
func TestStressSurpriseServerCloses(t *testing.T) {
	defer afterTest(t)
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Length", "5")
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Hello"))
		w.(Flusher).Flush()
		conn, buf, _ := w.(Hijacker).Hijack()
		buf.Flush()
		conn.Close()
	}))
	defer ts.Close()

	tr := &Transport{DisableKeepAlives: false}
	c := MakeNewClient()
	c.Transport = tr
	defer tr.CloseIdleConnections()

	// Do a bunch of traffic from different goroutines. Send to activityc
	// after each request completes, regardless of whether it failed.
	// If these are too high, OS X exhausts its ephemeral ports
	// and hangs waiting for them to transition TCP states. That's
	// not what we want to test. TODO(bradfitz): use an io.Pipe
	// dialer for this test instead?
	const (
		numClients    = 20
		reqsPerClient = 25
	)
	activityc := make(chan bool)
	for i := 0; i < numClients; i++ {
		go func() {
			for i := 0; i < reqsPerClient; i++ {
				res, err := c.Get(ts.URL)
				if err == nil {
					// We expect errors since the server is
					// hanging up on us after telling us to
					// send more requests, so we don't
					// actually care what the error is.
					// But we want to close the body in cases
					// where we won the race.
					res.Body.Close()
				}
				activityc <- true
			}
		}()
	}

	// Make sure all the request come back, one way or another.
	for i := 0; i < numClients*reqsPerClient; i++ {
		select {
		case <-activityc:
		case <-time.After(5 * time.Second):
			t.Fatalf("presumed deadlock; no HTTP client activity seen in awhile")
		}
	}
}

// TestTransportHeadResponses verifies that we deal with Content-Lengths
// with no bodies properly
func TestTransportHeadResponses(t *testing.T) {
	defer afterTest(t)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.Method != "HEAD" {
			panic("expected HEAD; got " + r.Method)
		}
		w.Header().Set("Content-Length", "123")
		w.WriteHeader(200)
	}))
	defer ts.Close()

	tr := &Transport{DisableKeepAlives: false}
	c := MakeNewClient()
	c.Transport = tr
	for i := 0; i < 2; i++ {
		res, err := c.Head(ts.URL)
		if err != nil {
			t.Errorf("error on loop %d: %v", i, err)
			continue
		}
		if e, g := "123", res.Header.Get("Content-Length"); e != g {
			t.Errorf("loop %d: expected Content-Length header of %q, got %q", i, e, g)
		}
		if e, g := int64(123), res.ContentLength; e != g {
			t.Errorf("loop %d: expected res.ContentLength of %v, got %v", i, e, g)
		}
		if all, err := ioutil.ReadAll(res.Body); err != nil {
			t.Errorf("loop %d: Body ReadAll: %v", i, err)
		} else if len(all) != 0 {
			t.Errorf("Bogus body %q", all)
		}
	}
}

// TestTransportHeadChunkedResponse verifies that we ignore chunked transfer-encoding
// on responses to HEAD requests.
func TestTransportHeadChunkedResponse(t *testing.T) {
	defer afterTest(t)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.Method != "HEAD" {
			panic("expected HEAD; got " + r.Method)
		}
		w.Header().Set("Transfer-Encoding", "chunked") // client should ignore
		w.Header().Set("x-client-ipport", r.RemoteAddr)
		w.WriteHeader(200)
	}))
	defer ts.Close()

	tr := &Transport{DisableKeepAlives: false}
	c := MakeNewClient()
	c.Transport = tr
	defer tr.CloseIdleConnections()

	// Ensure that we wait for the readLoop to complete before
	// calling Head again
	didRead := make(chan bool)
	SetReadLoopBeforeNextReadHook(func() { didRead <- true })
	defer SetReadLoopBeforeNextReadHook(nil)

	res1, err := c.Head(ts.URL)
	<-didRead

	if err != nil {
		t.Fatalf("request 1 error: %v", err)
	}

	res2, err := c.Head(ts.URL)
	<-didRead

	if err != nil {
		t.Fatalf("request 2 error: %v", err)
	}
	if v1, v2 := res1.Header.Get("x-client-ipport"), res2.Header.Get("x-client-ipport"); v1 != v2 {
		t.Errorf("ip/ports differed between head requests: %q vs %q", v1, v2)
	}
}

var roundTripTests = []struct {
	accept       string
	expectAccept string
	compressed   bool
}{
	// Requests with no accept-encoding header use transparent compression
	{"", "gzip", false},
	// Requests with other accept-encoding should pass through unmodified
	{"foo", "foo", false},
	// Requests with accept-encoding == gzip should be passed through
	{"gzip", "gzip", true},
}

// Test that the modification made to the Request by the RoundTripper is cleaned up
func TestRoundTripGzip(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	const responseBody = "test response body"
	ts := httptest.NewServer(HandlerFunc(func(rw ResponseWriter, req *Request) {
		accept := req.Header.Get("Accept-Encoding")
		if expect := req.FormValue("expect_accept"); accept != expect {
			t.Errorf("in handler, test %v: Accept-Encoding = %q, want %q",
				req.FormValue("testnum"), accept, expect)
		}
		if accept == "gzip" {
			rw.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(rw)
			gz.Write([]byte(responseBody))
			gz.Close()
		} else {
			rw.Header().Set("Content-Encoding", accept)
			rw.Write([]byte(responseBody))
		}
	}))
	defer ts.Close()

	for i, test := range roundTripTests {
		// Test basic request (no accept-encoding)
		req, _ := NewRequest("GET", fmt.Sprintf("%s/?testnum=%d&expect_accept=%s", ts.URL, i, test.expectAccept), nil)
		if test.accept != "" {
			req.Header.Set("Accept-Encoding", test.accept)
		}
		res, err := DefaultTransport.RoundTrip(req)
		var body []byte
		if test.compressed {
			var r *gzip.Reader
			r, err = gzip.NewReader(res.Body)
			if err != nil {
				t.Errorf("%d. gzip NewReader: %v", i, err)
				continue
			}
			body, err = ioutil.ReadAll(r)
			res.Body.Close()
		} else {
			body, err = ioutil.ReadAll(res.Body)
		}
		if err != nil {
			t.Errorf("%d. Error: %q", i, err)
			continue
		}
		if g, e := string(body), responseBody; g != e {
			t.Errorf("%d. body = %q; want %q", i, g, e)
		}
		if g, e := req.Header.Get("Accept-Encoding"), test.accept; g != e {
			t.Errorf("%d. Accept-Encoding = %q; want %q (it was mutated, in violation of RoundTrip contract)", i, g, e)
		}
		if g, e := res.Header.Get("Content-Encoding"), test.accept; g != e {
			t.Errorf("%d. Content-Encoding = %q; want %q", i, g, e)
		}
	}

}

func TestTransportGzip(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	const testString = "The test string aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const nRandBytes = 1024 * 1024
	ts := httptest.NewServer(HandlerFunc(func(rw ResponseWriter, req *Request) {
		if req.Method == "HEAD" {
			if g := req.Header.Get("Accept-Encoding"); g != "" {
				t.Errorf("HEAD request sent with Accept-Encoding of %q; want none", g)
			}
			return
		}
		if g, e := req.Header.Get("Accept-Encoding"), "gzip"; g != e {
			t.Errorf("Accept-Encoding = %q, want %q", g, e)
		}
		rw.Header().Set("Content-Encoding", "gzip")

		var w io.Writer = rw
		var buf bytes.Buffer
		if req.FormValue("chunked") == "0" {
			w = &buf
			defer io.Copy(rw, &buf)
			defer func() {
				rw.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
			}()
		}
		gz := gzip.NewWriter(w)
		gz.Write([]byte(testString))
		if req.FormValue("body") == "large" {
			io.CopyN(gz, rand.Reader, nRandBytes)
		}
		gz.Close()
	}))
	defer ts.Close()

	for _, chunked := range []string{"1", "0"} {
		c := MakeNewClient()
		c.Transport = &Transport{}

		// First fetch something large, but only read some of it.
		res, err := c.Get(ts.URL + "/?body=large&chunked=" + chunked)
		if err != nil {
			t.Fatalf("large get: %v", err)
		}
		buf := make([]byte, len(testString))
		n, err := io.ReadFull(res.Body, buf)
		if err != nil {
			t.Fatalf("partial read of large response: size=%d, %v", n, err)
		}
		if e, g := testString, string(buf); e != g {
			t.Errorf("partial read got %q, expected %q", g, e)
		}
		res.Body.Close()
		// Read on the body, even though it's closed
		n, err = res.Body.Read(buf)
		if n != 0 || err == nil {
			t.Errorf("expected error post-closed large Read; got = %d, %v", n, err)
		}

		// Then something small.
		res, err = c.Get(ts.URL + "/?chunked=" + chunked)
		if err != nil {
			t.Fatal(err)
		}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if g, e := string(body), testString; g != e {
			t.Fatalf("body = %q; want %q", g, e)
		}
		if g, e := res.Header.Get("Content-Encoding"), ""; g != e {
			t.Fatalf("Content-Encoding = %q; want %q", g, e)
		}

		// Read on the body after it's been fully read:
		n, err = res.Body.Read(buf)
		if n != 0 || err == nil {
			t.Errorf("expected Read error after exhausted reads; got %d, %v", n, err)
		}
		res.Body.Close()
		n, err = res.Body.Read(buf)
		if n != 0 || err == nil {
			t.Errorf("expected Read error after Close; got %d, %v", n, err)
		}
	}

	// And a HEAD request too, because they're always weird.
	c := MakeNewClient()
	c.Transport = &Transport{}
	res, err := c.Head(ts.URL)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if res.StatusCode != 200 {
		t.Errorf("Head status=%d; want=200", res.StatusCode)
	}
}

// If a request has Expect:100-continue header, the request blocks sending body until the first response.
// Premature consumption of the request body should not be occurred.
func TestTransportExpect100Continue(t *testing.T) {
	setParallel(t)
	defer afterTest(t)

	ts := httptest.NewServer(HandlerFunc(func(rw ResponseWriter, req *Request) {
		switch req.URL.Path {
		case "/100":
			// This endpoint implicitly responds 100 Continue and reads body.
			if _, err := io.Copy(ioutil.Discard, req.Body); err != nil {
				t.Error("Failed to read Body", err)
			}
			rw.WriteHeader(StatusOK)
		case "/200":
			// Go 1.5 adds Connection: close header if the client expect
			// continue but not entire request body is consumed.
			rw.WriteHeader(StatusOK)
		case "/500":
			rw.WriteHeader(StatusInternalServerError)
		case "/keepalive":
			// This hijacked endpoint responds error without Connection:close.
			_, bufrw, err := rw.(Hijacker).Hijack()
			if err != nil {
				log.Fatal(err)
			}
			bufrw.WriteString("HTTP/1.1 500 Internal Server Error\r\n")
			bufrw.WriteString("Content-Length: 0\r\n\r\n")
			bufrw.Flush()
		case "/timeout":
			// This endpoint tries to read body without 100 (Continue) response.
			// After ExpectContinueTimeout, the reading will be started.
			conn, bufrw, err := rw.(Hijacker).Hijack()
			if err != nil {
				log.Fatal(err)
			}
			if _, err := io.CopyN(ioutil.Discard, bufrw, req.ContentLength); err != nil {
				t.Error("Failed to read Body", err)
			}
			bufrw.WriteString("HTTP/1.1 200 OK\r\n\r\n")
			bufrw.Flush()
			conn.Close()
		}

	}))
	defer ts.Close()

	tests := []struct {
		path   string
		body   []byte
		sent   int
		status int
	}{
		{path: "/100", body: []byte("hello"), sent: 5, status: 200},       // Got 100 followed by 200, entire body is sent.
		{path: "/200", body: []byte("hello"), sent: 0, status: 200},       // Got 200 without 100. body isn't sent.
		{path: "/500", body: []byte("hello"), sent: 0, status: 500},       // Got 500 without 100. body isn't sent.
		{path: "/keepalive", body: []byte("hello"), sent: 0, status: 500}, // Although without Connection:close, body isn't sent.
		{path: "/timeout", body: []byte("hello"), sent: 5, status: 200},   // Timeout exceeded and entire body is sent.
	}

	for i, v := range tests {
		tr := &Transport{ExpectContinueTimeout: 2 * time.Second}
		defer tr.CloseIdleConnections()
		c := MakeNewClient()
		c.Transport = tr

		body := bytes.NewReader(v.body)
		req, err := NewRequest("PUT", ts.URL+v.path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Expect", "100-continue")
		req.ContentLength = int64(len(v.body))

		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()

		sent := len(v.body) - body.Len()
		if v.status != resp.StatusCode {
			t.Errorf("test %d: status code should be %d but got %d. (%s)", i, v.status, resp.StatusCode, v.path)
		}
		if v.sent != sent {
			t.Errorf("test %d: sent body should be %d but sent %d. (%s)", i, v.sent, sent, v.path)
		}
	}
}

func TestTransportProxy(t *testing.T) {
	defer afterTest(t)
	ch := make(chan string, 1)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		ch <- "real server"
	}))
	defer ts.Close()
	proxy := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		ch <- "proxy for " + r.URL.String()
	}))
	defer proxy.Close()

	pu, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := MakeNewClient()
	c.Transport = &Transport{Proxy: ProxyURL(pu)}
	c.Head(ts.URL)
	got := <-ch
	want := "proxy for " + ts.URL + "/"
	if got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

// Issue 16997: test transport dial preserves typed errors
func TestTransportDialPreservesNetOpProxyError(t *testing.T) {
	defer afterTest(t)

	var errDial = errors.New("some dial error")

	tr := &Transport{
		Proxy: func(*Request) (*url.URL, error) {
			return url.Parse("http://proxy.fake.tld/")
		},
		Dial: func(string, string) (net.Conn, error) {
			return nil, errDial
		},
	}
	defer tr.CloseIdleConnections()

	c := MakeNewClient()
	c.Transport = tr
	req, _ := NewRequest("GET", "http://fake.tld", nil)
	res, err := c.Do(req)
	if err == nil {
		res.Body.Close()
		t.Fatal("wanted a non-nil error")
	}

	uerr, ok := err.(*url.Error)
	if !ok {
		t.Fatalf("got %T, want *url.Error", err)
	}
	oe, ok := uerr.Err.(*net.OpError)
	if !ok {
		t.Fatalf("url.Error.Err =  %T; want *net.OpError", uerr.Err)
	}
	want := &net.OpError{
		Op:  "proxyconnect",
		Net: "tcp",
		Err: errDial, // original error, unwrapped.
	}
	if !reflect.DeepEqual(oe, want) {
		t.Errorf("Got error %#v; want %#v", oe, want)
	}
}

// TestTransportGzipRecursive sends a gzip quine and checks that the
// client gets the same value back. This is more cute than anything,
// but checks that we don't recurse forever, and checks that
// Content-Encoding is removed.
func TestTransportGzipRecursive(t *testing.T) {
	defer afterTest(t)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(rgz)
	}))
	defer ts.Close()

	tr := &Transport{}
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr
	res, err := c.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, rgz) {
		t.Fatalf("Incorrect result from recursive gz:\nhave=%x\nwant=%x",
			body, rgz)
	}
	if g, e := res.Header.Get("Content-Encoding"), ""; g != e {
		t.Fatalf("Content-Encoding = %q; want %q", g, e)
	}
}

// golang.org/issue/7750: request fails when server replies with
// a short gzip body
func TestTransportGzipShort(t *testing.T) {
	defer afterTest(t)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write([]byte{0x1f, 0x8b})
	}))
	defer ts.Close()

	tr := &Transport{}
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr
	res, err := c.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	_, err = ioutil.ReadAll(res.Body)
	if err == nil {
		t.Fatal("Expect an error from reading a body.")
	}
	if err != io.ErrUnexpectedEOF {
		t.Errorf("ReadAll error = %v; want io.ErrUnexpectedEOF", err)
	}
}

// Wait until number of goroutines is no greater than nmax, or time out.
func waitNumGoroutine(nmax int) int {
	nfinal := runtime.NumGoroutine()
	for ntries := 10; ntries > 0 && nfinal > nmax; ntries-- {
		time.Sleep(50 * time.Millisecond)
		runtime.GC()
		nfinal = runtime.NumGoroutine()
	}
	return nfinal
}

// tests that persistent goroutine connections shut down when no longer desired.
func TestTransportPersistConnLeak(t *testing.T) {
	// Not parallel: counts goroutines
	defer afterTest(t)

	const numReq = 25
	gotReqCh := make(chan bool, numReq)
	unblockCh := make(chan bool, numReq)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		gotReqCh <- true
		<-unblockCh
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(204)
	}))
	defer ts.Close()

	tr := &Transport{}
	c := MakeNewClient()
	c.Transport = tr

	n0 := runtime.NumGoroutine()

	didReqCh := make(chan bool, numReq)
	failed := make(chan bool, numReq)
	for i := 0; i < numReq; i++ {
		go func() {
			res, err := c.Get(ts.URL)
			didReqCh <- true
			if err != nil {
				t.Errorf("client fetch error: %v", err)
				failed <- true
				return
			}
			res.Body.Close()
		}()
	}

	// Wait for all goroutines to be stuck in the Handler.
	for i := 0; i < numReq; i++ {
		select {
		case <-gotReqCh:
			// ok
		case <-failed:
			close(unblockCh)
			return
		}
	}

	nhigh := runtime.NumGoroutine()

	// Tell all handlers to unblock and reply.
	for i := 0; i < numReq; i++ {
		unblockCh <- true
	}

	// Wait for all HTTP clients to be done.
	for i := 0; i < numReq; i++ {
		<-didReqCh
	}

	tr.CloseIdleConnections()
	nfinal := waitNumGoroutine(n0 + 5)

	growth := nfinal - n0

	// We expect 0 or 1 extra goroutine, empirically. Allow up to 5.
	// Previously we were leaking one per numReq.
	if int(growth) > 5 {
		t.Logf("goroutine growth: %d -> %d -> %d (delta: %d)", n0, nhigh, nfinal, growth)
		t.Error("too many new goroutines")
	}
}

// golang.org/issue/4531: Transport leaks goroutines when
// request.ContentLength is explicitly short
func TestTransportPersistConnLeakShortBody(t *testing.T) {
	// Not parallel: measures goroutines.
	defer afterTest(t)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
	}))
	defer ts.Close()

	tr := &Transport{}
	c := MakeNewClient()
	c.Transport = tr

	n0 := runtime.NumGoroutine()
	body := []byte("Hello")
	for i := 0; i < 20; i++ {
		req, err := NewRequest("POST", ts.URL, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.ContentLength = int64(len(body) - 2) // explicitly short
		_, err = c.Do(req)
		if err == nil {
			t.Fatal("Expect an error from writing too long of a body.")
		}
	}
	nhigh := runtime.NumGoroutine()
	tr.CloseIdleConnections()
	nfinal := waitNumGoroutine(n0 + 5)

	growth := nfinal - n0

	// We expect 0 or 1 extra goroutine, empirically. Allow up to 5.
	// Previously we were leaking one per numReq.
	t.Logf("goroutine growth: %d -> %d -> %d (delta: %d)", n0, nhigh, nfinal, growth)
	if int(growth) > 5 {
		t.Error("too many new goroutines")
	}
}

// This used to crash; https://golang.org/issue/3266
func TestTransportIdleConnCrash(t *testing.T) {
	defer afterTest(t)
	tr := &Transport{}
	c := MakeNewClient()
	c.Transport = tr

	unblockCh := make(chan bool, 1)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		<-unblockCh
		tr.CloseIdleConnections()
	}))
	defer ts.Close()

	didreq := make(chan bool)
	go func() {
		res, err := c.Get(ts.URL)
		if err != nil {
			t.Error(err)
		} else {
			res.Body.Close() // returns idle conn
		}
		didreq <- true
	}()
	unblockCh <- true
	<-didreq
}

// Test that the transport doesn't close the TCP connection early,
// before the response body has been read. This was a regression
// which sadly lacked a triggering test. The large response body made
// the old race easier to trigger.
func TestIssue3644(t *testing.T) {
	defer afterTest(t)
	const numFoos = 5000
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("Connection", "close")
		for i := 0; i < numFoos; i++ {
			w.Write([]byte("foo "))
		}
	}))
	defer ts.Close()
	tr := &Transport{}
	c := MakeNewClient()
	c.Transport = tr
	res, err := c.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	bs, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != numFoos*len("foo ") {
		t.Errorf("unexpected response length")
	}
}

// Test that a client receives a server's reply, even if the server doesn't read
// the entire request body.
func TestIssue3595(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	const deniedMsg = "sorry, denied."
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		Error(w, deniedMsg, StatusUnauthorized)
	}))
	defer ts.Close()
	tr := &Transport{}
	c := MakeNewClient()
	c.Transport = tr
	res, err := c.Post(ts.URL, "application/octet-stream", neverEnding('a'))
	if err != nil {
		t.Errorf("Post: %v", err)
		return
	}
	got, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("Body ReadAll: %v", err)
	}
	if !strings.Contains(string(got), deniedMsg) {
		t.Errorf("Known bug: response %q does not contain %q", got, deniedMsg)
	}
}

// From https://golang.org/issue/4454 ,
// "client fails to handle requests with no body and chunked encoding"
func TestChunkedNoContent(t *testing.T) {
	defer afterTest(t)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		w.WriteHeader(StatusNoContent)
	}))
	defer ts.Close()

	for _, closeBody := range []bool{true, false} {
		c := MakeNewClient()
		c.Transport = &Transport{}
		const n = 4
		for i := 1; i <= n; i++ {
			res, err := c.Get(ts.URL)
			if err != nil {
				t.Errorf("closingBody=%v, req %d/%d: %v", closeBody, i, n, err)
			} else {
				if closeBody {
					res.Body.Close()
				}
			}
		}
	}
}

func TestTransportConcurrency(t *testing.T) {
	// Not parallel: uses global test hooks.
	defer afterTest(t)
	maxProcs, numReqs := 16, 500
	if testing.Short() {
		maxProcs, numReqs = 4, 50
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(maxProcs))
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		fmt.Fprintf(w, "%v", r.FormValue("echo"))
	}))
	defer ts.Close()

	var wg sync.WaitGroup
	wg.Add(numReqs)

	// Due to the Transport's "socket late binding" (see
	// idleConnCh in transport.go), the numReqs HTTP requests
	// below can finish with a dial still outstanding. To keep
	// the leak checker happy, keep track of pending dials and
	// wait for them to finish (and be closed or returned to the
	// idle pool) before we close idle connections.
	SetPendingDialHooks(func() { wg.Add(1) }, wg.Done)
	defer SetPendingDialHooks(nil, nil)

	tr := &Transport{}
	defer tr.CloseIdleConnections()

	c := MakeNewClient()
	c.Transport = tr
	reqs := make(chan string)
	defer close(reqs)

	for i := 0; i < maxProcs*2; i++ {
		go func() {
			for req := range reqs {
				res, err := c.Get(ts.URL + "/?echo=" + req)
				if err != nil {
					t.Errorf("error on req %s: %v", req, err)
					wg.Done()
					continue
				}
				all, err := ioutil.ReadAll(res.Body)
				if err != nil {
					t.Errorf("read error on req %s: %v", req, err)
					wg.Done()
					continue
				}
				if string(all) != req {
					t.Errorf("body of req %s = %q; want %q", req, all, req)
				}
				res.Body.Close()
				wg.Done()
			}
		}()
	}
	for i := 0; i < numReqs; i++ {
		reqs <- fmt.Sprintf("request-%d", i)
	}
	wg.Wait()
}

func TestIssue4191_InfiniteGetTimeout(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	const debug = false
	mux := NewServeMux()
	mux.HandleFunc("/get", func(w ResponseWriter, r *Request) {
		io.Copy(w, neverEnding('a'))
	})
	ts := httptest.NewServer(mux)
	timeout := 100 * time.Millisecond
	client := MakeNewClient()
	client.Transport = &Transport{
		Dial: func(n, addr string) (net.Conn, error) {
			conn, err := net.Dial(n, addr)
			if err != nil {
				return nil, err
			}
			conn.SetDeadline(time.Now().Add(timeout))
			if debug {
				conn = NewLoggingConn("client", conn)
			}
			return conn, nil
		},
		DisableKeepAlives: true,
	}

	getFailed := false
	nRuns := 5
	if testing.Short() {
		nRuns = 1
	}
	for i := 0; i < nRuns; i++ {
		if debug {
			println("run", i+1, "of", nRuns)
		}
		sres, err := client.Get(ts.URL + "/get")
		if err != nil {
			if !getFailed {
				// Make the timeout longer, once.
				getFailed = true
				t.Logf("increasing timeout")
				i--
				timeout *= 10
				continue
			}
			t.Errorf("Error issuing GET: %v", err)
			break
		}
		_, err = io.Copy(ioutil.Discard, sres.Body)
		if err == nil {
			t.Errorf("Unexpected successful copy")
			break
		}
	}
	if debug {
		println("tests complete; waiting for handlers to finish")
	}
	ts.Close()
}

func TestIssue4191_InfiniteGetToPutTimeout(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	const debug = false
	mux := NewServeMux()
	mux.HandleFunc("/get", func(w ResponseWriter, r *Request) {
		io.Copy(w, neverEnding('a'))
	})
	mux.HandleFunc("/put", func(w ResponseWriter, r *Request) {
		defer r.Body.Close()
		io.Copy(ioutil.Discard, r.Body)
	})
	ts := httptest.NewServer(mux)
	timeout := 100 * time.Millisecond
	client := MakeNewClient()
	client.Transport = &Transport{
		Dial: func(n, addr string) (net.Conn, error) {
			conn, err := net.Dial(n, addr)
			if err != nil {
				return nil, err
			}
			conn.SetDeadline(time.Now().Add(timeout))
			if debug {
				conn = NewLoggingConn("client", conn)
			}
			return conn, nil
		},
		DisableKeepAlives: true,
	}

	getFailed := false
	nRuns := 5
	if testing.Short() {
		nRuns = 1
	}
	for i := 0; i < nRuns; i++ {
		if debug {
			println("run", i+1, "of", nRuns)
		}
		sres, err := client.Get(ts.URL + "/get")
		if err != nil {
			if !getFailed {
				// Make the timeout longer, once.
				getFailed = true
				t.Logf("increasing timeout")
				i--
				timeout *= 10
				continue
			}
			t.Errorf("Error issuing GET: %v", err)
			break
		}
		req, _ := NewRequest("PUT", ts.URL+"/put", sres.Body)
		_, err = client.Do(req)
		if err == nil {
			sres.Body.Close()
			t.Errorf("Unexpected successful PUT")
			break
		}
		sres.Body.Close()
	}
	if debug {
		println("tests complete; waiting for handlers to finish")
	}
	ts.Close()
}

func TestTransportResponseHeaderTimeout(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	if testing.Short() {
		t.Skip("skipping timeout test in -short mode")
	}
	inHandler := make(chan bool, 1)
	mux := NewServeMux()
	mux.HandleFunc("/fast", func(w ResponseWriter, r *Request) {
		inHandler <- true
	})
	mux.HandleFunc("/slow", func(w ResponseWriter, r *Request) {
		inHandler <- true
		time.Sleep(2 * time.Second)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	tr := &Transport{
		ResponseHeaderTimeout: 500 * time.Millisecond,
	}
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr

	tests := []struct {
		path    string
		want    int
		wantErr string
	}{
		{path: "/fast", want: 200},
		{path: "/slow", wantErr: "timeout awaiting response headers"},
		{path: "/fast", want: 200},
	}
	for i, tt := range tests {
		res, err := c.Get(ts.URL + tt.path)
		select {
		case <-inHandler:
		case <-time.After(5 * time.Second):
			t.Errorf("never entered handler for test index %d, %s", i, tt.path)
			continue
		}
		if err != nil {
			uerr, ok := err.(*url.Error)
			if !ok {
				t.Errorf("error is not an url.Error; got: %#v", err)
				continue
			}
			nerr, ok := uerr.Err.(net.Error)
			if !ok {
				t.Errorf("error does not satisfy net.Error interface; got: %#v", err)
				continue
			}
			if !nerr.Timeout() {
				t.Errorf("want timeout error; got: %q", nerr)
				continue
			}
			if strings.Contains(err.Error(), tt.wantErr) {
				continue
			}
			t.Errorf("%d. unexpected error: %v", i, err)
			continue
		}
		if tt.wantErr != "" {
			t.Errorf("%d. no error. expected error: %v", i, tt.wantErr)
			continue
		}
		if res.StatusCode != tt.want {
			t.Errorf("%d for path %q status = %d; want %d", i, tt.path, res.StatusCode, tt.want)
		}
	}
}

func TestTransportCancelRequest(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	if testing.Short() {
		t.Skip("skipping test in -short mode")
	}
	unblockc := make(chan bool)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		fmt.Fprintf(w, "Hello")
		w.(Flusher).Flush() // send headers and some body
		<-unblockc
	}))
	defer ts.Close()
	defer close(unblockc)

	tr := &Transport{}
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr

	req, _ := NewRequest("GET", ts.URL, nil)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(1 * time.Second)
		tr.CancelRequest(req)
	}()
	t0 := time.Now()
	body, err := ioutil.ReadAll(res.Body)
	d := time.Since(t0)

	if err != ExportErrRequestCanceled {
		t.Errorf("Body.Read error = %v; want errRequestCanceled", err)
	}
	if string(body) != "Hello" {
		t.Errorf("Body = %q; want Hello", body)
	}
	if d < 500*time.Millisecond {
		t.Errorf("expected ~1 second delay; got %v", d)
	}
	// Verify no outstanding requests after readLoop/writeLoop
	// goroutines shut down.
	for tries := 5; tries > 0; tries-- {
		n := tr.NumPendingRequestsForTesting()
		if n == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
		if tries == 1 {
			t.Errorf("pending requests = %d; want 0", n)
		}
	}
}

func TestTransportCancelRequestInDial(t *testing.T) {
	defer afterTest(t)
	if testing.Short() {
		t.Skip("skipping test in -short mode")
	}
	var logbuf bytes.Buffer
	eventLog := log.New(&logbuf, "", 0)

	unblockDial := make(chan bool)
	defer close(unblockDial)

	inDial := make(chan bool)
	tr := &Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			eventLog.Println("dial: blocking")
			inDial <- true
			<-unblockDial
			return nil, errors.New("nope")
		},
	}
	cl := MakeNewClient()
	cl.Transport = tr
	gotres := make(chan bool)
	req, _ := NewRequest("GET", "http://something.no-network.tld/", nil)
	go func() {
		_, err := cl.Do(req)
		eventLog.Printf("Get = %v", err)
		gotres <- true
	}()

	select {
	case <-inDial:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout; never saw blocking dial")
	}

	eventLog.Printf("canceling")
	tr.CancelRequest(req)
	tr.CancelRequest(req) // used to panic on second call

	select {
	case <-gotres:
	case <-time.After(5 * time.Second):
		panic("hang. events are: " + logbuf.String())
	}

	got := logbuf.String()
	want := `dial: blocking
canceling
Get = Get http://something.no-network.tld/: net/http: request canceled while waiting for connection
`
	if got != want {
		t.Errorf("Got events:\n%s\nWant:\n%s", got, want)
	}
}

func TestCancelRequestWithChannel(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	if testing.Short() {
		t.Skip("skipping test in -short mode")
	}
	unblockc := make(chan bool)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		fmt.Fprintf(w, "Hello")
		w.(Flusher).Flush() // send headers and some body
		<-unblockc
	}))
	defer ts.Close()
	defer close(unblockc)

	tr := &Transport{}
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr

	req, _ := NewRequest("GET", ts.URL, nil)
	ch := make(chan struct{})
	req.Cancel = ch

	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(1 * time.Second)
		close(ch)
	}()
	t0 := time.Now()
	body, err := ioutil.ReadAll(res.Body)
	d := time.Since(t0)

	if err != ExportErrRequestCanceled {
		t.Errorf("Body.Read error = %v; want errRequestCanceled", err)
	}
	if string(body) != "Hello" {
		t.Errorf("Body = %q; want Hello", body)
	}
	if d < 500*time.Millisecond {
		t.Errorf("expected ~1 second delay; got %v", d)
	}
	// Verify no outstanding requests after readLoop/writeLoop
	// goroutines shut down.
	for tries := 5; tries > 0; tries-- {
		n := tr.NumPendingRequestsForTesting()
		if n == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
		if tries == 1 {
			t.Errorf("pending requests = %d; want 0", n)
		}
	}
}

func TestCancelRequestWithChannelBeforeDo_Cancel(t *testing.T) {
	testCancelRequestWithChannelBeforeDo(t, false)
}
func TestCancelRequestWithChannelBeforeDo_Context(t *testing.T) {
	testCancelRequestWithChannelBeforeDo(t, true)
}
func testCancelRequestWithChannelBeforeDo(t *testing.T, withCtx bool) {
	setParallel(t)
	defer afterTest(t)
	unblockc := make(chan bool)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		<-unblockc
	}))
	defer ts.Close()
	defer close(unblockc)

	tr := &Transport{}
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr

	req, _ := NewRequest("GET", ts.URL, nil)
	if withCtx {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req = req.WithContext(ctx)
	} else {
		ch := make(chan struct{})
		req.Cancel = ch
		close(ch)
	}

	_, err := c.Do(req)
	if ue, ok := err.(*url.Error); ok {
		err = ue.Err
	}
	if withCtx {
		if err != context.Canceled {
			t.Errorf("Do error = %v; want %v", err, context.Canceled)
		}
	} else {
		if err == nil || !strings.Contains(err.Error(), "canceled") {
			t.Errorf("Do error = %v; want cancelation", err)
		}
	}
}

// Issue 11020. The returned error message should be errRequestCanceled
func TestTransportCancelBeforeResponseHeaders(t *testing.T) {
	defer afterTest(t)

	serverConnCh := make(chan net.Conn, 1)
	tr := &Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			cc, sc := net.Pipe()
			serverConnCh <- sc
			return cc, nil
		},
	}
	defer tr.CloseIdleConnections()
	errc := make(chan error, 1)
	req, _ := NewRequest("GET", "http://example.com/", nil)
	go func() {
		_, err := tr.RoundTrip(req)
		errc <- err
	}()

	sc := <-serverConnCh
	verb := make([]byte, 3)
	if _, err := io.ReadFull(sc, verb); err != nil {
		t.Errorf("Error reading HTTP verb from server: %v", err)
	}
	if string(verb) != "GET" {
		t.Errorf("server received %q; want GET", verb)
	}
	defer sc.Close()

	tr.CancelRequest(req)

	err := <-errc
	if err == nil {
		t.Fatalf("unexpected success from RoundTrip")
	}
	if err != ExportErrRequestCanceled {
		t.Errorf("RoundTrip error = %v; want ExportErrRequestCanceled", err)
	}
}

// golang.org/issue/3672 -- Client can't close HTTP stream
// Calling Close on a Response.Body used to just read until EOF.
// Now it actually closes the TCP connection.
func TestTransportCloseResponseBody(t *testing.T) {
	defer afterTest(t)
	writeErr := make(chan error, 1)
	msg := []byte("young\n")
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		for {
			_, err := w.Write(msg)
			if err != nil {
				writeErr <- err
				return
			}
			w.(Flusher).Flush()
		}
	}))
	defer ts.Close()

	tr := &Transport{}
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr

	req, _ := NewRequest("GET", ts.URL, nil)
	defer tr.CancelRequest(req)

	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	const repeats = 3
	buf := make([]byte, len(msg)*repeats)
	want := bytes.Repeat(msg, repeats)

	_, err = io.ReadFull(res.Body, buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, want) {
		t.Fatalf("read %q; want %q", buf, want)
	}
	didClose := make(chan error, 1)
	go func() {
		didClose <- res.Body.Close()
	}()
	select {
	case err := <-didClose:
		if err != nil {
			t.Errorf("Close = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("too long waiting for close")
	}
	select {
	case err := <-writeErr:
		if err == nil {
			t.Errorf("expected non-nil write error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("too long waiting for write error")
	}
}

type fooProto struct{}

func (fooProto) RoundTrip(req *Request) (*Response, error) {
	res := &Response{
		Status:     "200 OK",
		StatusCode: 200,
		Header:     make(Header),
		Body:       ioutil.NopCloser(strings.NewReader("You wanted " + req.URL.String())),
	}
	return res, nil
}

func TestTransportAltProto(t *testing.T) {
	defer afterTest(t)
	tr := &Transport{}
	c := MakeNewClient()
	c.Transport = tr
	tr.RegisterProtocol("foo", fooProto{})
	res, err := c.Get("foo://bar.com/path")
	if err != nil {
		t.Fatal(err)
	}
	bodyb, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	body := string(bodyb)
	if e := "You wanted foo://bar.com/path"; body != e {
		t.Errorf("got response %q, want %q", body, e)
	}
}

func TestTransportNoHost(t *testing.T) {
	defer afterTest(t)
	tr := &Transport{}
	_, err := tr.RoundTrip(&Request{
		Header: make(Header),
		URL: &url.URL{
			Scheme: "http",
		},
	})
	want := "http: no Host in request URL"
	if got := fmt.Sprint(err); got != want {
		t.Errorf("error = %v; want %q", err, want)
	}
}

// Issue 13311
func TestTransportEmptyMethod(t *testing.T) {
	req, _ := NewRequest("GET", "http://foo.com/", nil)
	req.Method = ""                                 // docs say "For client requests an empty string means GET"
	got, err := httputil.DumpRequestOut(req, false) // DumpRequestOut uses Transport
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "GET ") {
		t.Fatalf("expected substring 'GET '; got: %s", got)
	}
}

/*
func TestTransportSocketLateBinding(t *testing.T) {
	setParallel(t)
	defer afterTest(t)

	mux := NewServeMux()
	fooGate := make(chan bool, 1)
	mux.HandleFunc("/foo", func(w ResponseWriter, r *Request) {
		w.Header().Set("foo-ipport", r.RemoteAddr)
		w.(Flusher).Flush()
		<-fooGate
	})
	mux.HandleFunc("/bar", func(w ResponseWriter, r *Request) {
		w.Header().Set("bar-ipport", r.RemoteAddr)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	dialGate := make(chan bool, 1)
	tr := &Transport{
		Dial: func(n, addr string) (net.Conn, error) {
			if <-dialGate {
				return net.Dial(n, addr)
			}
			return nil, errors.New("manually closed")
		},
		DisableKeepAlives: false,
	}
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr

	dialGate <- true // only allow one dial
	fooRes, err := c.Get(ts.URL + "/foo")
	if err != nil {
		t.Fatal(err)
	}
	fooAddr := fooRes.Header.Get("foo-ipport")
	if fooAddr == "" {
		t.Fatal("No addr on /foo request")
	}
	time.AfterFunc(200*time.Millisecond, func() {
		// let the foo response finish so we can use its
		// connection for /bar
		fooGate <- true
		io.Copy(ioutil.Discard, fooRes.Body)
		fooRes.Body.Close()
	})

	barRes, err := c.Get(ts.URL + "/bar")
	if err != nil {
		t.Fatal(err)
	}
	barAddr := barRes.Header.Get("bar-ipport")
	if barAddr != fooAddr {
		t.Fatalf("/foo came from conn %q; /bar came from %q instead", fooAddr, barAddr)
	}
	barRes.Body.Close()
	dialGate <- false
}*/

// Issue 2184
func TestTransportReading100Continue(t *testing.T) {
	defer afterTest(t)

	const numReqs = 5
	reqBody := func(n int) string { return fmt.Sprintf("request body %d", n) }
	reqID := func(n int) string { return fmt.Sprintf("REQ-ID-%d", n) }

	send100Response := func(w *io.PipeWriter, r *io.PipeReader) {
		defer w.Close()
		defer r.Close()
		br := bufio.NewReader(r)
		n := 0
		for {
			n++
			req, err := ReadRequest(br)
			if err == io.EOF {
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			slurp, err := ioutil.ReadAll(req.Body)
			if err != nil {
				t.Errorf("Server request body slurp: %v", err)
				return
			}
			id := req.Header.Get("Request-Id")
			resCode := req.Header.Get("X-Want-Response-Code")
			if resCode == "" {
				resCode = "100 Continue"
				if string(slurp) != reqBody(n) {
					t.Errorf("Server got %q, %v; want %q", slurp, err, reqBody(n))
				}
			}
			body := fmt.Sprintf("Response number %d", n)
			v := []byte(strings.Replace(fmt.Sprintf(`HTTP/1.1 %s
Date: Thu, 28 Feb 2013 17:55:41 GMT

HTTP/1.1 200 OK
Content-Type: text/html
Echo-Request-Id: %s
Content-Length: %d

%s`, resCode, id, len(body), body), "\n", "\r\n", -1))
			w.Write(v)
			if id == reqID(numReqs) {
				return
			}
		}

	}

	tr := &Transport{
		Dial: func(n, addr string) (net.Conn, error) {
			sr, sw := io.Pipe() // server read/write
			cr, cw := io.Pipe() // client read/write
			conn := &rwTestConn{
				Reader: cr,
				Writer: sw,
				closeFunc: func() error {
					sw.Close()
					cw.Close()
					return nil
				},
			}
			go send100Response(cw, sr)
			return conn, nil
		},
		DisableKeepAlives: false,
	}
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr

	testResponse := func(req *Request, name string, wantCode int) {
		res, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: Do: %v", name, err)
		}
		if res.StatusCode != wantCode {
			t.Fatalf("%s: Response Statuscode=%d; want %d", name, res.StatusCode, wantCode)
		}
		if id, idBack := req.Header.Get("Request-Id"), res.Header.Get("Echo-Request-Id"); id != "" && id != idBack {
			t.Errorf("%s: response id %q != request id %q", name, idBack, id)
		}
		_, err = ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatalf("%s: Slurp error: %v", name, err)
		}
	}

	// Few 100 responses, making sure we're not off-by-one.
	for i := 1; i <= numReqs; i++ {
		req, _ := NewRequest("POST", "http://dummy.tld/", strings.NewReader(reqBody(i)))
		req.Header.Set("Request-Id", reqID(i))
		testResponse(req, fmt.Sprintf("100, %d/%d", i, numReqs), 200)
	}

	// And some other informational 1xx but non-100 responses, to test
	// we return them but don't re-use the connection.
	for i := 1; i <= numReqs; i++ {
		req, _ := NewRequest("POST", "http://other.tld/", strings.NewReader(reqBody(i)))
		req.Header.Set("X-Want-Response-Code", "123 Sesame Street")
		testResponse(req, fmt.Sprintf("123, %d/%d", i, numReqs), 123)
	}
}

type proxyFromEnvTest struct {
	req string // URL to fetch; blank means "http://example.com"

	env      string // HTTP_PROXY
	httpsenv string // HTTPS_PROXY
	noenv    string // NO_PROXY
	reqmeth  string // REQUEST_METHOD

	want    string
	wanterr error
}

func (t proxyFromEnvTest) String() string {
	var buf bytes.Buffer
	space := func() {
		if buf.Len() > 0 {
			buf.WriteByte(' ')
		}
	}
	if t.env != "" {
		fmt.Fprintf(&buf, "http_proxy=%q", t.env)
	}
	if t.httpsenv != "" {
		space()
		fmt.Fprintf(&buf, "https_proxy=%q", t.httpsenv)
	}
	if t.noenv != "" {
		space()
		fmt.Fprintf(&buf, "no_proxy=%q", t.noenv)
	}
	if t.reqmeth != "" {
		space()
		fmt.Fprintf(&buf, "request_method=%q", t.reqmeth)
	}
	req := "http://example.com"
	if t.req != "" {
		req = t.req
	}
	space()
	fmt.Fprintf(&buf, "req=%q", req)
	return strings.TrimSpace(buf.String())
}

var proxyFromEnvTests = []proxyFromEnvTest{
	{env: "127.0.0.1:8080", want: "http://127.0.0.1:8080"},
	{env: "cache.corp.example.com:1234", want: "http://cache.corp.example.com:1234"},
	{env: "cache.corp.example.com", want: "http://cache.corp.example.com"},
	{env: "https://cache.corp.example.com", want: "https://cache.corp.example.com"},
	{env: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080"},
	{env: "https://127.0.0.1:8080", want: "https://127.0.0.1:8080"},

	// Don't use secure for http
	{req: "http://insecure.tld/", env: "http.proxy.tld", httpsenv: "secure.proxy.tld", want: "http://http.proxy.tld"},
	// Use secure for https.
	{req: "https://secure.tld/", env: "http.proxy.tld", httpsenv: "secure.proxy.tld", want: "http://secure.proxy.tld"},
	{req: "https://secure.tld/", env: "http.proxy.tld", httpsenv: "https://secure.proxy.tld", want: "https://secure.proxy.tld"},

	// Issue 16405: don't use HTTP_PROXY in a CGI environment,
	// where HTTP_PROXY can be attacker-controlled.
	{env: "http://10.1.2.3:8080", reqmeth: "POST",
		want:    "<nil>",
		wanterr: errors.New("net/http: refusing to use HTTP_PROXY value in CGI environment; see golang.org/s/cgihttpproxy")},

	{want: "<nil>"},

	{noenv: "example.com", req: "http://example.com/", env: "proxy", want: "<nil>"},
	{noenv: ".example.com", req: "http://example.com/", env: "proxy", want: "<nil>"},
	{noenv: "ample.com", req: "http://example.com/", env: "proxy", want: "http://proxy"},
	{noenv: "example.com", req: "http://foo.example.com/", env: "proxy", want: "<nil>"},
	{noenv: ".foo.com", req: "http://example.com/", env: "proxy", want: "http://proxy"},
}

func TestProxyFromEnvironment(t *testing.T) {
	ResetProxyEnv()
	for _, tt := range proxyFromEnvTests {
		os.Setenv("HTTP_PROXY", tt.env)
		os.Setenv("HTTPS_PROXY", tt.httpsenv)
		os.Setenv("NO_PROXY", tt.noenv)
		os.Setenv("REQUEST_METHOD", tt.reqmeth)
		ResetCachedEnvironment()
		reqURL := tt.req
		if reqURL == "" {
			reqURL = "http://example.com"
		}
		req, _ := NewRequest("GET", reqURL, nil)
		url, err := ProxyFromEnvironment(req)
		if g, e := fmt.Sprintf("%v", err), fmt.Sprintf("%v", tt.wanterr); g != e {
			t.Errorf("%v: got error = %q, want %q", tt, g, e)
			continue
		}
		if got := fmt.Sprintf("%s", url); got != tt.want {
			t.Errorf("%v: got URL = %q, want %q", tt, url, tt.want)
		}
	}
}

func TestIdleConnChannelLeak(t *testing.T) {
	// Not parallel: uses global test hooks.
	var mu sync.Mutex
	var n int

	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		mu.Lock()
		n++
		mu.Unlock()
	}))
	defer ts.Close()

	const nReqs = 5
	didRead := make(chan bool, nReqs)
	SetReadLoopBeforeNextReadHook(func() { didRead <- true })
	defer SetReadLoopBeforeNextReadHook(nil)

	tr := &Transport{
		Dial: func(netw, addr string) (net.Conn, error) {
			return net.Dial(netw, ts.Listener.Addr().String())
		},
	}
	defer tr.CloseIdleConnections()

	c := MakeNewClient()
	c.Transport = tr

	// First, without keep-alives.
	for _, disableKeep := range []bool{true, false} {
		tr.DisableKeepAlives = disableKeep
		for i := 0; i < nReqs; i++ {
			_, err := c.Get(fmt.Sprintf("http://foo-host-%d.tld/", i))
			if err != nil {
				t.Fatal(err)
			}
			// Note: no res.Body.Close is needed here, since the
			// response Content-Length is zero. Perhaps the test
			// should be more explicit and use a HEAD, but tests
			// elsewhere guarantee that zero byte responses generate
			// a "Content-Length: 0" instead of chunking.
		}

		// At this point, each of the 5 Transport.readLoop goroutines
		// are scheduling noting that there are no response bodies (see
		// earlier comment), and are then calling putIdleConn, which
		// decrements this count. Usually that happens quickly, which is
		// why this test has seemed to work for ages. But it's still
		// racey: we have wait for them to finish first. See Issue 10427
		for i := 0; i < nReqs; i++ {
			<-didRead
		}

		if got := tr.IdleConnChMapSizeForTesting(); got != 0 {
			t.Fatalf("ForDisableKeepAlives = %v, map size = %d; want 0", disableKeep, got)
		}
	}
}

// Verify the status quo: that the Client.Post function coerces its
// body into a ReadCloser if it's a Closer, and that the Transport
// then closes it.
func TestTransportClosesRequestBody(t *testing.T) {
	defer afterTest(t)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		io.Copy(ioutil.Discard, r.Body)
	}))
	defer ts.Close()

	tr := &Transport{}
	defer tr.CloseIdleConnections()
	cl := MakeNewClient()
	cl.Transport = tr
	closes := 0

	res, err := cl.Post(ts.URL, "text/plain", countCloseReader{&closes, strings.NewReader("hello")})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if closes != 1 {
		t.Errorf("closes = %d; want 1", closes)
	}
}

func TestTransportTLSHandshakeTimeout(t *testing.T) {
	defer afterTest(t)
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	ln := newLocalListener(t)
	defer ln.Close()
	testdonec := make(chan struct{})
	defer close(testdonec)

	go func() {
		c, err := ln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		<-testdonec
		c.Close()
	}()

	getdonec := make(chan struct{})
	go func() {
		defer close(getdonec)
		tr := &Transport{
			Dial: func(_, _ string) (net.Conn, error) {
				return net.Dial("tcp", ln.Addr().String())
			},
			TLSHandshakeTimeout: 250 * time.Millisecond,
		}
		cl := MakeNewClient()
		cl.Transport = tr
		_, err := cl.Get("https://dummy.tld/")
		if err == nil {
			t.Error("expected error")
			return
		}
		ue, ok := err.(*url.Error)
		if !ok {
			t.Errorf("expected url.Error; got %#v", err)
			return
		}
		ne, ok := ue.Err.(net.Error)
		if !ok {
			t.Errorf("expected net.Error; got %#v", err)
			return
		}
		if !ne.Timeout() {
			t.Errorf("expected timeout error; got %v", err)
		}
		if !strings.Contains(err.Error(), "handshake timeout") {
			t.Errorf("expected 'handshake timeout' in error; got %v", err)
		}
	}()
	select {
	case <-getdonec:
	case <-time.After(5 * time.Second):
		t.Error("test timeout; TLS handshake hung?")
	}
}

// Trying to repro golang.org/issue/3514
func TestTLSServerClosesConnection(t *testing.T) {
	defer afterTest(t)

	closedc := make(chan bool, 1)
	ts := httptest.NewTLSServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		if strings.Contains(r.URL.Path, "/keep-alive-then-die") {
			conn, _, _ := w.(Hijacker).Hijack()
			conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nfoo"))
			conn.Close()
			closedc <- true
			return
		}
		fmt.Fprintf(w, "hello")
	}))
	defer ts.Close()
	tr := &Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	defer tr.CloseIdleConnections()
	client := MakeNewClient()
	client.Transport = tr
	var nSuccess = 0
	var errs []error
	const trials = 20
	for i := 0; i < trials; i++ {
		tr.CloseIdleConnections()
		res, err := client.Get(ts.URL + "/keep-alive-then-die")
		if err != nil {
			t.Fatal(err)
		}
		<-closedc
		slurp, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(slurp) != "foo" {
			t.Errorf("Got %q, want foo", slurp)
		}

		// Now try again and see if we successfully
		// pick a new connection.
		res, err = client.Get(ts.URL + "/")
		if err != nil {
			errs = append(errs, err)
			continue
		}
		_, err = ioutil.ReadAll(res.Body)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		nSuccess++
	}
	if nSuccess > 0 {
		t.Logf("successes = %d of %d", nSuccess, trials)
	} else {
		t.Errorf("All runs failed:")
	}
	for _, err := range errs {
		t.Logf("  err: %v", err)
	}
}

// byteFromChanReader is an io.Reader that reads a single byte at a
// time from the channel. When the channel is closed, the reader
// returns io.EOF.
type byteFromChanReader chan byte

func (c byteFromChanReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	b, ok := <-c
	if !ok {
		return 0, io.EOF
	}
	p[0] = b
	return 1, nil
}

// Verifies that the Transport doesn't reuse a connection in the case
// where the server replies before the request has been fully
// written. We still honor that reply (see TestIssue3595), but don't
// send future requests on the connection because it's then in a
// questionable state.
// golang.org/issue/7569
func TestTransportNoReuseAfterEarlyResponse(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	var sconn struct {
		sync.Mutex
		c net.Conn
	}
	var getOkay bool
	closeConn := func() {
		sconn.Lock()
		defer sconn.Unlock()
		if sconn.c != nil {
			sconn.c.Close()
			sconn.c = nil
			if !getOkay {
				t.Logf("Closed server connection")
			}
		}
	}
	defer closeConn()

	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.Method == "GET" {
			io.WriteString(w, "bar")
			return
		}
		conn, _, _ := w.(Hijacker).Hijack()
		sconn.Lock()
		sconn.c = conn
		sconn.Unlock()
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nfoo")) // keep-alive
		go io.Copy(ioutil.Discard, conn)
	}))
	defer ts.Close()
	tr := &Transport{}
	defer tr.CloseIdleConnections()
	client := MakeNewClient()
	client.Transport = tr
	const bodySize = 256 << 10
	finalBit := make(byteFromChanReader, 1)
	req, _ := NewRequest("POST", ts.URL, io.MultiReader(io.LimitReader(neverEnding('x'), bodySize-1), finalBit))
	req.ContentLength = bodySize
	res, err := client.Do(req)
	if err := wantBody(res, err, "foo"); err != nil {
		t.Errorf("POST response: %v", err)
	}
	donec := make(chan bool)
	go func() {
		defer close(donec)
		res, err = client.Get(ts.URL)
		if err := wantBody(res, err, "bar"); err != nil {
			t.Errorf("GET response: %v", err)
			return
		}
		getOkay = true // suppress test noise
	}()
	time.AfterFunc(5*time.Second, closeConn)
	select {
	case <-donec:
		finalBit <- 'x' // unblock the writeloop of the first Post
		close(finalBit)
	case <-time.After(7 * time.Second):
		t.Fatal("timeout waiting for GET request to finish")
	}
}

// Tests that we don't leak Transport persistConn.readLoop goroutines
// when a server hangs up immediately after saying it would keep-alive.
func TestTransportIssue10457(t *testing.T) {
	defer afterTest(t) // used to fail in goroutine leak check
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		// Send a response with no body, keep-alive
		// (implicit), and then lie and immediately close the
		// connection. This forces the Transport's readLoop to
		// immediately Peek an io.EOF and get to the point
		// that used to hang.
		conn, _, _ := w.(Hijacker).Hijack()
		conn.Write([]byte("HTTP/1.1 200 OK\r\nFoo: Bar\r\nContent-Length: 0\r\n\r\n")) // keep-alive
		conn.Close()
	}))
	defer ts.Close()
	tr := &Transport{}
	defer tr.CloseIdleConnections()
	cl := MakeNewClient()
	cl.Transport = tr
	res, err := cl.Get(ts.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer res.Body.Close()

	// Just a sanity check that we at least get the response. The real
	// test here is that the "defer afterTest" above doesn't find any
	// leaked goroutines.
	if got, want := res.Header.Get("Foo"), "Bar"; got != want {
		t.Errorf("Foo header = %q; want %q", got, want)
	}
}

type errorReader struct {
	err error
}

func (e errorReader) Read(p []byte) (int, error) { return 0, e.err }

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

type writerFuncConn struct {
	net.Conn
	write func(p []byte) (n int, err error)
}

func (c writerFuncConn) Write(p []byte) (n int, err error) { return c.write(p) }

// Issue 4677. If we try to reuse a connection that the server is in the
// process of closing, we may end up successfully writing out our request (or a
// portion of our request) only to find a connection error when we try to read
// from (or finish writing to) the socket.
//
// NOTE: we resend a request only if the request is idempotent, we reused a
// keep-alive connection, and we haven't yet received any header data. This
// automatically prevents an infinite resend loop because we'll run out of the
// cached keep-alive connections eventually.
func TestRetryIdempotentRequestsOnError(t *testing.T) {
	defer afterTest(t)

	var (
		mu     sync.Mutex
		logbuf bytes.Buffer
	)
	logf := func(format string, args ...interface{}) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(&logbuf, format, args...)
		logbuf.WriteByte('\n')
	}

	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		logf("Handler")
		w.Header().Set("X-Status", "ok")
	}))
	defer ts.Close()

	var writeNumAtomic int32
	tr := &Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			logf("Dial")
			c, err := net.Dial(network, ts.Listener.Addr().String())
			if err != nil {
				logf("Dial error: %v", err)
				return nil, err
			}
			return &writerFuncConn{
				Conn: c,
				write: func(p []byte) (n int, err error) {
					if atomic.AddInt32(&writeNumAtomic, 1) == 2 {
						logf("intentional write failure")
						return 0, errors.New("second write fails")
					}
					logf("Write(%q)", p)
					return c.Write(p)
				},
			}, nil
		},
	}
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr

	SetRoundTripRetried(func() {
		logf("Retried.")
	})
	defer SetRoundTripRetried(nil)

	for i := 0; i < 3; i++ {
		res, err := c.Get("http://fake.golang/")
		if err != nil {
			t.Fatalf("i=%d: Get = %v", i, err)
		}
		res.Body.Close()
	}

	mu.Lock()
	got := logbuf.String()
	mu.Unlock()
	const want = `Dial
Write("GET / HTTP/1.1\r\nHost: fake.golang\r\nUser-Agent: Mozilla/5.0 zgrab/0.x\r\nAccept-Encoding: gzip\r\n\r\n")
Handler
intentional write failure
Retried.
Dial
Write("GET / HTTP/1.1\r\nHost: fake.golang\r\nUser-Agent: Mozilla/5.0 zgrab/0.x\r\nAccept-Encoding: gzip\r\n\r\n")
Handler
Write("GET / HTTP/1.1\r\nHost: fake.golang\r\nUser-Agent: Mozilla/5.0 zgrab/0.x\r\nAccept-Encoding: gzip\r\n\r\n")
Handler
`
	if got != want {
		t.Errorf("Log of events differs. Got:\n%s\nWant:\n%s", got, want)
	}
}

// Issue 6981
func TestTransportClosesBodyOnError(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	readBody := make(chan error, 1)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		_, err := ioutil.ReadAll(r.Body)
		readBody <- err
	}))
	defer ts.Close()
	fakeErr := errors.New("fake error")
	didClose := make(chan bool, 1)
	req, _ := NewRequest("POST", ts.URL, struct {
		io.Reader
		io.Closer
	}{
		io.MultiReader(io.LimitReader(neverEnding('x'), 1<<20), errorReader{fakeErr}),
		closerFunc(func() error {
			select {
			case didClose <- true:
			default:
			}
			return nil
		}),
	})
	res, err := DefaultClient.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), fakeErr.Error()) {
		t.Fatalf("Do error = %v; want something containing %q", err, fakeErr.Error())
	}
	select {
	case err := <-readBody:
		if err == nil {
			t.Errorf("Unexpected success reading request body from handler; want 'unexpected EOF reading trailer'")
		}
	case <-time.After(5 * time.Second):
		t.Error("timeout waiting for server handler to complete")
	}
	select {
	case <-didClose:
	default:
		t.Errorf("didn't see Body.Close")
	}
}

func TestTransportDialTLS(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	var mu sync.Mutex // guards following
	var gotReq, didDial bool

	ts := httptest.NewTLSServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		mu.Lock()
		gotReq = true
		mu.Unlock()
	}))
	defer ts.Close()
	tr := &Transport{
		DialTLS: func(netw, addr string) (net.Conn, error) {
			mu.Lock()
			didDial = true
			mu.Unlock()
			c, err := tls.Dial(netw, addr, &tls.Config{
				InsecureSkipVerify: true,
			})
			if err != nil {
				return nil, err
			}
			return c, c.Handshake()
		},
	}
	defer tr.CloseIdleConnections()
	client := MakeNewClient()
	client.Transport = tr
	res, err := client.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	mu.Lock()
	if !gotReq {
		t.Error("didn't get request")
	}
	if !didDial {
		t.Error("didn't use dial hook")
	}
}

// Test for issue 8755
// Ensure that if a proxy returns an error, it is exposed by RoundTrip
func TestRoundTripReturnsProxyError(t *testing.T) {
	badProxy := func(*Request) (*url.URL, error) {
		return nil, errors.New("errorMessage")
	}

	tr := &Transport{Proxy: badProxy}

	req, _ := NewRequest("GET", "http://example.com", nil)

	_, err := tr.RoundTrip(req)

	if err == nil {
		t.Error("Expected proxy error to be returned by RoundTrip")
	}
}

// tests that putting an idle conn after a call to CloseIdleConns does return it
func TestTransportCloseIdleConnsThenReturn(t *testing.T) {
	tr := &Transport{}
	wantIdle := func(when string, n int) bool {
		got := tr.IdleConnCountForTesting("|http|example.com") // key used by PutIdleTestConn
		if got == n {
			return true
		}
		t.Errorf("%s: idle conns = %d; want %d", when, got, n)
		return false
	}
	wantIdle("start", 0)
	if !tr.PutIdleTestConn() {
		t.Fatal("put failed")
	}
	if !tr.PutIdleTestConn() {
		t.Fatal("second put failed")
	}
	wantIdle("after put", 2)
	tr.CloseIdleConnections()
	if !tr.IsIdleForTesting() {
		t.Error("should be idle after CloseIdleConnections")
	}
	wantIdle("after close idle", 0)
	if tr.PutIdleTestConn() {
		t.Fatal("put didn't fail")
	}
	wantIdle("after second put", 0)

	tr.RequestIdleConnChForTesting() // should toggle the transport out of idle mode
	if tr.IsIdleForTesting() {
		t.Error("shouldn't be idle after RequestIdleConnChForTesting")
	}
	if !tr.PutIdleTestConn() {
		t.Fatal("after re-activation")
	}
	wantIdle("after final put", 1)
}

// This tests that an client requesting a content range won't also
// implicitly ask for gzip support. If they want that, they need to do it
// on their own.
// golang.org/issue/8923
func TestTransportRangeAndGzip(t *testing.T) {
	defer afterTest(t)
	reqc := make(chan *Request, 1)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		reqc <- r
	}))
	defer ts.Close()

	req, _ := NewRequest("GET", ts.URL, nil)
	req.Header.Set("Range", "bytes=7-11")
	res, err := DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case r := <-reqc:
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			t.Error("Transport advertised gzip support in the Accept header")
		}
		if r.Header.Get("Range") == "" {
			t.Error("no Range in request")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
	res.Body.Close()
}

// Test for issue 10474
func TestTransportResponseCancelRace(t *testing.T) {
	defer afterTest(t)

	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		// important that this response has a body.
		var b [1024]byte
		w.Write(b[:])
	}))
	defer ts.Close()

	tr := &Transport{}
	defer tr.CloseIdleConnections()

	req, err := NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	// If we do an early close, Transport just throws the connection away and
	// doesn't reuse it. In order to trigger the bug, it has to reuse the connection
	// so read the body
	if _, err := io.Copy(ioutil.Discard, res.Body); err != nil {
		t.Fatal(err)
	}

	req2, err := NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr.CancelRequest(req)
	res, err = tr.RoundTrip(req2)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
}

func TestTransportDialCancelRace(t *testing.T) {
	defer afterTest(t)

	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {}))
	defer ts.Close()

	tr := &Transport{}
	defer tr.CloseIdleConnections()

	req, err := NewRequest("GET", ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	SetEnterRoundTripHook(func() {
		tr.CancelRequest(req)
	})
	defer SetEnterRoundTripHook(nil)
	res, err := tr.RoundTrip(req)
	if err != ExportErrRequestCanceled {
		t.Errorf("expected canceled request error; got %v", err)
		if err == nil {
			res.Body.Close()
		}
	}
}

// logWritesConn is a net.Conn that logs each Write call to writes
// and then proxies to w.
// It proxies Read calls to a reader it receives from rch.
type logWritesConn struct {
	net.Conn // nil. crash on use.

	w io.Writer

	rch <-chan io.Reader
	r   io.Reader // nil until received by rch

	mu     sync.Mutex
	writes []string
}

func (c *logWritesConn) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, string(p))
	return c.w.Write(p)
}

func (c *logWritesConn) Read(p []byte) (n int, err error) {
	if c.r == nil {
		c.r = <-c.rch
	}
	return c.r.Read(p)
}

func (c *logWritesConn) Close() error { return nil }

// Issue 6574
func TestTransportFlushesBodyChunks(t *testing.T) {
	defer afterTest(t)
	resBody := make(chan io.Reader, 1)
	connr, connw := io.Pipe() // connection pipe pair
	lw := &logWritesConn{
		rch: resBody,
		w:   connw,
	}
	tr := &Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return lw, nil
		},
	}
	bodyr, bodyw := io.Pipe() // body pipe pair
	go func() {
		defer bodyw.Close()
		for i := 0; i < 3; i++ {
			fmt.Fprintf(bodyw, "num%d\n", i)
		}
	}()
	resc := make(chan *Response)
	go func() {
		req, _ := NewRequest("POST", "http://localhost:8080", bodyr)
		req.Header.Set("User-Agent", "x") // known value for test
		res, err := tr.RoundTrip(req)
		if err != nil {
			t.Errorf("RoundTrip: %v", err)
			close(resc)
			return
		}
		resc <- res

	}()
	// Fully consume the request before checking the Write log vs. want.
	req, err := ReadRequest(bufio.NewReader(connr))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(ioutil.Discard, req.Body)

	// Unblock the transport's roundTrip goroutine.
	resBody <- strings.NewReader("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
	res, ok := <-resc
	if !ok {
		return
	}
	defer res.Body.Close()

	want := []string{
		"POST / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: x\r\nTransfer-Encoding: chunked\r\nAccept-Encoding: gzip\r\n\r\n" +
			"5\r\nnum0\n\r\n",
		"5\r\nnum1\n\r\n",
		"5\r\nnum2\n\r\n",
		"0\r\n\r\n",
	}
	if !reflect.DeepEqual(lw.writes, want) {
		t.Errorf("Writes differed.\n Got: %q\nWant: %q\n", lw.writes, want)
	}
}

// Issue 11745.
func TestTransportPrefersResponseOverWriteError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	defer afterTest(t)
	const contentLengthLimit = 1024 * 1024 // 1MB
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.ContentLength >= contentLengthLimit {
			w.WriteHeader(StatusBadRequest)
			r.Body.Close()
			return
		}
		w.WriteHeader(StatusOK)
	}))
	defer ts.Close()

	fail := 0
	count := 100
	bigBody := strings.Repeat("a", contentLengthLimit*2)
	for i := 0; i < count; i++ {
		req, err := NewRequest("PUT", ts.URL, strings.NewReader(bigBody))
		if err != nil {
			t.Fatal(err)
		}
		tr := new(Transport)
		defer tr.CloseIdleConnections()
		client := MakeNewClient()
		client.Transport = tr
		resp, err := client.Do(req)
		if err != nil {
			fail++
			t.Logf("%d = %#v", i, err)
			if ue, ok := err.(*url.Error); ok {
				t.Logf("urlErr = %#v", ue.Err)
				if ne, ok := ue.Err.(*net.OpError); ok {
					t.Logf("netOpError = %#v", ne.Err)
				}
			}
		} else {
			resp.Body.Close()
			if resp.StatusCode != 400 {
				t.Errorf("Expected status code 400, got %v", resp.Status)
			}
		}
	}
	if fail > 0 {
		t.Errorf("Failed %v out of %v\n", fail, count)
	}
}

func TestTransportAutomaticHTTP2(t *testing.T) {
	testTransportAutoHTTP(t, &Transport{}, true)
}

// golang.org/issue/14391: also check DefaultTransport
func TestTransportAutomaticHTTP2_DefaultTransport(t *testing.T) {
	testTransportAutoHTTP(t, DefaultTransport.(*Transport), true)
}

func TestTransportAutomaticHTTP2_TLSNextProto(t *testing.T) {
	testTransportAutoHTTP(t, &Transport{
		TLSNextProto: make(map[string]func(string, *tls.Conn) RoundTripper),
	}, false)
}

func TestTransportAutomaticHTTP2_TLSConfig(t *testing.T) {
	testTransportAutoHTTP(t, &Transport{
		TLSClientConfig: new(tls.Config),
	}, false)
}

func TestTransportAutomaticHTTP2_ExpectContinueTimeout(t *testing.T) {
	testTransportAutoHTTP(t, &Transport{
		ExpectContinueTimeout: 1 * time.Second,
	}, true)
}

func TestTransportAutomaticHTTP2_Dial(t *testing.T) {
	var d net.Dialer
	testTransportAutoHTTP(t, &Transport{
		Dial: d.Dial,
	}, false)
}

func TestTransportAutomaticHTTP2_DialTLS(t *testing.T) {
	testTransportAutoHTTP(t, &Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			panic("unused")
		},
	}, false)
}

func testTransportAutoHTTP(t *testing.T, tr *Transport, wantH2 bool) {
	_, err := tr.RoundTrip(new(Request))
	if err == nil {
		t.Error("expected error from RoundTrip")
	}
	if reg := tr.TLSNextProto["h2"] != nil; reg != wantH2 {
		t.Errorf("HTTP/2 registered = %v; want %v", reg, wantH2)
	}
}

// Issue 13633: there was a race where we returned bodyless responses
// to callers before recycling the persistent connection, which meant
// a client doing two subsequent requests could end up on different
// connections. It's somewhat harmless but enough tests assume it's
// not true in order to test other things that it's worth fixing.
// Plus it's nice to be consistent and not have timing-dependent
// behavior.
func TestTransportReuseConnEmptyResponseBody(t *testing.T) {
	defer afterTest(t)
	cst := newClientServerTest(t, h1Mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		w.Header().Set("X-Addr", r.RemoteAddr)
		// Empty response body.
	}))
	defer cst.close()
	n := 100
	if testing.Short() {
		n = 10
	}
	var firstAddr string
	for i := 0; i < n; i++ {
		res, err := cst.c.Get(cst.ts.URL)
		if err != nil {
			log.Fatal(err)
		}
		addr := res.Header.Get("X-Addr")
		if i == 0 {
			firstAddr = addr
		} else if addr != firstAddr {
			t.Fatalf("On request %d, addr %q != original addr %q", i+1, addr, firstAddr)
		}
		res.Body.Close()
	}
}

// Issue 13839
func TestNoCrashReturningTransportAltConn(t *testing.T) {
	cert, err := tls.X509KeyPair(LocalhostCert, LocalhostKey)
	if err != nil {
		t.Fatal(err)
	}
	ln := newLocalListener(t)
	defer ln.Close()

	handledPendingDial := make(chan bool, 1)
	SetPendingDialHooks(nil, func() { handledPendingDial <- true })
	defer SetPendingDialHooks(nil, nil)

	testDone := make(chan struct{})
	defer close(testDone)
	go func() {
		tln := tls.NewListener(ln, &tls.Config{
			NextProtos:   []string{"foo"},
			Certificates: []tls.Certificate{cert},
		})
		sc, err := tln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		if err := sc.(*tls.Conn).Handshake(); err != nil {
			t.Error(err)
			return
		}
		<-testDone
		sc.Close()
	}()

	addr := ln.Addr().String()

	req, _ := NewRequest("GET", "https://fake.tld/", nil)
	cancel := make(chan struct{})
	req.Cancel = cancel

	doReturned := make(chan bool, 1)
	madeRoundTripper := make(chan bool, 1)

	tr := &Transport{
		DisableKeepAlives: true,
		TLSNextProto: map[string]func(string, *tls.Conn) RoundTripper{
			"foo": func(authority string, c *tls.Conn) RoundTripper {
				madeRoundTripper <- true
				return funcRoundTripper(func() {
					t.Error("foo RoundTripper should not be called")
				})
			},
		},
		Dial: func(_, _ string) (net.Conn, error) {
			panic("shouldn't be called")
		},
		DialTLS: func(_, _ string) (net.Conn, error) {
			tc, err := tls.Dial("tcp", addr, &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"foo"},
			})
			if err != nil {
				return nil, err
			}
			if err := tc.Handshake(); err != nil {
				return nil, err
			}
			close(cancel)
			<-doReturned
			return tc, nil
		},
	}
	c := MakeNewClient()
	c.Transport = tr

	_, err = c.Do(req)
	if ue, ok := err.(*url.Error); !ok || ue.Err != ExportErrRequestCanceledConn {
		t.Fatalf("Do error = %v; want url.Error with errRequestCanceledConn", err)
	}

	doReturned <- true
	<-madeRoundTripper
	<-handledPendingDial
}

func TestTransportReuseConnection_Gzip_Chunked(t *testing.T) {
	testTransportReuseConnection_Gzip(t, true)
}

func TestTransportReuseConnection_Gzip_ContentLength(t *testing.T) {
	testTransportReuseConnection_Gzip(t, false)
}

// Make sure we re-use underlying TCP connection for gzipped responses too.
func testTransportReuseConnection_Gzip(t *testing.T, chunked bool) {
	setParallel(t)
	defer afterTest(t)
	addr := make(chan string, 2)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		addr <- r.RemoteAddr
		w.Header().Set("Content-Encoding", "gzip")
		if chunked {
			w.(Flusher).Flush()
		}
		w.Write(rgz) // arbitrary gzip response
	}))
	defer ts.Close()

	tr := &Transport{}
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr

	for i := 0; i < 2; i++ {
		res, err := c.Get(ts.URL)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(rgz))
		if n, err := io.ReadFull(res.Body, buf); err != nil {
			t.Errorf("%d. ReadFull = %v, %v", i, n, err)
		}
		// Note: no res.Body.Close call. It should work without it,
		// since the flate.Reader's internal buffering will hit EOF
		// and that should be sufficient.
	}
	a1, a2 := <-addr, <-addr
	if a1 != a2 {
		t.Fatalf("didn't reuse connection")
	}
}

func TestTransportResponseHeaderLength(t *testing.T) {
	setParallel(t)
	defer afterTest(t)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.URL.Path == "/long" {
			w.Header().Set("Long", strings.Repeat("a", 1<<20))
		}
	}))
	defer ts.Close()

	tr := &Transport{
		MaxResponseHeaderBytes: 512 << 10,
	}
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr

	if res, err := c.Get(ts.URL); err != nil {
		t.Fatal(err)
	} else {
		res.Body.Close()
	}

	res, err := c.Get(ts.URL + "/long")
	if err == nil {
		defer res.Body.Close()
		var n int64
		for k, vv := range res.Header {
			for _, v := range vv {
				n += int64(len(k)) + int64(len(v))
			}
		}
		t.Fatalf("Unexpected success. Got %v and %d bytes of response headers", res.Status, n)
	}
	if want := "server response headers exceeded 524288 bytes"; !strings.Contains(err.Error(), want) {
		t.Errorf("got error: %v; want %q", err, want)
	}
}

//func TestTransportEventTrace(t *testing.T)    { testTransportEventTrace(t, h1Mode, false) }
//func TestTransportEventTrace_h2(t *testing.T) { testTransportEventTrace(t, h2Mode, false) }

// test a non-nil httptrace.ClientTrace but with all hooks set to zero.
//func TestTransportEventTrace_NoHooks(t *testing.T)    { testTransportEventTrace(t, h1Mode, true) }
//func TestTransportEventTrace_NoHooks_h2(t *testing.T) { testTransportEventTrace(t, h2Mode, true) }
/*
func testTransportEventTrace(t *testing.T, h2 bool, noHooks bool) {
	defer afterTest(t)
	const resBody = "some body"
	gotWroteReqEvent := make(chan struct{})
	cst := newClientServerTest(t, h2, HandlerFunc(func(w ResponseWriter, r *Request) {
		if _, err := ioutil.ReadAll(r.Body); err != nil {
			t.Error(err)
		}
		if !noHooks {
			select {
			case <-gotWroteReqEvent:
			case <-time.After(5 * time.Second):
				t.Error("timeout waiting for WroteRequest event")
			}
		}
		io.WriteString(w, resBody)
	}))
	defer cst.close()

	cst.tr.ExpectContinueTimeout = 1 * time.Second

	var mu sync.Mutex // guards buf
	var buf bytes.Buffer
	logf := func(format string, args ...interface{}) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(&buf, format, args...)
		buf.WriteByte('\n')
	}

	addrStr := cst.ts.Listener.Addr().String()
	ip, port, err := net.SplitHostPort(addrStr)
	if err != nil {
		t.Fatal(err)
	}

	// Install a fake DNS server.
	ctx := context.WithValue(context.Background(), nettrace.LookupIPAltResolverKey{}, func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if host != "dns-is-faked.golang" {
			t.Errorf("unexpected DNS host lookup for %q", host)
			return nil, nil
		}
		return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
	})

	req, _ := NewRequest("POST", cst.scheme()+"://dns-is-faked.golang:"+port, strings.NewReader("some body"))
	trace := &httptrace.ClientTrace{
		GetConn:              func(hostPort string) { logf("Getting conn for %v ...", hostPort) },
		GotConn:              func(ci httptrace.GotConnInfo) { logf("got conn: %+v", ci) },
		GotFirstResponseByte: func() { logf("first response byte") },
		PutIdleConn:          func(err error) { logf("PutIdleConn = %v", err) },
		DNSStart:             func(e httptrace.DNSStartInfo) { logf("DNS start: %+v", e) },
		DNSDone:              func(e httptrace.DNSDoneInfo) { logf("DNS done: %+v", e) },
		ConnectStart:         func(network, addr string) { logf("ConnectStart: Connecting to %s %s ...", network, addr) },
		ConnectDone: func(network, addr string, err error) {
			if err != nil {
				t.Errorf("ConnectDone: %v", err)
			}
			logf("ConnectDone: connected to %s %s = %v", network, addr, err)
		},
		Wait100Continue: func() { logf("Wait100Continue") },
		Got100Continue:  func() { logf("Got100Continue") },
		WroteRequest: func(e httptrace.WroteRequestInfo) {
			logf("WroteRequest: %+v", e)
			close(gotWroteReqEvent)
		},
	}
	if h2 {
		trace.TLSHandshakeStart = func() { logf("tls handshake start") }
		trace.TLSHandshakeDone = func(s tls.ConnectionState, err error) {
			logf("tls handshake done. ConnectionState = %v \n err = %v", s, err)
		}
	}
	if noHooks {
		// zero out all func pointers, trying to get some path to crash
		*trace = httptrace.ClientTrace{}
	}
	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))

	req.Header.Set("Expect", "100-continue")
	res, err := cst.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	logf("got roundtrip.response")
	slurp, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	logf("consumed body")
	if string(slurp) != resBody || res.StatusCode != 200 {
		t.Fatalf("Got %q, %v; want %q, 200 OK", slurp, res.Status, resBody)
	}
	res.Body.Close()

	if noHooks {
		// Done at this point. Just testing a full HTTP
		// requests can happen with a trace pointing to a zero
		// ClientTrace, full of nil func pointers.
		return
	}

	mu.Lock()
	got := buf.String()
	mu.Unlock()

	wantOnce := func(sub string) {
		if strings.Count(got, sub) != 1 {
			t.Errorf("expected substring %q exactly once in output.", sub)
		}
	}
	wantOnceOrMore := func(sub string) {
		if strings.Count(got, sub) == 0 {
			t.Errorf("expected substring %q at least once in output.", sub)
		}
	}
	wantOnce("Getting conn for dns-is-faked.golang:" + port)
	wantOnce("DNS start: {Host:dns-is-faked.golang}")
	wantOnce("DNS done: {Addrs:[{IP:" + ip + " Zone:}] Err:<nil> Coalesced:false}")
	wantOnce("got conn: {")
	wantOnceOrMore("Connecting to tcp " + addrStr)
	wantOnceOrMore("connected to tcp " + addrStr + " = <nil>")
	wantOnce("Reused:false WasIdle:false IdleTime:0s")
	wantOnce("first response byte")
	if h2 {
		wantOnce("tls handshake start")
		wantOnce("tls handshake done")
	} else {
		wantOnce("PutIdleConn = <nil>")
	}
	wantOnce("Wait100Continue")
	wantOnce("Got100Continue")
	wantOnce("WroteRequest: {Err:<nil>}")
	if strings.Contains(got, " to udp ") {
		t.Errorf("should not see UDP (DNS) connections")
	}
	if t.Failed() {
		t.Errorf("Output:\n%s", got)
	}
}

func TestTransportEventTraceRealDNS(t *testing.T) {
	if testing.Short() {
		// Skip this test in short mode (the default for
		// all.bash), in case the user is using a shady/ISP
		// DNS server hijacking queries.
		// See issues 16732, 16716.
		// Our builders use 8.8.8.8, though, which correctly
		// returns NXDOMAIN, so still run this test there.
		t.Skip("skipping in short mode")
	}
	defer afterTest(t)
	tr := &Transport{}
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr
	var mu sync.Mutex // guards buf
	var buf bytes.Buffer
	logf := func(format string, args ...interface{}) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(&buf, format, args...)
		buf.WriteByte('\n')
	}

	req, _ := NewRequest("GET", "http://dns-should-not-resolve.golang:80", nil)
	trace := &httptrace.ClientTrace{
		DNSStart:     func(e httptrace.DNSStartInfo) { logf("DNSStart: %+v", e) },
		DNSDone:      func(e httptrace.DNSDoneInfo) { logf("DNSDone: %+v", e) },
		ConnectStart: func(network, addr string) { logf("ConnectStart: %s %s", network, addr) },
		ConnectDone:  func(network, addr string, err error) { logf("ConnectDone: %s %s %v", network, addr, err) },
	}
	req = req.WithContext(httptrace.WithClientTrace(context.Background(), trace))

	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected error during DNS lookup")
	}

	mu.Lock()
	got := buf.String()
	mu.Unlock()

	wantSub := func(sub string) {
		if !strings.Contains(got, sub) {
			t.Errorf("expected substring %q in output.", sub)
		}
	}
	wantSub("DNSStart: {Host:dns-should-not-resolve.golang}")
	wantSub("DNSDone: {Addrs:[] Err:")
	if strings.Contains(got, "ConnectStart") || strings.Contains(got, "ConnectDone") {
		t.Errorf("should not see Connect events")
	}
	if t.Failed() {
		t.Errorf("Output:\n%s", got)
	}
}*/

// Issue 14353: port can only contain digits.
func TestTransportRejectsAlphaPort(t *testing.T) {
	res, err := Get("http://dummy.tld:123foo/bar")
	if err == nil {
		res.Body.Close()
		t.Fatal("unexpected success")
	}
	ue, ok := err.(*url.Error)
	if !ok {
		t.Fatalf("got %#v; want *url.Error", err)
	}
	got := ue.Err.Error()
	want := `invalid URL port "123foo"`
	if got != want {
		t.Errorf("got error %q; want %q", got, want)
	}
}

// Test the httptrace.TLSHandshake{Start,Done} hooks with a https http1
// connections. The http2 test is done in TestTransportEventTrace_h2
func TestTLSHandshakeTrace(t *testing.T) {
	defer afterTest(t)
	s := httptest.NewTLSServer(HandlerFunc(func(w ResponseWriter, r *Request) {}))
	defer s.Close()

	var mu sync.Mutex
	var start, done bool
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() {
			mu.Lock()
			defer mu.Unlock()
			start = true
		},
		TLSHandshakeDone: func(s tls.ConnectionState, err error) {
			mu.Lock()
			defer mu.Unlock()
			done = true
			if err != nil {
				t.Fatal("Expected error to be nil but was:", err)
			}
		},
	}

	tr := &Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr

	req, err := NewRequest("GET", s.URL, nil)
	if err != nil {
		t.Fatal("Unable to construct test request:", err)
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	r, err := c.Do(req)
	if err != nil {
		t.Fatal("Unexpected error making request:", err)
	}
	r.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if !start {
		t.Fatal("Expected TLSHandshakeStart to be called, but wasn't")
	}
	if !done {
		t.Fatal("Expected TLSHandshakeDone to be called, but wasnt't")
	}
}

/*
func TestTransportMaxIdleConns(t *testing.T) {
	defer afterTest(t)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		// No body for convenience.
	}))
	defer ts.Close()
	tr := &Transport{
		MaxIdleConns: 4,
	}
	defer tr.CloseIdleConnections()

	ip, port, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c := MakeNewClient()
	c.Transport = tr
	ctx := context.WithValue(context.Background(), nettrace.LookupIPAltResolverKey{}, func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
	})

	hitHost := func(n int) {
		req, _ := NewRequest("GET", fmt.Sprintf("http://host-%d.dns-is-faked.golang:"+port, n), nil)
		req = req.WithContext(ctx)
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
	}
	for i := 0; i < 4; i++ {
		hitHost(i)
	}
	want := []string{
		"|http|host-0.dns-is-faked.golang:" + port,
		"|http|host-1.dns-is-faked.golang:" + port,
		"|http|host-2.dns-is-faked.golang:" + port,
		"|http|host-3.dns-is-faked.golang:" + port,
	}
	if got := tr.IdleConnKeysForTesting(); !reflect.DeepEqual(got, want) {
		t.Fatalf("idle conn keys mismatch.\n got: %q\nwant: %q\n", got, want)
	}

	// Now hitting the 5th host should kick out the first host:
	hitHost(4)
	want = []string{
		"|http|host-1.dns-is-faked.golang:" + port,
		"|http|host-2.dns-is-faked.golang:" + port,
		"|http|host-3.dns-is-faked.golang:" + port,
		"|http|host-4.dns-is-faked.golang:" + port,
	}
	if got := tr.IdleConnKeysForTesting(); !reflect.DeepEqual(got, want) {
		t.Fatalf("idle conn keys mismatch after 5th host.\n got: %q\nwant: %q\n", got, want)
	}
}*/

func TestTransportIdleConnTimeout_h1(t *testing.T) { testTransportIdleConnTimeout(t, h1Mode) }

//func TestTransportIdleConnTimeout_h2(t *testing.T) { testTransportIdleConnTimeout(t, h2Mode) }
func testTransportIdleConnTimeout(t *testing.T, h2 bool) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	defer afterTest(t)

	const timeout = 1 * time.Second

	cst := newClientServerTest(t, h2, HandlerFunc(func(w ResponseWriter, r *Request) {
		// No body for convenience.
	}))
	defer cst.close()
	tr := cst.tr
	tr.IdleConnTimeout = timeout
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr
	idleConns := func() []string {
		if h2 {
			return nil //tr.IdleConnStrsForTesting_h2()
		} else {
			return tr.IdleConnStrsForTesting()
		}
	}

	var conn string
	doReq := func(n int) {
		req, _ := NewRequest("GET", cst.ts.URL, nil)
		req = req.WithContext(httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
			PutIdleConn: func(err error) {
				if err != nil {
					t.Errorf("failed to keep idle conn: %v", err)
				}
			},
		}))
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		conns := idleConns()
		if len(conns) != 1 {
			t.Fatalf("req %v: unexpected number of idle conns: %q", n, conns)
		}
		if conn == "" {
			conn = conns[0]
		}
		if conn != conns[0] {
			t.Fatalf("req %v: cached connection changed; expected the same one throughout the test", n)
		}
	}
	for i := 0; i < 3; i++ {
		doReq(i)
		time.Sleep(timeout / 2)
	}
	time.Sleep(timeout * 3 / 2)
	if got := idleConns(); len(got) != 0 {
		t.Errorf("idle conns = %q; want none", got)
	}
}

// Issue 16208: Go 1.7 crashed after Transport.IdleConnTimeout if an
// HTTP/2 connection was established but but its caller no longer
// wanted it. (Assuming the connection cache was enabled, which it is
// by default)
//
// This test reproduced the crash by setting the IdleConnTimeout low
// (to make the test reasonable) and then making a request which is
// canceled by the DialTLS hook, which then also waits to return the
// real connection until after the RoundTrip saw the error.  Then we
// know the successful tls.Dial from DialTLS will need to go into the
// idle pool. Then we give it a of time to explode.
func TestIdleConnH2Crash(t *testing.T) {
	setParallel(t)
	cst := newClientServerTest(t, h2Mode, HandlerFunc(func(w ResponseWriter, r *Request) {
		// nothing
	}))
	defer cst.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sawDoErr := make(chan bool, 1)
	testDone := make(chan struct{})
	defer close(testDone)

	cst.tr.IdleConnTimeout = 5 * time.Millisecond
	cst.tr.DialTLS = func(network, addr string) (net.Conn, error) {
		c, err := tls.Dial(network, addr, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		})
		if err != nil {
			t.Error(err)
			return nil, err
		}
		if cs := c.ConnectionState(); cs.NegotiatedProtocol != "h2" {
			t.Errorf("protocol = %q; want %q", cs.NegotiatedProtocol, "h2")
			c.Close()
			return nil, errors.New("bogus")
		}

		cancel()

		failTimer := time.NewTimer(5 * time.Second)
		defer failTimer.Stop()
		select {
		case <-sawDoErr:
		case <-testDone:
		case <-failTimer.C:
			t.Error("timeout in DialTLS, waiting too long for cst.c.Do to fail")
		}
		return c, nil
	}

	req, _ := NewRequest("GET", cst.ts.URL, nil)
	req = req.WithContext(ctx)
	res, err := cst.c.Do(req)
	if err == nil {
		res.Body.Close()
		t.Fatal("unexpected success")
	}
	sawDoErr <- true

	// Wait for the explosion.
	time.Sleep(cst.tr.IdleConnTimeout * 10)
}

type funcConn struct {
	net.Conn
	read  func([]byte) (int, error)
	write func([]byte) (int, error)
}

func (c funcConn) Read(p []byte) (int, error)  { return c.read(p) }
func (c funcConn) Write(p []byte) (int, error) { return c.write(p) }
func (c funcConn) Close() error                { return nil }

// Issue 16465: Transport.RoundTrip should return the raw net.Conn.Read error from Peek
// back to the caller.
func TestTransportReturnsPeekError(t *testing.T) {
	errValue := errors.New("specific error value")

	wrote := make(chan struct{})
	var wroteOnce sync.Once

	tr := &Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			c := funcConn{
				read: func([]byte) (int, error) {
					<-wrote
					return 0, errValue
				},
				write: func(p []byte) (int, error) {
					wroteOnce.Do(func() { close(wrote) })
					return len(p), nil
				},
			}
			return c, nil
		},
	}
	_, err := tr.RoundTrip(httptest.NewRequest("GET", "http://fake.tld/", nil))
	if err != errValue {
		t.Errorf("error = %#v; want %v", err, errValue)
	}
}

/*
// Issue 13835: international domain names should work
func TestTransportIDNA_h1(t *testing.T) { testTransportIDNA(t, h1Mode) }
//func TestTransportIDNA_h2(t *testing.T) { testTransportIDNA(t, h2Mode) }
func testTransportIDNA(t *testing.T, h2 bool) {
	defer afterTest(t)

	const uniDomain = "гофер.го"
	const punyDomain = "xn--c1ae0ajs.xn--c1aw"

	var port string
	cst := newClientServerTest(t, h2, HandlerFunc(func(w ResponseWriter, r *Request) {
		want := punyDomain + ":" + port
		if r.Host != want {
			t.Errorf("Host header = %q; want %q", r.Host, want)
		}
		if h2 {
			if r.TLS == nil {
				t.Errorf("r.TLS == nil")
			} else if r.TLS.ServerName != punyDomain {
				t.Errorf("TLS.ServerName = %q; want %q", r.TLS.ServerName, punyDomain)
			}
		}
		w.Header().Set("Hit-Handler", "1")
	}))
	defer cst.close()

	ip, port, err := net.SplitHostPort(cst.ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Install a fake DNS server.
	ctx := context.WithValue(context.Background(), nettrace.LookupIPAltResolverKey{}, func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if host != punyDomain {
			t.Errorf("got DNS host lookup for %q; want %q", host, punyDomain)
			return nil, nil
		}
		return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
	})

	req, _ := NewRequest("GET", cst.scheme()+"://"+uniDomain+":"+port, nil)
	trace := &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			want := net.JoinHostPort(punyDomain, port)
			if hostPort != want {
				t.Errorf("getting conn for %q; want %q", hostPort, want)
			}
		},
		DNSStart: func(e httptrace.DNSStartInfo) {
			if e.Host != punyDomain {
				t.Errorf("DNSStart Host = %q; want %q", e.Host, punyDomain)
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))

	res, err := cst.tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.Header.Get("Hit-Handler") != "1" {
		out, err := httputil.DumpResponse(res, true)
		if err != nil {
			t.Fatal(err)
		}
		t.Errorf("Response body wasn't from Handler. Got:\n%s\n", out)
	}
}*/

// Issue 13290: send User-Agent in proxy CONNECT
func TestTransportProxyConnectHeader(t *testing.T) {
	defer afterTest(t)
	reqc := make(chan *Request, 1)
	ts := httptest.NewServer(HandlerFunc(func(w ResponseWriter, r *Request) {
		if r.Method != "CONNECT" {
			t.Errorf("method = %q; want CONNECT", r.Method)
		}
		reqc <- r
		c, _, err := w.(Hijacker).Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		c.Close()
	}))
	defer ts.Close()
	tr := &Transport{
		ProxyConnectHeader: Header{
			"User-Agent": {"foo"},
			"Other":      {"bar"},
		},
		Proxy: func(r *Request) (*url.URL, error) {
			return url.Parse(ts.URL)
		},
	}
	defer tr.CloseIdleConnections()
	c := MakeNewClient()
	c.Transport = tr
	res, err := c.Get("https://dummy.tld/") // https to force a CONNECT
	if err == nil {
		res.Body.Close()
		t.Errorf("unexpected success")
	}
	select {
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	case r := <-reqc:
		if got, want := r.Header.Get("User-Agent"), "foo"; got != want {
			t.Errorf("CONNECT request User-Agent = %q; want %q", got, want)
		}
		if got, want := r.Header.Get("Other"), "bar"; got != want {
			t.Errorf("CONNECT request Other = %q; want %q", got, want)
		}
	}
}

var errFakeRoundTrip = errors.New("fake roundtrip")

type funcRoundTripper func()

func (fn funcRoundTripper) RoundTrip(*Request) (*Response, error) {
	fn()
	return nil, errFakeRoundTrip
}

func wantBody(res *Response, err error, want string) error {
	if err != nil {
		return err
	}
	slurp, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("error reading body: %v", err)
	}
	if string(slurp) != want {
		return fmt.Errorf("body = %q; want %q", slurp, want)
	}
	if err := res.Body.Close(); err != nil {
		return fmt.Errorf("body Close = %v", err)
	}
	return nil
}

func newLocalListener(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		ln, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

type countCloseReader struct {
	n *int
	io.Reader
}

func (cr countCloseReader) Close() error {
	(*cr.n)++
	return nil
}

// rgz is a gzip quine that uncompresses to itself.
var rgz = []byte{
	0x1f, 0x8b, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x72, 0x65, 0x63, 0x75, 0x72, 0x73,
	0x69, 0x76, 0x65, 0x00, 0x92, 0xef, 0xe6, 0xe0,
	0x60, 0x00, 0x83, 0xa2, 0xd4, 0xe4, 0xd2, 0xa2,
	0xe2, 0xcc, 0xb2, 0x54, 0x06, 0x00, 0x00, 0x17,
	0x00, 0xe8, 0xff, 0x92, 0xef, 0xe6, 0xe0, 0x60,
	0x00, 0x83, 0xa2, 0xd4, 0xe4, 0xd2, 0xa2, 0xe2,
	0xcc, 0xb2, 0x54, 0x06, 0x00, 0x00, 0x17, 0x00,
	0xe8, 0xff, 0x42, 0x12, 0x46, 0x16, 0x06, 0x00,
	0x05, 0x00, 0xfa, 0xff, 0x42, 0x12, 0x46, 0x16,
	0x06, 0x00, 0x05, 0x00, 0xfa, 0xff, 0x00, 0x05,
	0x00, 0xfa, 0xff, 0x00, 0x14, 0x00, 0xeb, 0xff,
	0x42, 0x12, 0x46, 0x16, 0x06, 0x00, 0x05, 0x00,
	0xfa, 0xff, 0x00, 0x05, 0x00, 0xfa, 0xff, 0x00,
	0x14, 0x00, 0xeb, 0xff, 0x42, 0x88, 0x21, 0xc4,
	0x00, 0x00, 0x14, 0x00, 0xeb, 0xff, 0x42, 0x88,
	0x21, 0xc4, 0x00, 0x00, 0x14, 0x00, 0xeb, 0xff,
	0x42, 0x88, 0x21, 0xc4, 0x00, 0x00, 0x14, 0x00,
	0xeb, 0xff, 0x42, 0x88, 0x21, 0xc4, 0x00, 0x00,
	0x14, 0x00, 0xeb, 0xff, 0x42, 0x88, 0x21, 0xc4,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
	0x00, 0xff, 0xff, 0x00, 0x17, 0x00, 0xe8, 0xff,
	0x42, 0x88, 0x21, 0xc4, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
	0x17, 0x00, 0xe8, 0xff, 0x42, 0x12, 0x46, 0x16,
	0x06, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x08,
	0x00, 0xf7, 0xff, 0x3d, 0xb1, 0x20, 0x85, 0xfa,
	0x00, 0x00, 0x00, 0x42, 0x12, 0x46, 0x16, 0x06,
	0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x08, 0x00,
	0xf7, 0xff, 0x3d, 0xb1, 0x20, 0x85, 0xfa, 0x00,
	0x00, 0x00, 0x3d, 0xb1, 0x20, 0x85, 0xfa, 0x00,
	0x00, 0x00,
}

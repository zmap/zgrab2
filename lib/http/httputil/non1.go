// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Reverse proxy tests.

package httputil

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zmap/zgrab2/lib/http"
	"github.com/zmap/zgrab2/lib/http/httptest"
)

const fakeHopHeader = "X-Fake-Hop-Header-For-Test"

func init() {
	hopHeaders = append(hopHeaders, fakeHopHeader)
}

func TestReverseProxy(t *testing.T) {
	const backendResponse = "I am the backend"
	const backendStatus = 404
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.FormValue("mode") == "hangup" {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
			return
		}
		if len(r.TransferEncoding) > 0 {
			t.Errorf("backend got unexpected TransferEncoding: %v", r.TransferEncoding)
		}
		if r.Header.Get("X-Forwarded-For") == "" {
			t.Errorf("didn't get X-Forwarded-For header")
		}
		if c := r.Header.Get("Connection"); c != "" {
			t.Errorf("handler got Connection header value %q", c)
		}
		if c := r.Header.Get("Upgrade"); c != "" {
			t.Errorf("handler got Upgrade header value %q", c)
		}
		if c := r.Header.Get("Proxy-Connection"); c != "" {
			t.Errorf("handler got Proxy-Connection header value %q", c)
		}
		if g, e := r.Host, "some-name"; g != e {
			t.Errorf("backend got Host header %q, want %q", g, e)
		}
		w.Header().Set("Trailers", "not a special header field name")
		w.Header().Set("Trailer", "X-Trailer")
		w.Header().Set("X-Foo", "bar")
		w.Header().Set("Upgrade", "foo")
		w.Header().Set(fakeHopHeader, "foo")
		w.Header().Add("X-Multi-Value", "foo")
		w.Header().Add("X-Multi-Value", "bar")
		http.SetCookie(w, &http.Cookie{Name: "flavor", Value: "chocolateChip"})
		w.WriteHeader(backendStatus)
		w.Write([]byte(backendResponse))
		w.Header().Set("X-Trailer", "trailer_value")
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	proxyHandler.ErrorLog = log.New(ioutil.Discard, "", 0) // quiet for tests
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	getReq.Host = "some-name"
	getReq.Header.Set("Connection", "close")
	getReq.Header.Set("Proxy-Connection", "should be deleted")
	getReq.Header.Set("Upgrade", "foo")
	getReq.Close = true
	res, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if g, e := res.StatusCode, backendStatus; g != e {
		t.Errorf("got res.StatusCode %d; expected %d", g, e)
	}
	if g, e := res.Header.Get("X-Foo"), "bar"; g != e {
		t.Errorf("got X-Foo %q; expected %q", g, e)
	}
	if c := res.Header.Get(fakeHopHeader); c != "" {
		t.Errorf("got %s header value %q", fakeHopHeader, c)
	}
	if g, e := res.Header.Get("Trailers"), "not a special header field name"; g != e {
		t.Errorf("header Trailers = %q; want %q", g, e)
	}
	if g, e := len(res.Header["X-Multi-Value"]), 2; g != e {
		t.Errorf("got %d X-Multi-Value header values; expected %d", g, e)
	}
	if g, e := len(res.Header["Set-Cookie"]), 1; g != e {
		t.Fatalf("got %d SetCookies, want %d", g, e)
	}
	if g, e := res.Trailer, (http.Header{"X-Trailer": nil}); !reflect.DeepEqual(g, e) {
		t.Errorf("before reading body, Trailer = %#v; want %#v", g, e)
	}
	if cookie := res.Cookies()[0]; cookie.Name != "flavor" {
		t.Errorf("unexpected cookie %q", cookie.Name)
	}
	bodyBytes, _ := ioutil.ReadAll(res.Body)
	if g, e := string(bodyBytes), backendResponse; g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}
	if g, e := res.Trailer.Get("X-Trailer"), "trailer_value"; g != e {
		t.Errorf("Trailer(X-Trailer) = %q ; want %q", g, e)
	}

	// Test that a backend failing to be reached or one which doesn't return
	// a response results in a StatusBadGateway.
	getReq, _ = http.NewRequest("GET", frontend.URL+"/?mode=hangup", nil)
	getReq.Close = true
	res, err = http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadGateway {
		t.Errorf("request to bad proxy = %v; want 502 StatusBadGateway", res.Status)
	}

}

// Issue 16875: remove any proxied headers mentioned in the "Connection"
// header value.
func TestReverseProxyStripHeadersPresentInConnection(t *testing.T) {
	const fakeConnectionToken = "X-Fake-Connection-Token"
	const backendResponse = "I am the backend"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c := r.Header.Get(fakeConnectionToken); c != "" {
			t.Errorf("handler got header %q = %q; want empty", fakeConnectionToken, c)
		}
		if c := r.Header.Get("Upgrade"); c != "" {
			t.Errorf("handler got header %q = %q; want empty", "Upgrade", c)
		}
		w.Header().Set("Connection", "Upgrade, "+fakeConnectionToken)
		w.Header().Set("Upgrade", "should be deleted")
		w.Header().Set(fakeConnectionToken, "should be deleted")
		io.WriteString(w, backendResponse)
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHandler.ServeHTTP(w, r)
		if c := r.Header.Get("Upgrade"); c != "original value" {
			t.Errorf("handler modified header %q = %q; want %q", "Upgrade", c, "original value")
		}
	}))
	defer frontend.Close()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	getReq.Header.Set("Connection", "Upgrade, "+fakeConnectionToken)
	getReq.Header.Set("Upgrade", "original value")
	getReq.Header.Set(fakeConnectionToken, "should be deleted")
	res, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer res.Body.Close()
	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if got, want := string(bodyBytes), backendResponse; got != want {
		t.Errorf("got body %q; want %q", got, want)
	}
	if c := res.Header.Get("Upgrade"); c != "" {
		t.Errorf("handler got header %q = %q; want empty", "Upgrade", c)
	}
	if c := res.Header.Get(fakeConnectionToken); c != "" {
		t.Errorf("handler got header %q = %q; want empty", fakeConnectionToken, c)
	}
}

func TestXForwardedFor(t *testing.T) {
	const prevForwardedFor = "client ip"
	const backendResponse = "I am the backend"
	const backendStatus = 404
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "" {
			t.Errorf("didn't get X-Forwarded-For header")
		}
		if !strings.Contains(r.Header.Get("X-Forwarded-For"), prevForwardedFor) {
			t.Errorf("X-Forwarded-For didn't contain prior data")
		}
		w.WriteHeader(backendStatus)
		w.Write([]byte(backendResponse))
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	getReq.Host = "some-name"
	getReq.Header.Set("Connection", "close")
	getReq.Header.Set("X-Forwarded-For", prevForwardedFor)
	getReq.Close = true
	res, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if g, e := res.StatusCode, backendStatus; g != e {
		t.Errorf("got res.StatusCode %d; expected %d", g, e)
	}
	bodyBytes, _ := ioutil.ReadAll(res.Body)
	if g, e := string(bodyBytes), backendResponse; g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}
}

var proxyQueryTests = []struct {
	baseSuffix string // suffix to add to backend URL
	reqSuffix  string // suffix to add to frontend's request URL
	want       string // what backend should see for final request URL (without ?)
}{
	{"", "", ""},
	{"?sta=tic", "?us=er", "sta=tic&us=er"},
	{"", "?us=er", "us=er"},
	{"?sta=tic", "", "sta=tic"},
}

func TestReverseProxyQuery(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Got-Query", r.URL.RawQuery)
		w.Write([]byte("hi"))
	}))
	defer backend.Close()

	for i, tt := range proxyQueryTests {
		backendURL, err := url.Parse(backend.URL + tt.baseSuffix)
		if err != nil {
			t.Fatal(err)
		}
		frontend := httptest.NewServer(NewSingleHostReverseProxy(backendURL))
		req, _ := http.NewRequest("GET", frontend.URL+tt.reqSuffix, nil)
		req.Close = true
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%d. Get: %v", i, err)
		}
		if g, e := res.Header.Get("X-Got-Query"), tt.want; g != e {
			t.Errorf("%d. got query %q; expected %q", i, g, e)
		}
		res.Body.Close()
		frontend.Close()
	}
}

func TestReverseProxyFlushInterval(t *testing.T) {
	const expected = "hi"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(expected))
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	proxyHandler := NewSingleHostReverseProxy(backendURL)
	proxyHandler.FlushInterval = time.Microsecond

	done := make(chan bool)
	onExitFlushLoop = func() { done <- true }
	defer func() { onExitFlushLoop = nil }()

	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	req, _ := http.NewRequest("GET", frontend.URL, nil)
	req.Close = true
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer res.Body.Close()
	if bodyBytes, _ := ioutil.ReadAll(res.Body); string(bodyBytes) != expected {
		t.Errorf("got body %q; expected %q", bodyBytes, expected)
	}

	select {
	case <-done:
		// OK
	case <-time.After(5 * time.Second):
		t.Error("maxLatencyWriter flushLoop() never exited")
	}
}

func TestReverseProxyCancelation(t *testing.T) {
	const backendResponse = "I am the backend"

	reqInFlight := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(reqInFlight) // cause the client to cancel its request

		select {
		case <-time.After(10 * time.Second):
			// Note: this should only happen in broken implementations, and the
			// closenotify case should be instantaneous.
			t.Error("Handler never saw CloseNotify")
			return
		case <-w.(http.CloseNotifier).CloseNotify():
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(backendResponse))
	}))

	defer backend.Close()

	backend.Config.ErrorLog = log.New(ioutil.Discard, "", 0)

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	proxyHandler := NewSingleHostReverseProxy(backendURL)

	// Discards errors of the form:
	// http: proxy error: read tcp 127.0.0.1:44643: use of closed network connection
	proxyHandler.ErrorLog = log.New(ioutil.Discard, "", 0)

	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	go func() {
		<-reqInFlight
		http.DefaultTransport.(*http.Transport).CancelRequest(getReq)
	}()
	res, err := http.DefaultClient.Do(getReq)
	if res != nil {
		t.Errorf("got response %v; want nil", res.Status)
	}
	if err == nil {
		// This should be an error like:
		// Get http://127.0.0.1:58079: read tcp 127.0.0.1:58079:
		//    use of closed network connection
		t.Error("DefaultClient.Do() returned nil error; want non-nil error")
	}
}

func req(t *testing.T, v string) *http.Request {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(v)))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// Issue 12344
func TestNilBody(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hi"))
	}))
	defer backend.Close()

	frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		backURL, _ := url.Parse(backend.URL)
		rp := NewSingleHostReverseProxy(backURL)
		r := req(t, "GET / HTTP/1.0\r\n\r\n")
		r.Body = nil // this accidentally worked in Go 1.4 and below, so keep it working
		rp.ServeHTTP(w, r)
	}))
	defer frontend.Close()

	res, err := http.Get(frontend.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	slurp, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(slurp) != "hi" {
		t.Errorf("Got %q; want %q", slurp, "hi")
	}
}

// Issue 15524
func TestUserAgentHeader(t *testing.T) {
	const explicitUA = "explicit UA"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/noua" {
			if c := r.Header.Get("User-Agent"); c != "Mozilla/5.0 zgrab/0.x" {
				t.Errorf("handler got unexpected User-Agent header %q", c)
			}
			return
		}
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	proxyHandler.ErrorLog = log.New(ioutil.Discard, "", 0) // quiet for tests
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	getReq.Header.Set("User-Agent", explicitUA)
	getReq.Close = true
	res, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	res.Body.Close()

	getReq, _ = http.NewRequest("GET", frontend.URL+"/noua", nil)
	getReq.Header.Set("User-Agent", "")
	getReq.Close = true
	res, err = http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	res.Body.Close()
}

type bufferPool struct {
	get func() []byte
	put func([]byte)
}

func (bp bufferPool) Get() []byte  { return bp.get() }
func (bp bufferPool) Put(v []byte) { bp.put(v) }

func TestReverseProxyGetPutBuffer(t *testing.T) {
	const msg = "hi"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, msg)
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu  sync.Mutex
		log []string
	)
	addLog := func(event string) {
		mu.Lock()
		defer mu.Unlock()
		log = append(log, event)
	}
	rp := NewSingleHostReverseProxy(backendURL)
	const size = 1234
	rp.BufferPool = bufferPool{
		get: func() []byte {
			addLog("getBuf")
			return make([]byte, size)
		},
		put: func(p []byte) {
			addLog("putBuf-" + strconv.Itoa(len(p)))
		},
	}
	frontend := httptest.NewServer(rp)
	defer frontend.Close()

	req, _ := http.NewRequest("GET", frontend.URL, nil)
	req.Close = true
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	slurp, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if string(slurp) != msg {
		t.Errorf("msg = %q; want %q", slurp, msg)
	}
	wantLog := []string{"getBuf", "putBuf-" + strconv.Itoa(size)}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(log, wantLog) {
		t.Errorf("Log events = %q; want %q", log, wantLog)
	}
}

func TestReverseProxy_Post(t *testing.T) {
	const backendResponse = "I am the backend"
	const backendStatus = 200
	var requestBody = bytes.Repeat([]byte("a"), 1<<20)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slurp, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Backend body read = %v", err)
		}
		if len(slurp) != len(requestBody) {
			t.Errorf("Backend read %d request body bytes; want %d", len(slurp), len(requestBody))
		}
		if !bytes.Equal(slurp, requestBody) {
			t.Error("Backend read wrong request body.") // 1MB; omitting details
		}
		w.Write([]byte(backendResponse))
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	postReq, _ := http.NewRequest("POST", frontend.URL, bytes.NewReader(requestBody))
	res, err := http.DefaultClient.Do(postReq)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if g, e := res.StatusCode, backendStatus; g != e {
		t.Errorf("got res.StatusCode %d; expected %d", g, e)
	}
	bodyBytes, _ := ioutil.ReadAll(res.Body)
	if g, e := string(bodyBytes), backendResponse; g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}
}

type RoundTripperFunc func(*http.Request) (*http.Response, error)

func (fn RoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

// Issue 16036: send a Request with a nil Body when possible
func TestReverseProxy_NilBody(t *testing.T) {
	backendURL, _ := url.Parse("http://fake.tld/")
	proxyHandler := NewSingleHostReverseProxy(backendURL)
	proxyHandler.ErrorLog = log.New(ioutil.Discard, "", 0) // quiet for tests
	proxyHandler.Transport = RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if req.Body != nil {
			t.Error("Body != nil; want a nil Body")
		}
		return nil, errors.New("done testing the interesting part; so force a 502 Gateway error")
	})
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	res, err := http.DefaultClient.Get(frontend.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 502 {
		t.Errorf("status code = %v; want 502 (Gateway Error)", res.Status)
	}
}

// Issue 14237. Test ModifyResponse and that an error from it
// causes the proxy to return StatusBadGateway, or StatusOK otherwise.
func TestReverseProxyModifyResponse(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("X-Hit-Mod", fmt.Sprintf("%v", r.URL.Path == "/mod"))
	}))
	defer backendServer.Close()

	rpURL, _ := url.Parse(backendServer.URL)
	rproxy := NewSingleHostReverseProxy(rpURL)
	rproxy.ErrorLog = log.New(ioutil.Discard, "", 0) // quiet for tests
	rproxy.ModifyResponse = func(resp *http.Response) error {
		if resp.Header.Get("X-Hit-Mod") != "true" {
			return fmt.Errorf("tried to by-pass proxy")
		}
		return nil
	}

	frontendProxy := httptest.NewServer(rproxy)
	defer frontendProxy.Close()

	tests := []struct {
		url      string
		wantCode int
	}{
		{frontendProxy.URL + "/mod", http.StatusOK},
		{frontendProxy.URL + "/schedule", http.StatusBadGateway},
	}

	for i, tt := range tests {
		resp, err := http.Get(tt.url)
		if err != nil {
			t.Fatalf("failed to reach proxy: %v", err)
		}
		if g, e := resp.StatusCode, tt.wantCode; g != e {
			t.Errorf("#%d: got res.StatusCode %d; expected %d", i, g, e)
		}
		resp.Body.Close()
	}
}

// Issue 16659: log errors from short read
func TestReverseProxy_CopyBuffer(t *testing.T) {
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := "this call was relayed by the reverse proxy"
		// Coerce a wrong content length to induce io.UnexpectedEOF
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(out)*2))
		fmt.Fprintln(w, out)
	}))
	defer backendServer.Close()

	rpURL, err := url.Parse(backendServer.URL)
	if err != nil {
		t.Fatal(err)
	}

	var proxyLog bytes.Buffer
	rproxy := NewSingleHostReverseProxy(rpURL)
	rproxy.ErrorLog = log.New(&proxyLog, "", log.Lshortfile)
	frontendProxy := httptest.NewServer(rproxy)
	defer frontendProxy.Close()

	resp, err := http.Get(frontendProxy.URL)
	if err != nil {
		t.Fatalf("failed to reach proxy: %v", err)
	}
	defer resp.Body.Close()

	if _, err := ioutil.ReadAll(resp.Body); err == nil {
		t.Fatalf("want non-nil error")
	}
	expected := []string{
		"EOF",
		"read",
	}
	for _, phrase := range expected {
		if !bytes.Contains(proxyLog.Bytes(), []byte(phrase)) {
			t.Errorf("expected log to contain phrase %q", phrase)
		}
	}
}

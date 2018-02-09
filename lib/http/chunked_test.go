// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"testing"
)

func TestChunk(t *testing.T) {
	var b bytes.Buffer

	w := NewChunkedWriter(&b)
	const chunk1 = "hello, "
	const chunk2 = "world! 0123456789abcdef"
	w.Write([]byte(chunk1))
	w.Write([]byte(chunk2))
	w.Close()

	if g, e := b.String(), "7\r\nhello, \r\n17\r\nworld! 0123456789abcdef\r\n0\r\n"; g != e {
		t.Fatalf("chunk writer wrote %q; want %q", g, e)
	}

	r := NewChunkedReader(&b)
	data, err := ioutil.ReadAll(r)
	if err != nil {
		t.Logf(`data: "%s"`, data)
		t.Fatalf("ReadAll from reader: %v", err)
	}
	if g, e := string(data), chunk1+chunk2; g != e {
		t.Errorf("chunk reader read %q; want %q", g, e)
	}
}

func TestChunkReadMultiple(t *testing.T) {
	// Bunch of small chunks, all read together.
	{
		var b bytes.Buffer
		w := NewChunkedWriter(&b)
		w.Write([]byte("foo"))
		w.Write([]byte("bar"))
		w.Close()

		r := NewChunkedReader(&b)
		buf := make([]byte, 10)
		n, err := r.Read(buf)
		if n != 6 || err != io.EOF {
			t.Errorf("Read = %d, %v; want 6, EOF", n, err)
		}
		buf = buf[:n]
		if string(buf) != "foobar" {
			t.Errorf("Read = %q; want %q", buf, "foobar")
		}
	}

	// One big chunk followed by a little chunk, but the small bufio.Reader size
	// should prevent the second chunk header from being read.
	{
		var b bytes.Buffer
		w := NewChunkedWriter(&b)
		// fillBufChunk is 11 bytes + 3 bytes header + 2 bytes footer = 16 bytes,
		// the same as the bufio ReaderSize below (the minimum), so even
		// though we're going to try to Read with a buffer larger enough to also
		// receive "foo", the second chunk header won't be read yet.
		const fillBufChunk = "0123456789a"
		const shortChunk = "foo"
		w.Write([]byte(fillBufChunk))
		w.Write([]byte(shortChunk))
		w.Close()

		r := NewChunkedReader(bufio.NewReaderSize(&b, 16))
		buf := make([]byte, len(fillBufChunk)+len(shortChunk))
		n, err := r.Read(buf)
		if n != len(fillBufChunk) || err != nil {
			t.Errorf("Read = %d, %v; want %d, nil", n, err, len(fillBufChunk))
		}
		buf = buf[:n]
		if string(buf) != fillBufChunk {
			t.Errorf("Read = %q; want %q", buf, fillBufChunk)
		}

		n, err = r.Read(buf)
		if n != len(shortChunk) || err != io.EOF {
			t.Errorf("Read = %d, %v; want %d, EOF", n, err, len(shortChunk))
		}
	}

	// And test that we see an EOF chunk, even though our buffer is already full:
	{
		r := NewChunkedReader(bufio.NewReader(strings.NewReader("3\r\nfoo\r\n0\r\n")))
		buf := make([]byte, 3)
		n, err := r.Read(buf)
		if n != 3 || err != io.EOF {
			t.Errorf("Read = %d, %v; want 3, EOF", n, err)
		}
		if string(buf) != "foo" {
			t.Errorf("buf = %q; want foo", buf)
		}
	}
}

func TestChunkReaderAllocs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	var buf bytes.Buffer
	w := NewChunkedWriter(&buf)
	a, b, c := []byte("aaaaaa"), []byte("bbbbbbbbbbbb"), []byte("cccccccccccccccccccccccc")
	w.Write(a)
	w.Write(b)
	w.Write(c)
	w.Close()

	readBuf := make([]byte, len(a)+len(b)+len(c)+1)
	byter := bytes.NewReader(buf.Bytes())
	bufr := bufio.NewReader(byter)
	mallocs := testing.AllocsPerRun(100, func() {
		byter.Seek(0, io.SeekStart)
		bufr.Reset(byter)
		r := NewChunkedReader(bufr)
		n, err := io.ReadFull(r, readBuf)
		if n != len(readBuf)-1 {
			t.Fatalf("read %d bytes; want %d", n, len(readBuf)-1)
		}
		if err != io.ErrUnexpectedEOF {
			t.Fatalf("read error = %v; want ErrUnexpectedEOF", err)
		}
	})
	if mallocs > 1.5 {
		t.Errorf("mallocs = %v; want 1", mallocs)
	}
}

func TestParseHexUint(t *testing.T) {
	type testCase struct {
		in      string
		want    uint64
		wantErr string
	}
	tests := []testCase{
		{"x", 0, "invalid byte in chunk length"},
		{"0000000000000000", 0, ""},
		{"0000000000000001", 1, ""},
		{"ffffffffffffffff", 1<<64 - 1, ""},
		{"000000000000bogus", 0, "invalid byte in chunk length"},
		{"00000000000000000", 0, "http chunk length too large"}, // could accept if we wanted
		{"10000000000000000", 0, "http chunk length too large"},
		{"00000000000000001", 0, "http chunk length too large"}, // could accept if we wanted
	}
	for i := uint64(0); i <= 1234; i++ {
		tests = append(tests, testCase{in: fmt.Sprintf("%x", i), want: i})
	}
	for _, tt := range tests {
		got, err := parseHexUint([]byte(tt.in))
		if tt.wantErr != "" {
			if !strings.Contains(fmt.Sprint(err), tt.wantErr) {
				t.Errorf("parseHexUint(%q) = %v, %v; want error %q", tt.in, got, err, tt.wantErr)
			}
		} else {
			if err != nil || got != tt.want {
				t.Errorf("parseHexUint(%q) = %v, %v; want %v", tt.in, got, err, tt.want)
			}
		}
	}
}

func TestChunkReadingIgnoresExtensions(t *testing.T) {
	in := "7;ext=\"some quoted string\"\r\n" + // token=quoted string
		"hello, \r\n" +
		"17;someext\r\n" + // token without value
		"world! 0123456789abcdef\r\n" +
		"0;someextension=sometoken\r\n" // token=token
	data, err := ioutil.ReadAll(NewChunkedReader(strings.NewReader(in)))
	if err != nil {
		t.Fatalf("ReadAll = %q, %v", data, err)
	}
	if g, e := string(data), "hello, world! 0123456789abcdef"; g != e {
		t.Errorf("read %q; want %q", g, e)
	}
}

// Issue 17355: ChunkedReader shouldn't block waiting for more data
// if it can return something.
func TestChunkReadPartial(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte("7\r\n1234567"))
	}()
	cr := NewChunkedReader(pr)
	readBuf := make([]byte, 7)
	n, err := cr.Read(readBuf)
	if err != nil {
		t.Fatal(err)
	}
	want := "1234567"
	if n != 7 || string(readBuf) != want {
		t.Fatalf("Read: %v %q; want %d, %q", n, readBuf[:n], len(want), want)
	}
	go func() {
		pw.Write([]byte("xx"))
	}()
	_, err = cr.Read(readBuf)
	if got := fmt.Sprint(err); !strings.Contains(got, "malformed") {
		t.Fatalf("second read = %v; want malformed error", err)
	}

}

// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httptrace_test

import (
	"fmt"
	"github.com/zmap/zgrab2/lib/http"
	"github.com/zmap/zgrab2/lib/http/httptrace"
	"log"
)

func Example() {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			fmt.Printf("Got Conn: %+v\n", connInfo)
		},
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			fmt.Printf("DNS Info: %+v\n", dnsInfo)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	_, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		log.Fatal(err)
	}
}

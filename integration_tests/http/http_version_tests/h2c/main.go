package main

import (
	"fmt"
	"log"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedProtocol := "HTTP/2.0"
		if r.Proto != expectedProtocol {
			http.Error(w, fmt.Sprintf("expected protocol %s, got %s", expectedProtocol, r.Proto), http.StatusHTTPVersionNotSupported)
			return
		}
		_, err := fmt.Fprint(w, "Successfully served over HTTP/2 NOT over TLS!\n")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	h2s := &http2.Server{}
	h1s := &http.Server{
		Addr:    ":443",
		Handler: h2c.NewHandler(handler, h2s),
	}
	log.Fatal(h1s.ListenAndServe())
}

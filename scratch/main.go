package main

import (
	"context"
	"fmt"
	"github.com/zmap/zcrypto/tls"
	"net"

	"github.com/zmap/zgrab2/lib/http"
	"github.com/zmap/zgrab2/lib/http2"
)

func SimpleHTTP2Client() *http.Client {
	return &http.Client{
		Transport: &http2.Transport{
			// So http2.Transport doesn't complain the URL scheme isn't 'https'
			// Pretend we are dialing a TLS endpoint.
			// Note, we ignore the passed tls.Config
			//DialTLSContext: func(ctx context.Context, n, a string, _ *tls.Config) (net.Conn, error) {
			//	var d net.Dialer
			//	return d.DialContext(ctx, n, a)
			//},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Skip TLS verification for testing
			},
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				var d net.Dialer
				conn, err := d.DialContext(ctx, network, addr)
				if err != nil {
					return nil, fmt.Errorf("dialing %s: %w", addr, err)
				}
				tlsConn := tls.Client(conn, cfg)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					return nil, fmt.Errorf("TLS handshake failed: %w", err)
				}
				return tlsConn, nil
			},
		},
	}
}

func HTTP1TransportUpgrade() *http.Client {
	http1Transport := &http.Transport{
		Proxy:               nil, // TODO: implement proxying
		DisableKeepAlives:   false,
		DisableCompression:  false,
		MaxIdleConnsPerHost: 10,
		RawHeaderBuffer:     true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Skip TLS verification for testing
		},
	}
	err := http2.ConfigureTransport(http1Transport)
	if err != nil {
		fmt.Printf("Error configuring HTTP/2 transport: %v\n", err)
		return nil
	}
	return &http.Client{
		Transport: http1Transport,
	}
}

// TODO Phillip
// My guess is that how we'll need to do this is to build separate HTTP1 and HTTP2 transports

func main() {
	url := "https://localhost:8082/"

	client := HTTP1TransportUpgrade()
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("Could not send HTTP Get: Error: %v\n", err)
		return
	}
	fmt.Printf("Client Proto: %d\n", resp.ProtoMajor)
}

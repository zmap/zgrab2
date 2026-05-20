package zgrab2_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	zgrab2 "github.com/zmap/zgrab2" // adjust import path to match your module
)

// This file incudes tests to verify our timeouts at different phases of a connection, ie: TCP SYN, TLS handshake, read,
// and write on a connection

const (
	connectTimeout      = 300 * time.Millisecond
	tlsHandshakeTimeout = 800 * time.Millisecond
	targetTimeout       = 2 * time.Second
)

// baseFlags returns a BaseFlags whose ConnectTimeout is short so tests stay efficient
func baseFlags() *zgrab2.BaseFlags {
	return &zgrab2.BaseFlags{
		ConnectTimeout: connectTimeout,
		// TargetTimeout can be generous; it only governs read/write after connect.
		TargetTimeout: targetTimeout,
	}
}

// selfSignedCert generates an in-memory CA-signed TLS certificate for 127.0.0.1
// and returns the tls.Config that a server can use, plus the CA cert pool for
// clients.
func selfSignedCert(t *testing.T) (serverCfg *tls.Config, caPool *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	serverCfg = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}},
	}

	caPool = x509.NewCertPool()
	caPool.AddCert(cert)
	return
}

// dial is a small helper that calls the dialer and returns (conn, elapsed, err).
func dial(
	t *testing.T,
	ctx context.Context,
	dialer func(context.Context, *zgrab2.ScanTarget, string) (net.Conn, error),
	target *zgrab2.ScanTarget,
	addr string,
) (net.Conn, time.Duration, error) {
	t.Helper()
	start := time.Now()
	conn, err := dialer(ctx, target, addr)
	return conn, time.Since(start), err
}

// assertTimedOutNear fails the test if elapsed is outside [min, max].
func assertTimedOutNear(t *testing.T, elapsed, min, max time.Duration) {
	t.Helper()
	if elapsed < min {
		t.Errorf("returned too quickly: %v (expected >= %v)", elapsed, min)
	}
	if elapsed > max {
		t.Errorf("took too long: %v (expected <= %v)", elapsed, max)
	}
}

// ── Scenario 1: server ignores the TCP SYN ───────────────────────────────────
//
// We listen on a port with SO_REUSEPORT via net.Listen but immediately close
// the *listener* without accepting anything.  The kernel will send RST/ignore
// SYNs depending on the OS. The dialer must time out within ConnectTimeout.

func TestTCPDialer_NoTCPHandshake_TimesOut(t *testing.T) {
	// Find a port that is definitely not listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not open temp listener: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // close immediately — nothing will accept on this port

	// Give the OS a moment to fully release the port.
	time.Sleep(10 * time.Millisecond)

	flags := baseFlags()
	dialer := zgrab2.GetDefaultTCPDialer(flags)
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1")}

	ctx, cancel := context.WithTimeout(context.Background(), targetTimeout)
	defer cancel()
	conn, elapsed, err := dial(t, ctx, dialer, target, addr)
	if conn != nil {
		conn.Close()
		t.Error("expected nil conn, got a connection")
	}
	if err == nil {
		t.Error("expected an error, got nil")
	}

	// Should time out at roughly ConnectTimeout, definitely not faster and not
	// more than 3× slower (to tolerate slow CI machines).
	assertTimedOutNear(t, elapsed, 0, connectTimeout*3)
	t.Logf("scenario 1 elapsed=%v err=%v", elapsed, err)
}

// ── Scenario 2: TCP connects, TLS hangs ──────────────────────────────────────
//
// A TCP server accepts the connection and then does nothing — it neither sends
// a TLS ServerHello nor closes the socket.  GetDefaultTLSWrapper (called via
// GetDefaultTLSDialer) must time out within TLSHandshakeTimeout.

func TestTLSDialer_TCPOkTLSHangs_TimesOut(t *testing.T) {
	// Start a server that accepts TCP but never speaks TLS.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			var conn net.Conn
			conn, err = ln.Accept()
			if err != nil {
				return // listener closed
			}
			// Hold the connection open but send nothing.
			for {
				// Continually read off the socket
				buf := make([]byte, 1)
				_, err = conn.Read(buf) //nolint:errcheck
				if err != nil {
					t.Logf("server read error (expected when client times out): %v", err)
					return
				}
			}
		}
	}()

	flags := baseFlags()
	// Skip verification — we have no real cert on this fake server.
	// The handshake will hang before certs are exchanged anyway.
	tlsFlags := &zgrab2.TLSFlags{TLSHandshakeTimeout: tlsHandshakeTimeout}
	dialer := zgrab2.GetDefaultTLSDialer(flags, tlsFlags)
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1")}

	ctx, cancel := context.WithTimeout(context.Background(), targetTimeout)
	defer cancel()
	conn, elapsed, err := dial(t, ctx, dialer, target, ln.Addr().String())
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Error("expected an error, got nil")
	}
	lowerBound := time.Duration(float64(tlsHandshakeTimeout) * 0.8)
	upperBound := time.Duration(float64(tlsHandshakeTimeout) * 1.2)

	assertTimedOutNear(t, elapsed, lowerBound, upperBound)
	t.Logf("scenario 2 elapsed=%v err=%v", elapsed, err)
}

// ── Scenario 3: full TCP + TLS handshake succeeds ────────────────────────────
//
// A TLS server that uses a self-signed certificate is started.  The client
// uses a TLSFlags configured with a CA pool containing that certificate.
// The dialer should return a valid *TLSConnection with no error.

func TestTLSDialer_FullHandshake_Succeeds(t *testing.T) {
	serverCfg, _ := selfSignedCert(t)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			var conn net.Conn
			conn, err = ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Complete the handshake and hold open briefly.
				if tlsConn, ok := c.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
				time.Sleep(500 * time.Millisecond)
			}(conn)
		}
	}()

	dialer := zgrab2.GetDefaultTLSDialer(baseFlags(), &zgrab2.TLSFlags{TLSHandshakeTimeout: tlsHandshakeTimeout})
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1")}

	ctx, cancel := context.WithTimeout(context.Background(), targetTimeout)
	defer cancel()
	conn, elapsed, err := dial(t, ctx, dialer, target, ln.Addr().String())
	if err != nil {
		t.Fatalf("expected successful handshake, got err=%v (elapsed=%v)", err, elapsed)
	}
	if conn == nil {
		t.Fatal("expected non-nil conn")
	}
	conn.Close()

	// Should finish well within the timeout.
	if elapsed > connectTimeout {
		t.Errorf("handshake took longer than ConnectTimeout: %v > %v", elapsed, connectTimeout)
	}
	t.Logf("scenario 3 elapsed=%v", elapsed)
}

// ── Scenario 4: server reads payload but never replies — Read times out at TargetTimeout ──
//
// The server completes TLS, drains whatever the client sends (so the client
// Write returns immediately), and then parks without ever writing a response.
// The client Write succeeds fast; the subsequent Read blocks until the
// TargetTimeout deadline fires.
//
// Key distinctions from scenario 3:
//   - Write succeeds immediately (server is reading) — only Read blocks.
//   - We assert readElapsed ≥ TargetTimeout, ruling out ConnectTimeout.

func TestTLSDialer_ServerReadsButNeverReplies_ReadTimesOutAfterTargetTimeout(t *testing.T) {
	serverCfg, _ := selfSignedCert(t)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	defer ln.Close()

	// Server: finish TLS, drain all incoming data, never write a response.
	go func() {
		for {
			var conn net.Conn
			conn, err = ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				// Drain incoming bytes so the client Write returns immediately,
				// but never send anything back.
				io.Copy(io.Discard, c) //nolint:errcheck
			}(conn)
		}
	}()

	dialer := zgrab2.GetDefaultTLSDialer(baseFlags(), &zgrab2.TLSFlags{TLSHandshakeTimeout: tlsHandshakeTimeout})
	target := &zgrab2.ScanTarget{IP: net.ParseIP("127.0.0.1")}

	ctx, cancel := context.WithTimeout(context.Background(), targetTimeout)
	defer cancel()
	conn, dialElapsed, err := dial(t, ctx, dialer, target, ln.Addr().String())
	if err != nil {
		t.Fatalf("expected successful dial+handshake, got err=%v", err)
	}
	defer conn.Close()

	if dialElapsed > connectTimeout {
		t.Errorf("dial took longer than ConnectTimeout: %v > %v", dialElapsed, connectTimeout)
	}

	// Write a small request — should return immediately because the server is reading.
	payload := []byte("GET / HTTP/1.0\r\n\r\n")
	writeStart := time.Now()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write failed unexpectedly: %v", err)
	}
	writeElapsed := time.Since(writeStart)

	// The write must finish well before TargetTimeout fires.
	if writeElapsed > targetTimeout/2 {
		t.Errorf("Write took too long (%v) — server may not be reading", writeElapsed)
	}

	// Now block on Read waiting for a reply that will never come.
	readStart := time.Now()
	buf := make([]byte, 4096)
	_, readErr := conn.Read(buf)
	readElapsed := time.Since(readStart)

	if readErr == nil {
		t.Fatal("expected a read deadline error, got nil")
	}

	// Must not have timed out faster than TargetTimeout (ConnectTimeout leak).
	if readElapsed < targetTimeout/2 {
		t.Errorf("Read failed too quickly (%v) — ConnectTimeout may have fired instead of TargetTimeout", readElapsed)
	}

	// Must not have taken vastly longer than TargetTimeout (3× CI slack).
	if readElapsed > targetTimeout*3 {
		t.Errorf("Read took too long: %v (expected ~%v)", readElapsed, targetTimeout)
	}

	t.Logf("scenario 4: dial=%v write=%v read_blocked_for=%v err=%v",
		dialElapsed, writeElapsed, readElapsed, readErr)
}

package zgrab2

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zmap/zgrab2/ratelimit"
)

// withRateLimitConfig restores the rate limit settings after the test and
// gives it a fresh limiter cache, so limiters created by other tests can't
// leak in.
func withRateLimitConfig(t *testing.T) {
	t.Helper()
	oldLimit, oldDisabled := config.ServerRateLimit, serverRateLimitDisabled.Load()
	oldLimiter := ipRateLimiter
	t.Cleanup(func() {
		config.ServerRateLimit = oldLimit
		serverRateLimitDisabled.Store(oldDisabled)
		ipRateLimiter = oldLimiter
	})
	ipRateLimiter = ratelimit.NewPerObjectRateLimiter[netip.Addr](10, time.Minute)
}

func acceptLoop(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return l.Addr().String()
}

func dialOnce(addr string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := NewDialer(nil).DialContext(ctx, "tcp", addr)
	if err == nil {
		_ = conn.Close()
	}
	return err
}

func TestServerRateLimitEnforced(t *testing.T) {
	withRateLimitConfig(t)
	config.ServerRateLimit = 1
	addr := acceptLoop(t)
	if err := dialOnce(addr, time.Second); err != nil {
		t.Fatalf("first dial: %v", err)
	}
	// The single token is spent; the next one is a second away.
	if err := dialOnce(addr, 100*time.Millisecond); err == nil {
		t.Fatal("second dial succeeded, want it rate limited")
	}
}

func TestServerRateLimitDisabled(t *testing.T) {
	withRateLimitConfig(t)
	// A limit of 0 would refuse every dial; disabling must win over it.
	config.ServerRateLimit = 0
	DisableServerRateLimit()
	addr := acceptLoop(t)
	for i := 0; i < 20; i++ {
		if err := dialOnce(addr, time.Second); err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
	}
}

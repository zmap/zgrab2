package ratelimit

import (
	"context"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestWaitOrCreateEntryExpiresImmediately covers a new limiter whose cache
// entry has already expired by the time WaitOrCreate uses it. In production
// this happens when the goroutine stalls for longer than the cache TTL (GC,
// CPU starvation, VM pause) between creating the limiter and using it; a tiny
// TTL makes the same window deterministic.
func TestWaitOrCreateEntryExpiresImmediately(t *testing.T) {
	l := NewPerObjectRateLimiter[int](100, time.Microsecond)
	for i := 0; i < 1000; i++ {
		if err := l.WaitOrCreate(context.Background(), i, rate.Inf, 1); err != nil {
			t.Fatalf("WaitOrCreate(%d): %v", i, err)
		}
	}
}

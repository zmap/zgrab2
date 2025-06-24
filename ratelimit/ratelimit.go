package ratelimit

import (
	"context"
	"fmt"
	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/time/rate"
	"sync"
	"time"
)

const (
	maxLRUSize = 10_000_000       // Limiters track IP connects per second. There's no way we'll have over 10 million unique IPs per second, so this should be plenty.
	maxLRUTTL  = time.Second * 10 // Memory Leak Avoidance - We'll remove a limiter for an IP after 10 seconds of inactivity. It'll be re-created if the IP connects again after that time.
)

// PerObjectRateLimiter manages a per-object rate limit.
// It is thread-safe
type PerObjectRateLimiter[K comparable] struct {
	*sync.Mutex
	limitLRU *lru.LRU[K, *rate.Limiter]
}

// NewPerObjectRateLimiter creates a new PerObjectRateLimiter.
func NewPerObjectRateLimiter[K comparable]() *PerObjectRateLimiter[K] {
	limiter := &PerObjectRateLimiter[K]{
		Mutex: &sync.Mutex{},
	}
	limiter.limitLRU = lru.NewLRU[K, *rate.Limiter](maxLRUSize, nil, maxLRUTTL) // Initialize LRU cache with a maximum size
	return limiter
}

// WaitOrCreate waits for the rate limiter for the given key to allow access.
// If the rate limiter does not exist, one is created using rateLimit and burstRate
func (l *PerObjectRateLimiter[K]) WaitOrCreate(ctx context.Context, key K, rateLimit rate.Limit, burstRate int) error {
	l.Lock()
	l.limitLRU.Add(key, rate.NewLimiter(rateLimit, burstRate)) // ensure limiter exists for the key
	limiter, ok := l.limitLRU.Get(key)
	if !ok {
		panic("unexpected error: rate limiter for key not found after adding it")
	}
	l.Unlock() // Unlock before waiting to avoid deadlocks
	if err := limiter.Wait(ctx); err != nil {
		return fmt.Errorf("could not wait for rate limiter for key %v: %w", key, err)
	}
	return nil
}

package ratelimit

import (
	"context"
	"fmt"
	"golang.org/x/time/rate"
	"sort"
	"sync"
)

// PerObjectRateLimiter manages a per-object rate limit.
// It is thread-safe
type PerObjectRateLimiter[K comparable] struct {
	rates map[K]rate.Limiter // Rate limiters for each object
	// The individual rate limiters are thread-safe, but in the case that a rate limit is added, the outer map must be protected.
	ratesMutex sync.RWMutex
	// TODO Phillip remove
	accesses   map[K]uint // Access counters for each object
	accessLock sync.Mutex
}

// WaitOrCreate waits for the rate limiter for the given key to allow access.
// If the rate limiter does not exist, one is created using rateLimit and burstRate
func (l *PerObjectRateLimiter[K]) WaitOrCreate(ctx context.Context, key K, rateLimit rate.Limit, burstRate int) error {
	l.createIfNecessary(key, rateLimit, burstRate) // Ensure the rate limiter exists
	limiter, ok := l.rates[key]
	if !ok {
		// shouldn't be possible, but just in case
		return fmt.Errorf("rate limiter for key %v not found", key)
	}
	if err := limiter.Wait(ctx); err != nil {
		return fmt.Errorf("could not wait for rate limiter for key %v: %w", key, err)
	}
	l.accessLock.Lock()
	defer l.accessLock.Unlock()
	l.accesses[key]++ // initialized in NewPerObjectRateLimit, so safe to assume it exists
	return nil
}

// createIfNecessary ensures that a rate limiter for the given key exists.
// It is thread-safe and performs opportunistic locking to minimize contention.
func (l *PerObjectRateLimiter[K]) createIfNecessary(key K, rateLimit rate.Limit, burstRate int) {
	checkIfKeyShouldBeCreated := func() bool {
		if l.rates == nil {
			return true
		}
		if _, ok := l.rates[key]; !ok {
			return true
		}
		return false
	}
	l.ratesMutex.RLock()
	likelyNeedsCreation := checkIfKeyShouldBeCreated()
	l.ratesMutex.RUnlock()
	if likelyNeedsCreation {
		// There's a slim chance that another goroutine created the key in the meantime since we only held a read lock.
		// So aquire a write lock and check again.
		l.ratesMutex.Lock()
		defer l.ratesMutex.Unlock()
		definitelyNeedsCreation := checkIfKeyShouldBeCreated()
		if definitelyNeedsCreation {
			if l.rates == nil {
				l.rates = make(map[K]rate.Limiter)
			}
			if _, ok := l.rates[key]; !ok {
				l.rates[key] = *rate.NewLimiter(rateLimit, burstRate)
				l.accessLock.Lock()
				defer l.accessLock.Unlock()
				l.accesses[key] = 0 // Initialize access count
			}
		}
	}

}

func (l *PerObjectRateLimiter[K]) PrintAccesses() string {
	var result string
	l.accessLock.Lock()
	defer l.accessLock.Unlock()
	if l.rates == nil {
		return ""
	}
	// Get access counts, sort in descending order
	type kv struct {
		Key   K
		Value uint
	}
	var pairs []kv
	for k, v := range l.accesses {
		pairs = append(pairs, kv{k, v})
	}

	// Sort by Value descending
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Value > pairs[j].Value
	})

	// Print sorted result
	for _, p := range pairs {
		result += fmt.Sprintf("%s - %d\n", p.Key, p.Value)
	}
	return result
}

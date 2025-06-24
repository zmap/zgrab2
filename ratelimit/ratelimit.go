package ratelimit

import (
	"context"
	"fmt"
	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/time/rate"
	"sort"
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
	// TODO Phillip remove
	accesses   map[K]uint // Access counters for each object
	accessLock sync.Mutex
}

// NewPerObjectRateLimiter creates a new PerObjectRateLimiter.
func NewPerObjectRateLimiter[K comparable]() *PerObjectRateLimiter[K] {
	limiter := &PerObjectRateLimiter[K]{
		Mutex:      &sync.Mutex{},
		accesses:   make(map[K]uint),
		accessLock: sync.Mutex{},
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
	l.accessLock.Lock()
	defer l.accessLock.Unlock()
	l.accesses[key]++ // initialized in NewPerObjectRateLimit, so safe to assume it exists
	return nil
}

func (l *PerObjectRateLimiter[K]) PrintAccesses() string {
	var result string
	l.accessLock.Lock()
	defer l.accessLock.Unlock()
	totalAccesses := uint(0)
	// Get access counts, sort in descending order
	type kv struct {
		Key   K
		Value uint
	}
	var pairs []kv
	for k, v := range l.accesses {
		totalAccesses += v
		pairs = append(pairs, kv{k, v})
	}

	// Sort by Value descending
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Value > pairs[j].Value
	})
	result += fmt.Sprintf("%d Unique IPs\n", len(l.accesses))
	result += fmt.Sprintf("%d Total accesses\n", totalAccesses)
	result += fmt.Sprintf("%f Average accesses per IP\n", float64(totalAccesses)/float64(len(l.accesses)))

	// Print sorted result
	const topK = 20
	result += fmt.Sprintf("Top %d IPs by Accesses:\n", topK)
	for i, p := range pairs {
		if i > topK {
			// Limit to 20 entries for readability
			result += "...\n"
			break
		}
		result += fmt.Sprintf("%v - %d\n", p.Key, p.Value)
	}
	return result
}

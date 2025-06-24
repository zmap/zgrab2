package ratelimit

import (
	"context"
	"fmt"
	"golang.org/x/time/rate"
	"sort"
	"sync"
	"time"
)

// PerObjectRateLimiter manages a per-object rate limit.
// It is thread-safe
type PerObjectRateLimiter[K comparable] struct {
	rates map[K]*rate.Limiter // Rate limiters for each object
	// The individual rate limiters are thread-safe, but in the case that a rate limit is added, the outer map must be protected.
	ratesMutex sync.RWMutex
	// TODO Phillip remove
	accesses   map[K]uint // Access counters for each object
	accessLock sync.Mutex
}

type LRULimiter[K comparable] struct {
	key      K
	lastUsed time.Time
}

type LRUHeap[K comparable] struct {
	limiters []LRULimiter[K] // Slice of limiters sorted by last used time
}

func (h *LRUHeap[K]) Len() int {
	return len(h.limiters)
}

func (h *LRUHeap[K]) Less(i, j int) bool {
	return h.limiters[i].lastUsed.Before(h.limiters[j].lastUsed)
}

func (h *LRUHeap[K]) Swap(i, j int) {
	h.limiters[i], h.limiters[j] = h.limiters[j], h.limiters[i]
}

func (h *LRUHeap[K]) Push(x any) {
	limiter, ok := x.(LRULimiter[K])
	if !ok {
		panic(fmt.Sprintf("expected LRULimiter[K], got %T", x))
	}
	h.limiters = append(h.limiters, limiter)
}

func (h *LRUHeap[K]) Pop() any {
	old := h
	n := h.Len()
	x := old.limiters[n-1]
	h.limiters = old.limiters[0 : n-1]
	return x
}

// NewPerObjectRateLimiter creates a new PerObjectRateLimiter.
func NewPerObjectRateLimiter[K comparable]() *PerObjectRateLimiter[K] {
	return &PerObjectRateLimiter[K]{
		rates:      make(map[K]*rate.Limiter),
		ratesMutex: sync.RWMutex{},
		accesses:   make(map[K]uint),
		accessLock: sync.Mutex{},
	}
}

// WaitOrCreate waits for the rate limiter for the given key to allow access.
// If the rate limiter does not exist, one is created using rateLimit and burstRate
func (l *PerObjectRateLimiter[K]) WaitOrCreate(ctx context.Context, key K, rateLimit rate.Limit, burstRate int) error {
	l.createIfNecessary(key, rateLimit, burstRate) // Ensure the rate limiter exists
	l.ratesMutex.RLock()
	limiter, ok := l.rates[key]
	l.ratesMutex.RUnlock()
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
			if _, ok := l.rates[key]; !ok {
				l.rates[key] = rate.NewLimiter(rateLimit, burstRate)
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
	result += fmt.Sprintf("%d Unique IPs\n", len(l.rates))
	result += fmt.Sprintf("%d Total accesses\n", totalAccesses)
	result += fmt.Sprintf("%f Average accesses per IP\n", float64(totalAccesses)/float64(len(l.rates)))

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

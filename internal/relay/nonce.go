package relay

import (
	"sync"
	"time"
)

// NonceCache tracks recently-seen nonces and rejects duplicates.
//
// Memory bound: at MAX_QPS = 1000 req/s (a reasonable upper bound for
// a single Apps Script deployment, given UrlFetchApp quotas), with
// NonceTTL = 5min, the cache holds ≤ 300k entries (~24 bytes each =
// ~7 MiB). The sweep below is O(n) but runs once per minute, well
// under either deployment's CPU budget.
//
// This type is intended for a Go-hosted verifier (e.g. when running
// the relay endpoint directly on a VPS as an alternative to Apps
// Script). The Apps Script Code.gs uses CacheService for the same
// purpose.
type NonceCache struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	ttl    time.Duration
	stop   chan struct{}
	closed bool
}

// NewNonceCache returns a cache with the given TTL, and starts a
// background sweeper goroutine. Call Close to stop it.
func NewNonceCache(ttl time.Duration) *NonceCache {
	if ttl <= 0 {
		ttl = NonceTTL
	}
	c := &NonceCache{
		seen: make(map[string]time.Time, 1024),
		ttl:  ttl,
		stop: make(chan struct{}),
	}
	go c.sweeper()
	return c
}

// SeenAndStore returns true iff this nonce was already in the cache.
// On false, it's atomically inserted with the current timestamp.
func (c *NonceCache) SeenAndStore(nonce string) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.seen[nonce]; ok && now.Sub(t) <= c.ttl {
		return true
	}
	c.seen[nonce] = now
	return false
}

func (c *NonceCache) sweeper() {
	t := time.NewTicker(c.ttl / 5)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			cutoff := time.Now().Add(-c.ttl)
			c.mu.Lock()
			for k, v := range c.seen {
				if v.Before(cutoff) {
					delete(c.seen, k)
				}
			}
			c.mu.Unlock()
		case <-c.stop:
			return
		}
	}
}

// Close stops the sweeper. Safe to call more than once.
func (c *NonceCache) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	close(c.stop)
}

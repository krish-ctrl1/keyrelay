package core

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// CachingProvider wraps a SecretProvider with a TTL cache. Concurrent misses
// for the same SecretRef are collapsed into one upstream fetch via
// singleflight. Failures are never cached, so recovery is immediate.
type CachingProvider struct {
	next         SecretProvider
	ttl          time.Duration
	fetchTimeout time.Duration
	now          func() time.Time

	mu      sync.Mutex
	entries map[string]cacheEntry
	group   singleflight.Group
}

type cacheEntry struct {
	secret  Secret
	expires time.Time
}

// NewCachingProvider returns a cache in front of next. A ttl <= 0 disables
// caching but keeps request collapsing.
func NewCachingProvider(next SecretProvider, ttl time.Duration) *CachingProvider {
	return &CachingProvider{
		next:         next,
		ttl:          ttl,
		fetchTimeout: 10 * time.Second,
		now:          time.Now,
		entries:      make(map[string]cacheEntry),
	}
}

// GetSecret implements SecretProvider.
func (c *CachingProvider) GetSecret(ctx context.Context, ref SecretRef) (Secret, error) {
	key := ref.String()
	if s, ok := c.lookup(key); ok {
		return s, nil
	}
	ch := c.group.DoChan(key, func() (any, error) {
		if s, ok := c.lookup(key); ok {
			return s, nil
		}
		// The shared fetch must not be cancelled just because the first caller
		// went away; it is bounded by fetchTimeout instead.
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.fetchTimeout)
		defer cancel()
		s, err := c.next.GetSecret(fctx, ref)
		if err != nil {
			return Secret{}, err
		}
		c.store(key, s)
		return s, nil
	})
	select {
	case <-ctx.Done():
		return Secret{}, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return Secret{}, res.Err
		}
		return res.Val.(Secret), nil
	}
}

// Invalidate drops a cached entry, e.g. after the upstream rejects it.
func (c *CachingProvider) Invalidate(ref SecretRef) {
	c.mu.Lock()
	delete(c.entries, ref.String())
	c.mu.Unlock()
}

func (c *CachingProvider) lookup(key string) (Secret, bool) {
	if c.ttl <= 0 {
		return Secret{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return Secret{}, false
	}
	if !c.now().Before(e.expires) {
		delete(c.entries, key)
		return Secret{}, false
	}
	return e.secret, true
}

func (c *CachingProvider) store(key string, s Secret) {
	if c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	c.entries[key] = cacheEntry{secret: s, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
}

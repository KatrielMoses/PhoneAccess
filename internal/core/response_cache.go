package core

import (
	"context"
	"sync"
)

type responseCacheKey struct{}

type ResponseCache struct {
	mu      sync.Mutex
	entries map[string]*responseCacheEntry
}

type responseCacheEntry struct {
	ready chan struct{}
	data  []byte
	err   error
}

func NewResponseCache() *ResponseCache {
	return &ResponseCache{entries: map[string]*responseCacheEntry{}}
}

func ContextWithResponseCache(ctx context.Context, cache *ResponseCache) context.Context {
	if cache == nil {
		cache = NewResponseCache()
	}
	return context.WithValue(ctx, responseCacheKey{}, cache)
}

func ResponseCacheFromContext(ctx context.Context) *ResponseCache {
	if ctx == nil {
		return nil
	}
	cache, _ := ctx.Value(responseCacheKey{}).(*ResponseCache)
	return cache
}

func (c *ResponseCache) Get(key string) ([]byte, bool) {
	if c == nil || key == "" {
		return nil, false
	}
	c.mu.Lock()
	entry := c.entries[key]
	c.mu.Unlock()
	if entry == nil {
		return nil, false
	}
	<-entry.ready
	if entry.err != nil {
		return nil, false
	}
	return cloneBytes(entry.data), true
}

func (c *ResponseCache) GetOrFetch(ctx context.Context, key string, fetch func(context.Context) ([]byte, error)) ([]byte, error) {
	if c == nil || key == "" {
		return fetch(ctx)
	}

	c.mu.Lock()
	if entry := c.entries[key]; entry != nil {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-entry.ready:
			return cloneBytes(entry.data), entry.err
		}
	}
	entry := &responseCacheEntry{ready: make(chan struct{})}
	c.entries[key] = entry
	c.mu.Unlock()

	entry.data, entry.err = fetch(ctx)
	if entry.err == nil {
		entry.data = cloneBytes(entry.data)
	}
	close(entry.ready)

	return cloneBytes(entry.data), entry.err
}

func cloneBytes(data []byte) []byte {
	if data == nil {
		return nil
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out
}

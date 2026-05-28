package core

import (
	"context"
	"sync"
	"time"
)

type RateLimiter struct {
	mu       sync.Mutex
	lastSeen map[string]time.Time
	delay    time.Duration
}

func NewRateLimiter(delay time.Duration) *RateLimiter {
	if delay < 0 {
		delay = 0
	}
	return &RateLimiter{
		lastSeen: map[string]time.Time{},
		delay:    delay,
	}
}

func (r *RateLimiter) Wait(ctx context.Context, key string) error {
	if r == nil || r.delay == 0 || key == "" {
		return nil
	}

	for {
		r.mu.Lock()
		now := time.Now()
		wait := r.delay - now.Sub(r.lastSeen[key])
		if wait <= 0 {
			r.lastSeen[key] = now
			r.mu.Unlock()
			return nil
		}
		r.mu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

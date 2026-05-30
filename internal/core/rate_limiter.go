package core

import (
	"context"
	"math/rand"
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

// jitter applies ±30% random variance to base, keeping the result positive.
func jitter(base time.Duration) time.Duration {
	factor := 0.7 + rand.Float64()*0.6 // 0.70 to 1.30
	d := time.Duration(float64(base) * factor)
	if d <= 0 {
		return base
	}
	return d
}

func (r *RateLimiter) Wait(ctx context.Context, key string) error {
	if r == nil || r.delay == 0 || key == "" {
		return nil
	}

	effectiveDelay := jitter(r.delay)

	for {
		r.mu.Lock()
		now := time.Now()
		wait := effectiveDelay - now.Sub(r.lastSeen[key])
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

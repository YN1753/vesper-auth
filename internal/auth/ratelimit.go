package auth

import (
	"sync"
	"time"
)

type attemptBucket struct {
	failures    []time.Time
	lockedUntil time.Time
	lastTouch   time.Time
}

// RateLimiter tracks authentication failures per dimension (e.g. IP, account, client)
// and enforces a cooldown lockout after repeated failures with a bounded bucket map.
type RateLimiter struct {
	mu          sync.Mutex
	buckets     map[string]*attemptBucket
	maxAttempts int
	window      time.Duration
	lockout     time.Duration
	maxBuckets  int
	now         func() time.Time
	lastSweep   time.Time
}

// NewRateLimiter creates a RateLimiter with the given threshold, failure window, and lockout duration.
func NewRateLimiter(maxAttempts int, window, lockout time.Duration) *RateLimiter {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if window <= 0 {
		window = 10 * time.Minute
	}
	if lockout <= 0 {
		lockout = 15 * time.Minute
	}
	now := time.Now
	return &RateLimiter{
		buckets:     make(map[string]*attemptBucket),
		maxAttempts: maxAttempts,
		window:      window,
		lockout:     lockout,
		maxBuckets:  10000,
		now:         now,
		lastSweep:   now(),
	}
}

// SetMaxBuckets configures the maximum number of tracked keys in memory.
func (r *RateLimiter) SetMaxBuckets(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n > 0 {
		r.maxBuckets = n
	}
}

// Len returns the current number of active buckets in memory.
func (r *RateLimiter) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets)
}

// SetClock overrides the internal clock (intended for unit testing).
func (r *RateLimiter) SetClock(fn func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = fn
	r.lastSweep = fn()
}

// Check verifies whether any of the provided keys is currently locked out.
// Returns allowed=true if none are locked, or allowed=false with the longest remaining cooldown.
func (r *RateLimiter) Check(keys ...string) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	r.sweepIfDueLocked(now)

	var maxWait time.Duration
	for _, k := range keys {
		if k == "" {
			continue
		}
		b, ok := r.buckets[k]
		if !ok {
			continue
		}
		if b.lockedUntil.After(now) {
			wait := b.lockedUntil.Sub(now)
			if wait > maxWait {
				maxWait = wait
			}
		}
	}
	if maxWait > 0 {
		return false, maxWait
	}
	return true, 0
}

// RecordFailure records a failed attempt for each non-empty key and triggers lockout
// if failures within the window reach maxAttempts.
func (r *RateLimiter) RecordFailure(keys ...string) (locked bool, retryAfter time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	r.sweepIfDueLocked(now)

	cutoff := now.Add(-r.window)
	for _, k := range keys {
		if k == "" {
			continue
		}
		b, ok := r.buckets[k]
		if !ok {
			r.ensureCapacityLocked(now)
			b = &attemptBucket{}
			r.buckets[k] = b
		}
		b.lastTouch = now

		pruned := b.failures[:0]
		for _, ts := range b.failures {
			if ts.After(cutoff) {
				pruned = append(pruned, ts)
			}
		}
		b.failures = append(pruned, now)

		if len(b.failures) >= r.maxAttempts {
			b.lockedUntil = now.Add(r.lockout)
			b.failures = nil
			locked = true
			if r.lockout > retryAfter {
				retryAfter = r.lockout
			}
		} else if b.lockedUntil.After(now) {
			locked = true
			if w := b.lockedUntil.Sub(now); w > retryAfter {
				retryAfter = w
			}
		}
	}
	return locked, retryAfter
}

// Reset clears failure counters and lockouts for the provided keys (typically on successful auth).
func (r *RateLimiter) Reset(keys ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, k := range keys {
		if k != "" {
			delete(r.buckets, k)
		}
	}
}

func (r *RateLimiter) sweepIfDueLocked(now time.Time) {
	if now.Sub(r.lastSweep) < 5*time.Minute {
		return
	}
	r.evictExpiredLocked(now)
}

func (r *RateLimiter) evictExpiredLocked(now time.Time) {
	r.lastSweep = now
	cutoff := now.Add(-r.window)
	for k, b := range r.buckets {
		if b.lockedUntil.After(now) {
			continue
		}
		hasRecent := false
		for _, ts := range b.failures {
			if ts.After(cutoff) {
				hasRecent = true
				break
			}
		}
		if !hasRecent {
			delete(r.buckets, k)
		}
	}
}

func (r *RateLimiter) ensureCapacityLocked(now time.Time) {
	if len(r.buckets) < r.maxBuckets {
		return
	}
	r.evictExpiredLocked(now)
	if len(r.buckets) < r.maxBuckets {
		return
	}

	// Prefer evicting the least-recently-touched unlocked entry; fallback to earliest-expiring locked entry.
	var victimUnlocked string
	var oldestTouch time.Time
	var victimLocked string
	var earliestUnlock time.Time

	for k, b := range r.buckets {
		if !b.lockedUntil.After(now) {
			if victimUnlocked == "" || b.lastTouch.Before(oldestTouch) {
				victimUnlocked = k
				oldestTouch = b.lastTouch
			}
		} else {
			if victimLocked == "" || b.lockedUntil.Before(earliestUnlock) {
				victimLocked = k
				earliestUnlock = b.lockedUntil
			}
		}
	}

	if victimUnlocked != "" {
		delete(r.buckets, victimUnlocked)
	} else if victimLocked != "" {
		delete(r.buckets, victimLocked)
	}
}

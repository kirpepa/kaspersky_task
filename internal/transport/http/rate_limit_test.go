package httptransport

import (
	"context"
	"math"
	"net/netip"
	"testing"
	"time"
)

func newClockedLimiter(t *testing.T, rps float64, burst, maxClients int, ttl time.Duration) (*IPRateLimiter, *time.Time) {
	t.Helper()
	limiter, err := NewIPRateLimiter(rps, burst, maxClients, ttl)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }
	return limiter, &now
}

func TestIPRateLimitRefillsWithoutResettingOnRejectedRequests(t *testing.T) {
	limiter, now := newClockedLimiter(t, 10, 2, 10, time.Minute)
	ip := netip.MustParseAddr("203.0.113.10")
	for i := 0; i < 2; i++ {
		if allowed, _ := limiter.allow(ip); !allowed {
			t.Fatal("initial burst was rejected")
		}
	}
	if allowed, retry := limiter.allow(ip); allowed || retry != 1 {
		t.Fatalf("exhausted limit: allowed=%v retry=%d; want false, 1", allowed, retry)
	}
	*now = now.Add(50 * time.Millisecond)
	if allowed, _ := limiter.allow(ip); allowed {
		t.Fatal("a fractional token allowed a request")
	}
	*now = now.Add(50 * time.Millisecond)
	if allowed, _ := limiter.allow(ip); !allowed {
		t.Fatal("request rejected after one token replenished")
	}
	if allowed, _ := limiter.allow(ip); allowed {
		t.Fatal("one replenished token allowed two requests")
	}
	*now = now.Add(time.Hour)
	for i := 0; i < 2; i++ {
		if allowed, _ := limiter.allow(ip); !allowed {
			t.Fatal("burst did not refill after inactivity")
		}
	}
	if allowed, _ := limiter.allow(ip); allowed {
		t.Fatal("long inactivity accumulated more than the configured burst")
	}
}

func TestIPRateLimitRetryAfterRoundsUpForSlowRates(t *testing.T) {
	limiter, now := newClockedLimiter(t, 0.4, 1, 10, time.Minute)
	ip := netip.MustParseAddr("203.0.113.10")
	limiter.allow(ip)
	if allowed, retry := limiter.allow(ip); allowed || retry != 3 {
		t.Fatalf("2.5 second wait: allowed=%v retry=%d; want false, 3", allowed, retry)
	}
	*now = now.Add(750 * time.Millisecond)
	if allowed, retry := limiter.allow(ip); allowed || retry != 2 {
		t.Fatalf("1.75 second wait: allowed=%v retry=%d; want false, 2", allowed, retry)
	}
	*now = now.Add(1750 * time.Millisecond)
	if allowed, _ := limiter.allow(ip); !allowed {
		t.Fatal("request rejected after the actual refill delay")
	}
}

func TestIPRateLimitCleanupKeepsClientsMakingDeniedRequests(t *testing.T) {
	limiter, now := newClockedLimiter(t, 0.01, 1, 2, 100*time.Second)
	active := netip.MustParseAddr("203.0.113.10")
	idle := netip.MustParseAddr("203.0.113.20")
	limiter.allow(active)
	limiter.allow(idle)
	*now = now.Add(90 * time.Second)
	if allowed, _ := limiter.allow(active); allowed {
		t.Fatal("request was allowed before refill")
	}
	*now = now.Add(10 * time.Second)
	limiter.cleanup()
	if _, exists := limiter.clients[idle]; exists {
		t.Fatal("idle client was not removed at its expiry")
	}
	if _, exists := limiter.clients[active]; !exists {
		t.Fatal("a client still making requests was removed")
	}
	*now = now.Add(90 * time.Second)
	limiter.cleanup()
	if len(limiter.clients) != 0 {
		t.Fatal("registry was not emptied after all clients became inactive")
	}
}

func TestIPRateLimitCapacityDoesNotEvictActiveClients(t *testing.T) {
	limiter, now := newClockedLimiter(t, 1, 2, 1, 10*time.Second)
	first := netip.MustParseAddr("203.0.113.10")
	second := netip.MustParseAddr("203.0.113.20")
	limiter.allow(first)
	if allowed, retry := limiter.allow(second); allowed || retry != 10 {
		t.Fatalf("full registry: allowed=%v retry=%d; want false, 10", allowed, retry)
	}
	*now = now.Add(time.Second)
	if allowed, _ := limiter.allow(first); !allowed {
		t.Fatal("existing client was blocked by registry capacity")
	}
	*now = now.Add(9 * time.Second)
	if allowed, retry := limiter.allow(second); allowed || retry != 1 {
		t.Fatalf("postponed expiry: allowed=%v retry=%d; want false, 1", allowed, retry)
	}
	if _, exists := limiter.clients[first]; !exists {
		t.Fatal("active client was evicted to admit a new IP")
	}
	*now = now.Add(time.Second)
	if allowed, _ := limiter.allow(second); !allowed {
		t.Fatal("new IP could not reuse expired capacity before periodic cleanup")
	}
	if len(limiter.clients) != 1 {
		t.Fatalf("registry contains %d entries, want 1", len(limiter.clients))
	}
	if _, exists := limiter.clients[first]; exists {
		t.Fatal("expired client was retained")
	}
}

func TestIPRateLimiterRejectsUnsafeSettings(t *testing.T) {
	tests := []struct {
		name              string
		rps               float64
		burst, maxClients int
		ttl               time.Duration
	}{
		{"zero rate", 0, 1, 1, time.Minute},
		{"negative rate", -1, 1, 1, time.Minute},
		{"NaN rate", math.NaN(), 1, 1, time.Minute},
		{"infinite rate", math.Inf(1), 1, 1, time.Minute},
		{"zero burst", 1, 0, 1, time.Minute},
		{"negative burst", 1, -1, 1, time.Minute},
		{"zero capacity", 1, 1, 0, time.Minute},
		{"negative capacity", 1, 1, -1, time.Minute},
		{"zero TTL", 1, 1, 1, 0},
		{"negative TTL", 1, 1, 1, -time.Minute},
		{"expiry before refill", 1, 2, 1, time.Second},
		{"unrepresentable refill time", math.SmallestNonzeroFloat64, 1, 1, time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewIPRateLimiter(tt.rps, tt.burst, tt.maxClients, tt.ttl); err == nil {
				t.Fatal("invalid settings were accepted")
			}
		})
	}
	if _, err := NewIPRateLimiter(1, 2, 1, 2*time.Second); err != nil {
		t.Fatalf("TTL equal to refill time should be accepted: %v", err)
	}
}

func TestIPRateLimiterCleanupTaskStopsOnCancellation(t *testing.T) {
	limiter, _ := newClockedLimiter(t, 1, 1, 1, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		limiter.Run(ctx)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup task did not stop when cancelled")
	}
}

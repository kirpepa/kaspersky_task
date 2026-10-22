package httptransport

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const rateLimitCleanupInterval = time.Minute

type ipRateLimitClient struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// IPRateLimiter keeps a separate token bucket for each directly connected IP.
// Its state is local to this process and is safe for concurrent requests.
type IPRateLimiter struct {
	mu         sync.Mutex
	clients    map[netip.Addr]*ipRateLimitClient
	rps        rate.Limit
	burst      int
	maxClients int
	idleTTL    time.Duration
	// Activity can postpone expiry, so this is a lower bound until the next
	// cleanup. It avoids scanning a full registry on every unknown IP.
	nextExpiry time.Time
	now        func() time.Time
}

// NewIPRateLimiter creates a bounded registry. idleTTL must allow an empty
// bucket to refill completely before removing its state.
func NewIPRateLimiter(rps float64, burst, maxClients int, idleTTL time.Duration) (*IPRateLimiter, error) {
	if math.IsNaN(rps) || math.IsInf(rps, 0) || rps <= 0 {
		return nil, errors.New("rate limit RPS must be finite and positive")
	}
	if burst <= 0 || maxClients <= 0 || idleTTL <= 0 {
		return nil, errors.New("rate limit burst, max clients and idle TTL must be positive")
	}
	if float64(burst)/rps > idleTTL.Seconds() {
		return nil, errors.New("rate limit idle TTL must be at least burst / RPS to avoid resetting an exhausted limit")
	}
	return &IPRateLimiter{
		clients:    make(map[netip.Addr]*ipRateLimitClient),
		rps:        rate.Limit(rps),
		burst:      burst,
		maxClients: maxClients,
		idleTTL:    idleTTL,
		now:        time.Now,
	}, nil
}

// Run periodically removes inactive clients until ctx is cancelled. The caller
// owns this background task; creating a limiter does not start a goroutine.
func (l *IPRateLimiter) Run(ctx context.Context) {
	ticker := time.NewTicker(rateLimitCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.cleanup()
		}
	}
}

// allow returns a retry delay in whole seconds when a request is denied.
func (l *IPRateLimiter) allow(ip netip.Addr) (bool, int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	client, exists := l.clients[ip]
	if !exists {
		if len(l.clients) >= l.maxClients {
			if !now.Before(l.nextExpiry) {
				l.cleanupLocked(now)
			}
			if len(l.clients) >= l.maxClients {
				return false, retryAfterSeconds(l.nextExpiry.Sub(now).Seconds())
			}
		}
		client = &ipRateLimitClient{limiter: rate.NewLimiter(l.rps, l.burst)}
		l.clients[ip] = client
		expires := now.Add(l.idleTTL)
		if l.nextExpiry.IsZero() || expires.Before(l.nextExpiry) {
			l.nextExpiry = expires
		}
	}
	// Denied requests count as activity too: an active IP must not regain a
	// fresh bucket through registry cleanup.
	client.lastSeen = now
	if client.limiter.AllowN(now, 1) {
		return true, 0
	}
	seconds := (1 - client.limiter.TokensAt(now)) / float64(l.rps)
	return false, retryAfterSeconds(seconds)
}

func retryAfterSeconds(seconds float64) int64 {
	return max(1, int64(math.Ceil(seconds)))
}

func (l *IPRateLimiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanupLocked(l.now())
}

func (l *IPRateLimiter) cleanupLocked(now time.Time) {
	l.nextExpiry = time.Time{}
	for ip, client := range l.clients {
		expires := client.lastSeen.Add(l.idleTTL)
		if !now.Before(expires) {
			delete(l.clients, ip)
			continue
		}
		if l.nextExpiry.IsZero() || expires.Before(l.nextExpiry) {
			l.nextExpiry = expires
		}
	}
}

func (h *handler) rateLimit(limiter *IPRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// RemoteAddr is supplied by net/http. Forwarding headers are ignored
			// because this service has no configured trusted reverse proxies.
			peer, err := netip.ParseAddrPort(r.RemoteAddr)
			if err != nil {
				h.writeJSON(w, http.StatusBadRequest, newErrorResponse("Invalid client address", "Could not determine the client IP from the connection"))
				return
			}
			ip := peer.Addr().Unmap().WithZone("")
			allowed, retryAfter := limiter.allow(ip)
			if !allowed {
				if r.ProtoMajor == 1 && r.Body != nil && r.Body != http.NoBody {
					// Send the rejection before net/http drains an unread body.
					w.Header().Set("Connection", "close")
				}
				w.Header().Set("Retry-After", strconv.FormatInt(retryAfter, 10))
				w.Header().Set("Cache-Control", "no-store")
				h.writeJSON(w, http.StatusTooManyRequests, newErrorResponse("Too many requests", "Retry after the delay specified in the Retry-After header"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

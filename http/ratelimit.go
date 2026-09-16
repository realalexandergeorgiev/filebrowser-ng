package fbhttp

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Login/signup have no brute-force protection upstream (docs delegate to
// fail2ban). This sliding-window limiter rejects excessive attempts per
// direct TCP peer with 429. Forwarded headers are ignored on purpose:
// clients can spoof them, the TCP peer cannot.
//
// The limiter lives in the handler closure: NewHandler builds routes once,
// so production shares one limiter, while tests wrapping handle() per call
// stay isolated from each other.
type rateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
	now    func() time.Time
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		hits:   map[string][]time.Time{},
		max:    max,
		window: window,
		now:    time.Now,
	}
}

// allow records a hit and reports whether it fits the budget. When the
// budget is spent it also returns how long the caller should wait.
func (l *rateLimiter) allow(ip string) (bool, time.Duration) {
	now := l.now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	kept := l.hits[ip][:0]
	for _, t := range l.hits[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		return false, kept[0].Add(l.window).Sub(now).Round(time.Second)
	}
	l.hits[ip] = append(kept, now)
	return true, 0
}

// peerIP keys the limiter by TCP peer. Empty peers share one bucket, which
// only matters for in-process tests that bypass the network.
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// check enforces the budget for the request's peer, writing 429 with a
// Retry-After hint when it is spent. It reports whether the request may
// proceed.
func (l *rateLimiter) check(w http.ResponseWriter, r *http.Request) bool {
	ok, retryAfter := l.allow(peerIP(r))
	if ok {
		return true
	}
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter/time.Second)))
	return false
}

package fbhttp

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	fbAuth "github.com/realalexandergeorgiev/filebrowser-ng/auth"
)

// Brute-force protection on top of the per-endpoint rate budgets: peers that
// keep failing authentication are banned from the whole API for a while.
// Failures that count are presented-but-wrong credentials only — a wrong
// login password, a wrong share password, a token with a bad signature.
// Missing, malformed or expired tokens (and sessions that lapsed
// server-side) are normal client state and never count, so logged-out tabs
// or a corrupt cookie cannot ban anyone.
//
// Like the rate limiter, bans key on the TCP peer, never on forwarded
// headers from untrusted peers: clients can spoof those, the TCP peer
// cannot. When the peer is a configured trusted proxy, the forwarded client
// IP is banned instead, so one attacker behind a shared proxy cannot ban
// every user at once (see banKey).
//
// The list is in-process: a restart clears bans, and replicas do not share
// them (same limitation as the rate budgets). Entries expire on their own
// and the maps are capped, so attackers cannot grow memory without bound.
const (
	// maxBanFailures in banFailWindow triggers a ban of banDuration.
	maxBanFailures = 10
	banFailWindow  = 10 * time.Minute
	banDuration    = time.Hour

	// maxBanPeers bounds both maps together.
	maxBanPeers = 10000
)

type ipBanList struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	duration time.Duration
	cap      int
	fails    map[string][]time.Time
	bans     map[string]time.Time
	now      func() time.Time
}

// ipBans is process-wide so every handler shares one view of hostile peers.
var ipBans = newIPBanList(maxBanFailures, banFailWindow, banDuration, maxBanPeers)

func newIPBanList(max int, window, duration time.Duration, cap int) *ipBanList {
	return &ipBanList{
		max:      max,
		window:   window,
		duration: duration,
		cap:      cap,
		fails:    map[string][]time.Time{},
		bans:     map[string]time.Time{},
		now:      time.Now,
	}
}

// banned reports whether the peer is currently banned and how long the ban
// still lasts. Expired bans are dropped lazily.
func (b *ipBanList) banned(ip string) (time.Duration, bool) {
	now := b.now()

	b.mu.Lock()
	defer b.mu.Unlock()

	exp, ok := b.bans[ip]
	if !ok {
		return 0, false
	}
	if !now.Before(exp) {
		delete(b.bans, ip)
		return 0, false
	}
	return exp.Sub(now).Round(time.Second), true
}

// fail records one authentication failure and bans the peer once the budget
// is spent. Bans are logged so probes stay visible in the server log.
func (b *ipBanList) fail(ip string) {
	now := b.now()

	b.mu.Lock()
	defer b.mu.Unlock()

	if exp, ok := b.bans[ip]; ok {
		if now.Before(exp) {
			return // already banned: keep the original expiry
		}
		delete(b.bans, ip)
	}
	if _, ok := b.fails[ip]; !ok {
		b.makeRoomLocked(now)
		if len(b.fails)+len(b.bans) >= b.cap {
			return // fail open for new peers under flood; bans still hold
		}
	}

	cutoff := now.Add(-b.window)
	kept := b.fails[ip][:0]
	for _, t := range b.fails[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	b.fails[ip] = kept

	if len(kept) < b.max {
		return
	}
	delete(b.fails, ip)
	b.bans[ip] = now.Add(b.duration)
	log.Printf("banning %s for %s after %d auth failures in %s", ip, b.duration, b.max, b.window)
}

// reset clears a peer's failures and any active ban. A successful login
// proves legitimacy, so it resets the peer.
func (b *ipBanList) reset(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.fails, ip)
	delete(b.bans, ip)
}

// makeRoomLocked drops expired entries; if the maps are still full it evicts
// the peer with the stalest failure history.
func (b *ipBanList) makeRoomLocked(now time.Time) {
	cutoff := now.Add(-b.window)
	for ip, ts := range b.fails {
		kept := ts[:0]
		for _, t := range ts {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(b.fails, ip)
		} else {
			b.fails[ip] = kept
		}
	}
	for ip, exp := range b.bans {
		if !now.Before(exp) {
			delete(b.bans, ip)
		}
	}
	if len(b.fails)+len(b.bans) < b.cap {
		return
	}
	var (
		victim    string
		victimSet bool
		oldest    time.Time
	)
	for ip, ts := range b.fails {
		if len(ts) == 0 {
			continue
		}
		if !victimSet || ts[0].Before(oldest) {
			victim, victimSet, oldest = ip, true, ts[0]
		}
	}
	if victimSet {
		delete(b.fails, victim)
	}
}

// check refuses banned peers with 429 plus a Retry-After hint and logs the
// refusal. It reports whether the request may proceed.
func (b *ipBanList) check(w http.ResponseWriter, r *http.Request, trusted []string) bool {
	key := banKey(r, trusted)
	retryAfter, ok := b.banned(key)
	if !ok {
		return true
	}
	if retryAfter < time.Second {
		retryAfter = time.Second
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter/time.Second)))
	log.Print(formatRequestLog(r.URL.Path, http.StatusTooManyRequests, key, nil))
	return false
}

// banKey attributes a request to its TCP peer, except when the peer is a
// trusted proxy: then the forwarded client is keyed instead. Forwarded
// headers from untrusted peers are never honored.
func banKey(r *http.Request, trusted []string) string {
	if fbAuth.TrustedProxyPeer(r, trusted) {
		if client := forwardedClientIP(r); client != "" {
			return client
		}
	}
	return peerIP(r)
}

// forwardedClientIP takes the rightmost X-Forwarded-For entry. Our trusted
// proxy appends the true peer last, so the rightmost entry is the hardest to
// spoof; anything left of it is attacker-controlled and ignored.
func forwardedClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			if client := strings.TrimSpace(parts[i]); client != "" {
				return client
			}
		}
	}
	return strings.TrimSpace(r.Header.Get("X-Real-Ip"))
}

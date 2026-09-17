package fbhttp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/realalexandergeorgiev/filebrowser-ng/settings"
	"github.com/realalexandergeorgiev/filebrowser-ng/share"
	"github.com/realalexandergeorgiev/filebrowser-ng/users"
)

// swapBanList replaces the process-wide ban list with a fresh one for a
// single test: production handlers share ipBans, so tests that provoke bans
// must not leak them into other tests.
func swapBanList(t *testing.T, max int) {
	t.Helper()
	old := ipBans
	ipBans = newIPBanList(max, banFailWindow, banDuration, maxBanPeers)
	t.Cleanup(func() { ipBans = old })
}

func TestIPBanListThresholdAndExpiry(t *testing.T) {
	now := time.Now()
	b := newIPBanList(3, 10*time.Minute, time.Hour, 100)
	b.now = func() time.Time { return now }

	for i := 0; i < 2; i++ {
		b.fail("10.0.0.1")
		if _, ok := b.banned("10.0.0.1"); ok {
			t.Fatalf("banned after %d failures, want threshold 3", i+1)
		}
	}
	b.fail("10.0.0.1")
	retry, ok := b.banned("10.0.0.1")
	if !ok {
		t.Fatalf("not banned after 3 failures")
	}
	if retry <= 50*time.Minute || retry > time.Hour {
		t.Fatalf("ban remainder = %v, want ~1h", retry)
	}

	// Failures outside the window do not accumulate.
	b2 := newIPBanList(3, 10*time.Minute, time.Hour, 100)
	b2.now = func() time.Time { return now }
	b2.fail("10.0.0.2")
	now = now.Add(11 * time.Minute)
	b2.fail("10.0.0.2")
	if _, ok := b2.banned("10.0.0.2"); ok {
		t.Fatalf("failures 11 minutes apart banned the peer")
	}

	// The ban lapses on its own.
	now = now.Add(time.Hour)
	if _, ok := b.banned("10.0.0.1"); ok {
		t.Fatalf("ban survived its duration")
	}
}

func TestIPBanListReset(t *testing.T) {
	b := newIPBanList(2, 10*time.Minute, time.Hour, 100)
	b.fail("10.0.0.3")
	b.reset("10.0.0.3")
	b.fail("10.0.0.3")
	if _, ok := b.banned("10.0.0.3"); ok {
		t.Fatalf("banned after reset + 1 failure, want a clean record")
	}
}

func TestIPBanListCap(t *testing.T) {
	b := newIPBanList(100, 10*time.Minute, time.Hour, 3)
	for _, ip := range []string{"10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4"} {
		b.fail(ip)
	}
	b.mu.Lock()
	n := len(b.fails) + len(b.bans)
	b.mu.Unlock()
	if n > 3 {
		t.Fatalf("tracked %d peers with cap 3", n)
	}
	// The newest peer is still tracked and protectable.
	b.mu.Lock()
	_, tracked := b.fails["10.0.1.4"]
	b.mu.Unlock()
	if !tracked {
		t.Fatalf("newest peer evicted instead of the stalest")
	}
}

func TestBanKeyResolution(t *testing.T) {
	req := func(remote, xff, xrip string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		if xrip != "" {
			r.Header.Set("X-Real-Ip", xrip)
		}
		return r
	}
	trusted := []string{"127.0.0.0/8"}

	// Untrusted peers cannot launder or frame anyone via headers.
	if got := banKey(req("203.0.113.5:443", "198.51.100.9", ""), nil); got != "203.0.113.5" {
		t.Errorf("untrusted XFF honored: %q", got)
	}
	// Behind a trusted proxy the forwarded client is keyed (rightmost:
	// what our proxy appended last, hardest to spoof).
	if got := banKey(req("127.0.0.1:1234", "198.51.100.9, 203.0.113.1", ""), trusted); got != "203.0.113.1" {
		t.Errorf("rightmost XFF = %q", got)
	}
	if got := banKey(req("127.0.0.1:1234", "", "198.51.100.9"), trusted); got != "198.51.100.9" {
		t.Errorf("X-Real-Ip = %q", got)
	}
	if got := banKey(req("127.0.0.1:1234", "", ""), trusted); got != "127.0.0.1" {
		t.Errorf("no headers = %q", got)
	}
}

func TestLoginFailuresBanPeer(t *testing.T) {
	swapBanList(t, 3)
	st, _ := sessionTestSetup(t)
	peer := "198.51.100.7:1234"

	login := handle(loginHandler(time.Hour), "", st, &settings.Server{})
	tryLogin := func(password string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"username":"u","password":%q}`, password)
		req, _ := http.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		req.RemoteAddr = peer
		rec := httptest.NewRecorder()
		login.ServeHTTP(rec, req)
		return rec
	}

	for i := 0; i < 3; i++ {
		if rec := tryLogin("wrong-password"); rec.Code != http.StatusForbidden {
			t.Fatalf("failure %d = %d, want 403", i+1, rec.Code)
		}
	}

	// The ban is global: even an unauthenticated probe is refused now.
	probe := handle(withUser(func(w http.ResponseWriter, _ *http.Request, _ *data) (int, error) {
		_, err := w.Write([]byte("protected"))
		return 0, err
	}), "", st, &settings.Server{})
	req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = peer
	rec := httptest.NewRecorder()
	probe.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("banned peer probe = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Errorf("ban 429 without Retry-After hint")
	}

	// Other peers are unaffected.
	req2, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	req2.RemoteAddr = "198.51.100.8:1234"
	rec2 := httptest.NewRecorder()
	probe.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("other peer probe = %d, want 401", rec2.Code)
	}
}

func TestSuccessfulLoginResetsPeer(t *testing.T) {
	swapBanList(t, 3)
	st, _ := sessionTestSetup(t)
	peer := "198.51.100.9:1234"

	h := handle(loginHandler(time.Hour), "", st, &settings.Server{})
	tryLogin := func(password string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"username":"u","password":%q}`, password)
		req, _ := http.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		req.RemoteAddr = peer
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	for i := 0; i < 2; i++ {
		if rec := tryLogin("wrong-password"); rec.Code != http.StatusForbidden {
			t.Fatalf("failure %d = %d, want 403", i+1, rec.Code)
		}
	}
	if rec := tryLogin(sessionTestPassword); rec.Code != http.StatusOK {
		t.Fatalf("correct password = %d, want 200", rec.Code)
	}
	// Without the reset these two would be failures 3+4 and ban the peer.
	for i := 0; i < 2; i++ {
		if rec := tryLogin("wrong-password"); rec.Code != http.StatusForbidden {
			t.Fatalf("post-login failure %d = %d, want 403 (no ban)", i+1, rec.Code)
		}
	}
}

func TestForgedTokenCountsTowardsBan(t *testing.T) {
	swapBanList(t, 3)
	h := routingTestHandler(t)
	peer := "198.51.100.10:1234"

	// JWT-shaped but signed with the wrong key: pure guessing.
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &authToken{
		User:             userInfo{ID: 1, Username: "u"},
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
	}).SignedString([]byte("attacker-key"))
	if err != nil {
		t.Fatal(err)
	}

	get := func(peer, token string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodGet, "/api/users", http.NoBody)
		req.RemoteAddr = peer
		if token != "" {
			req.Header.Set("X-Auth", token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Requests without any credential never count, however many.
	for i := 0; i < 5; i++ {
		if rec := get(peer, ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("credential-less probe %d = %d, want 401", i+1, rec.Code)
		}
	}
	// Malformed tokens do not count either.
	for i := 0; i < 5; i++ {
		if rec := get(peer, "bogus"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("malformed-token probe %d = %d, want 401", i+1, rec.Code)
		}
	}
	// Forged tokens do: three strikes, then the peer is banned.
	for i := 0; i < 3; i++ {
		if rec := get(peer, forged); rec.Code != http.StatusUnauthorized {
			t.Fatalf("forged token %d = %d, want 401", i+1, rec.Code)
		}
	}
	if rec := get(peer, forged); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("banned peer = %d, want 429", rec.Code)
	}
}

func TestSharePasswordFailuresBanPeer(t *testing.T) {
	swapBanList(t, 3)
	userScope := t.TempDir()
	if err := os.WriteFile(filepath.Join(userScope, "secret.txt"), []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}

	perm := users.Permissions{Share: true, Download: true}
	st := scopedUserStorage(t, userScope, perm, []byte("test-signing-key"))

	pwHash, status, err := getSharePasswordHash(share.CreateBody{Password: "LinkSecret123!"})
	if err != nil || status != 0 {
		t.Fatalf("hash password: %v %d", err, status)
	}
	const hash = "banlinktesthash1"
	if err := st.Share.Save(&share.Link{
		Path: "/secret.txt", Hash: hash, Expire: 0, UserID: 1,
		PasswordHash: string(pwHash), Token: "link-bypass-token",
	}); err != nil {
		t.Fatal(err)
	}

	peer := "198.51.100.11:1234"
	h := handle(publicDlHandler, "", st, &settings.Server{})
	try := func(password string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodGet, hash, http.NoBody)
		req.RemoteAddr = peer
		req.Header.Set("X-SHARE-PASSWORD", password)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	for i := 0; i < 3; i++ {
		if rec := try("wrong-password"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("guess %d = %d, want 401", i+1, rec.Code)
		}
	}
	// Banned: even the correct password is refused now.
	if rec := try("LinkSecret123!"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("banned peer with correct password = %d, want 429", rec.Code)
	}
}

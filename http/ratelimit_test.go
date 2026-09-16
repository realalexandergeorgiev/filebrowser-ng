package fbhttp

// Login/signup had no brute-force protection (docs delegated to fail2ban).
// Attempts per TCP peer are now budgeted; overshoot answers 429.
import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/filebrowser/filebrowser/v2/settings"
)

func TestRateLimiterBudgetAndWindow(t *testing.T) {
	now := time.Now()
	l := newRateLimiter(2, time.Minute)
	l.now = func() time.Time { return now }

	if ok, _ := l.allow("10.0.0.1"); !ok {
		t.Fatalf("first hit denied")
	}
	if ok, _ := l.allow("10.0.0.1"); !ok {
		t.Fatalf("second hit denied")
	}
	if ok, retry := l.allow("10.0.0.1"); ok || retry <= 0 {
		t.Fatalf("third hit = %v, retry %v; want deny with hint", ok, retry)
	}
	// Another peer has its own budget.
	if ok, _ := l.allow("10.0.0.2"); !ok {
		t.Fatalf("other peer denied")
	}
	// After the window the budget is back.
	now = now.Add(61 * time.Second)
	if ok, _ := l.allow("10.0.0.1"); !ok {
		t.Fatalf("hit after window denied")
	}
}

func TestPeerIPParsing(t *testing.T) {
	req := func(addr string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
		r.RemoteAddr = addr
		return r
	}
	if got := peerIP(req("203.0.113.5:443")); got != "203.0.113.5" {
		t.Errorf("host:port -> %q", got)
	}
	if got := peerIP(req("[::1]:80")); got != "::1" {
		t.Errorf("v6 -> %q", got)
	}
	if got := peerIP(req("10.0.0.9")); got != "10.0.0.9" {
		t.Errorf("bare ip -> %q", got)
	}
}

func TestLoginRateLimited(t *testing.T) {
	st, _ := sessionTestSetup(t)
	h := handle(loginHandler(time.Hour), "", st, &settings.Server{})

	try := func() *httptest.ResponseRecorder {
		body := `{"username":"u","password":"wrong-password"}`
		req, _ := http.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	for i := 0; i < maxLoginAttempts; i++ {
		if rec := try(); rec.Code != http.StatusForbidden {
			t.Fatalf("attempt %d = %d, want 403 (bad password, within budget)", i+1, rec.Code)
		}
	}
	rec := try()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-budget attempt = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Errorf("429 without Retry-After hint")
	}
}

func TestSignupRateLimited(t *testing.T) {
	st, _ := sessionTestSetup(t)
	// Signup disabled here; enable it to reach the limiter through the
	// normal path (the setting object is shared with the store).
	set, err := st.Settings.Get()
	if err != nil {
		t.Fatal(err)
	}
	set.Signup = true
	if err := st.Settings.Save(set); err != nil {
		t.Fatal(err)
	}

	h := handle(signupHandler(), "", st, &settings.Server{})
	try := func(i int) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"username":"spray%d","password":"SprayPw12345!"}`, i)
		req, _ := http.NewRequest(http.MethodPost, "/signup", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	for i := 0; i < maxSignupAttempts; i++ {
		rec := try(i)
		// Registrations succeed here; what matters is that none is
		// rate-limited within budget.
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d = %d body=%q, want 200", i+1, rec.Code, rec.Body.String())
		}
	}
	if rec := try(999); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-budget signup = %d, want 429", rec.Code)
	}
}

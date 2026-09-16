package fbhttp

// Share passwords had no guessing budget: anyone holding a link hash could
// try passwords without limit. Guesses are now budgeted per peer and link.
import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/share"
	"github.com/filebrowser/filebrowser/v2/users"
)

func TestSharePasswordRateLimited(t *testing.T) {
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
	const hash = "pwlinktesthash01"
	if err := st.Share.Save(&share.Link{
		Path: "/secret.txt", Hash: hash, Expire: 0, UserID: 1,
		PasswordHash: string(pwHash), Token: "link-bypass-token",
	}); err != nil {
		t.Fatal(err)
	}

	h := handle(publicDlHandler, "", st, &settings.Server{})
	try := func(password string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodGet, hash, http.NoBody)
		req.Header.Set("X-SHARE-PASSWORD", password)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// The correct password works and consumes one unit of budget.
	if rec := try("LinkSecret123!"); rec.Code != http.StatusOK {
		t.Fatalf("correct password = %d body=%q, want 200", rec.Code, rec.Body.String())
	}

	// Wrong passwords are rejected until the budget is spent...
	for i := 0; i < maxSharePasswordAttempts-1; i++ {
		if rec := try("wrong-password"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("guess %d = %d, want 401", i+1, rec.Code)
		}
	}
	// ...then guessing stops with 429.
	rec := try("wrong-password")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-budget guess = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Errorf("429 without Retry-After hint")
	}
	if !strings.Contains(rec.Body.String(), "429") {
		t.Errorf("unexpected 429 body: %q", rec.Body.String())
	}
}

// URL tokens spare the password, so they must be set and fresh: stale ones
// (logs, history, pre-upgrade links) fall back to the password, and a
// correct password slides the lifetime again.
func TestShareTokenLifetime(t *testing.T) {
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
	mkLink := func(hash, token string, createdAt int64) {
		t.Helper()
		if err := st.Share.Save(&share.Link{
			Path: "/secret.txt", Hash: hash, Expire: 0, UserID: 1,
			PasswordHash: string(pwHash), Token: token, TokenCreatedAt: createdAt,
		}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().Unix()
	mkLink("freshhash1234567", "fresh-token", now)
	mkLink("stalehash1234567", "stale-token", now-int64((maxShareTokenAge+time.Hour).Seconds()))
	mkLink("legacyhash123456", "legacy-token", 0)
	mkLink("notokenhash12345", "", now)

	h := handle(publicDlHandler, "", st, &settings.Server{})
	get := func(target, password string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodGet, target, http.NoBody)
		if password != "" {
			req.Header.Set("X-SHARE-PASSWORD", password)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Fresh token works without the password.
	if rec := get("freshhash1234567?token=fresh-token", ""); rec.Code != http.StatusOK {
		t.Fatalf("fresh token = %d, want 200", rec.Code)
	}
	// Wrong token never works.
	if rec := get("freshhash1234567?token=nope", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token = %d, want 401", rec.Code)
	}
	// Stale token stops working...
	if rec := get("stalehash1234567?token=stale-token", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("VULNERABLE: stale token = %d, want 401", rec.Code)
	}
	// ...until the password slides it again.
	if rec := get("stalehash1234567", "LinkSecret123!"); rec.Code != http.StatusOK {
		t.Fatalf("password after stale token = %d, want 200", rec.Code)
	}
	slid, err := st.Share.GetByHash("stalehash1234567")
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(time.Unix(slid.TokenCreatedAt, 0)) > time.Minute {
		t.Fatalf("token lifetime not slid: %v", slid.TokenCreatedAt)
	}
	if rec := get("stalehash1234567?token=stale-token", ""); rec.Code != http.StatusOK {
		t.Fatalf("slid token = %d, want 200", rec.Code)
	}

	// Pre-upgrade links (zero timestamp) need one password entry, then work.
	if rec := get("legacyhash123456?token=legacy-token", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("legacy token = %d, want 401", rec.Code)
	}
	if rec := get("legacyhash123456", "LinkSecret123!"); rec.Code != http.StatusOK {
		t.Fatalf("legacy password = %d, want 200", rec.Code)
	}
	if rec := get("legacyhash123456?token=legacy-token", ""); rec.Code != http.StatusOK {
		t.Fatalf("slid legacy token = %d, want 200", rec.Code)
	}

	// A password link without a token must not bypass via empty token.
	if rec := get("notokenhash12345?token=", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("VULNERABLE: empty token bypass = %d, want 401", rec.Code)
	}
	if rec := get("notokenhash12345", "LinkSecret123!"); rec.Code != http.StatusOK {
		t.Fatalf("password on tokenless link = %d, want 200", rec.Code)
	}
}

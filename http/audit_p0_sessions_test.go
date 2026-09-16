package fbhttp

// Audit characterization for P0-C1 (ARCHITEKTUR.md §3, #5216,
// GO-2025-3812/CVE-2025-53826): LastUpdate is a renew-hint, not revocation.
//
// Current behavior pinned here: a token issued BEFORE a user update
// (e.g. password change / permission revocation via Users.Update, which bumps
// LastUpdate past the token's iat) is STILL ACCEPTED with 200 and only gets
// an `X-Renew-Token: true` hint header.
//
// filebrowser-ng target: this same token MUST be rejected (401) after the
// server-side session rewrite. When that lands, flip this test to assert 401.
import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

func TestAuditLastUpdateIsHintOnly(t *testing.T) {
	key := []byte("test-signing-key")
	perm := users.Permissions{Download: true}
	st := scopedUserStorage(t, t.TempDir(), perm, key)
	if err := st.Settings.Save(&settings.Settings{Key: key}); err != nil {
		t.Fatalf("failed to save settings: %v", err)
	}

	token := signToken(t, perm, key) // iat = now-1m

	protected := withUser(func(w http.ResponseWriter, _ *http.Request, _ *data) (int, error) {
		_, err := w.Write([]byte("protected"))
		return 0, err
	})
	call := func() *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set("X-Auth", token)
		rec := httptest.NewRecorder()
		handle(protected, "", st, &settings.Server{}).ServeHTTP(rec, req)
		return rec
	}

	if rec := call(); rec.Code != http.StatusOK {
		t.Fatalf("setup: valid token = %d, want 200", rec.Code)
	}

	// Simulate password change / permission revocation AFTER the token was issued.
	u, err := st.Users.Get("", false, uint(1))
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	if err := st.Users.Update(u); err != nil {
		t.Fatalf("failed to update user: %v", err)
	}

	rec := call()
	if rec.Code != http.StatusOK {
		t.Fatalf("AUDIT CHANGED: post-update token = %d (want 200 on v2 baseline; 401 is the ng target)", rec.Code)
	}
	if got := rec.Header().Get("X-Renew-Token"); got != "true" {
		t.Fatalf("AUDIT CHANGED: X-Renew-Token = %q, want %q (hint-only signal)", got, "true")
	}
}

package fbhttp

// Regression for P0-C1 (ARCHITEKTUR.md §3, #5216,
// GO-2025-3812/CVE-2025-53826): tokens are bearer pointers to server-side
// sessions. Revoking the session (logout, password/security change, user
// deletion) turns a cryptographically valid token into 401 at once —
// LastUpdate is only a renew hint, never the enforcement mechanism.
import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

func TestRevokedSessionTokenRejected(t *testing.T) {
	key := []byte("test-signing-key")
	perm := users.Permissions{Download: true}
	st := scopedUserStorage(t, t.TempDir(), perm, key)
	if err := st.Settings.Save(&settings.Settings{Key: key}); err != nil {
		t.Fatalf("failed to save settings: %v", err)
	}

	sess, err := st.Sessions.Create(1, time.Hour)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	claims := &authToken{
		User: userInfo{ID: 1, Username: "u", Perm: perm},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        sess.JTI,
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

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
		t.Fatalf("setup: valid session token = %d, want 200", rec.Code)
	}

	// Revoke without touching the user record at all: no password change,
	// no LastUpdate bump. The token must die anyway.
	if err := st.Sessions.Revoke(sess.JTI); err != nil {
		t.Fatalf("failed to revoke session: %v", err)
	}
	if rec := call(); rec.Code != http.StatusUnauthorized {
		t.Fatalf("VULNERABLE: revoked-session token = %d; want 401", rec.Code)
	}
}

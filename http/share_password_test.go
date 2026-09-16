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

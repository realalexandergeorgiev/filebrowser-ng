package fbhttp

// Regression: walking a scope with a symlink-confined entry used to invoke
// the result callback with nil FileInfo, panicking the search handler on
// f.IsDir. Unreadable entries are skipped instead.
import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

func TestSearchSkipsConfinedEntries(t *testing.T) {
	root := t.TempDir()
	userScope := filepath.Join(root, "user")
	outside := filepath.Join(root, "outside")
	for _, d := range []string{userScope, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(userScope, "mine.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Planted out-of-band, mirroring the symlink scope-escape advisories.
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(userScope, "escape")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("OUT-OF-SCOPE"), 0o600); err != nil {
		t.Fatal(err)
	}

	key := []byte("test-signing-key")
	perm := users.Permissions{}
	st := scopedUserStorage(t, userScope, perm, key)
	signed := signToken(t, st, perm, key)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VULNERABLE: search panicked on confined entry: %v", r)
		}
	}()
	req, _ := http.NewRequest(http.MethodGet, "/?query=escape", http.NoBody)
	req.Header.Set("X-Auth", signed)
	rec := httptest.NewRecorder()
	handle(searchHandler, "/api/search", st, &settings.Server{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("search = %d body=%q, want 200", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "OUT-OF-SCOPE") {
		t.Fatalf("VULNERABLE: search leaked out-of-scope content: %q", rec.Body.String())
	}
}

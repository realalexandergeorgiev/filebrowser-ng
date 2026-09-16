package fbhttp

// Regression: TUS 400 responses used to embed file.RealPath() (the absolute
// server path) in the error, and handle() appends 400 errors to the response
// body (data.go). Responses must not leak server filesystem layout.
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

func TestTusErrorsDoNotLeakServerPaths(t *testing.T) {
	root := t.TempDir()
	userScope := filepath.Join(root, "user")
	if err := os.MkdirAll(filepath.Join(userScope, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}

	key := []byte("test-signing-key")
	perm := users.Permissions{Create: true, Modify: true}
	st := scopedUserStorage(t, userScope, perm, key)
	signed := signToken(t, st, perm, key)

	cache := newMemoryUploadCache()
	t.Cleanup(cache.Close)
	post := handle(tusPostHandler(cache), "", st, &settings.Server{})
	patch := handle(tusPatchHandler(cache), "", st, &settings.Server{})

	serve := func(h http.Handler, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
		var rdr *strings.Reader
		if body == "" {
			rdr = strings.NewReader("")
		} else {
			rdr = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, target, rdr)
		req.Header.Set("X-Auth", signed)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	assertNoLeak := func(name string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d body=%q", name, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), userScope) || strings.Contains(rec.Body.String(), root) {
			t.Fatalf("VULNERABLE: %s leaks server path: %q", name, rec.Body.String())
		}
	}

	// POST to an existing directory.
	rec := serve(post, http.MethodPost, "/dir", "", map[string]string{"Upload-Length": "10"})
	assertNoLeak("POST dir", rec)

	// PATCH to a path that was a file at upload creation but is a directory now.
	recPost := serve(post, http.MethodPost, "/swap", "", map[string]string{"Upload-Length": "5"})
	if recPost.Code != http.StatusCreated {
		t.Fatalf("setup POST expected 201, got %d body=%q", recPost.Code, recPost.Body.String())
	}
	if err := os.Remove(filepath.Join(userScope, "swap")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(userScope, "swap"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec = serve(patch, http.MethodPatch, "/swap", "hello", map[string]string{
		"Content-Type":  "application/offset+octet-stream",
		"Upload-Offset": "0",
	})
	assertNoLeak("PATCH dir", rec)
}

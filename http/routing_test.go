package fbhttp

// The stdlib router table must expose every API route with the same methods
// as before: a typo'd pattern would silently fall through to the index page.
import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	boltapi "go.etcd.io/bbolt"

	fbAuth "github.com/realalexandergeorgiev/filebrowser-ng/auth"
	"github.com/realalexandergeorgiev/filebrowser-ng/diskcache"
	"github.com/realalexandergeorgiev/filebrowser-ng/settings"
	"github.com/realalexandergeorgiev/filebrowser-ng/storage/bolt"
	"github.com/realalexandergeorgiev/filebrowser-ng/users"
)

func routingTestHandler(t *testing.T) http.Handler {
	t.Helper()
	db, err := boltapi.Open(filepath.Join(t.TempDir(), "db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := bolt.NewStorage(db)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("test-signing-key")
	if err := st.Settings.Save(&settings.Settings{Key: key, AuthMethod: fbAuth.MethodJSONAuth}); err != nil {
		t.Fatal(err)
	}
	if err := st.Auth.Save(&fbAuth.JSONAuth{}); err != nil {
		t.Fatal(err)
	}
	perm := users.Permissions{Download: true}
	if err := st.Users.Save(&users.User{Username: "u", Password: "pw", Perm: perm}); err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(nil, diskcache.NewNoOp(), newMemoryUploadCache(), st, &settings.Server{},
		fstest.MapFS{"public/index.html": {Data: []byte("index-page")}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestRouterTable(t *testing.T) {
	h := routingTestHandler(t)
	serve := func(method, target, token string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(method, target, http.NoBody)
		if token != "" {
			req.Header.Set("X-Auth", token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Unknown paths fall through to the index page.
	if rec := serve(http.MethodGet, "/no-such-page", ""); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "index-page") {
		t.Errorf("fallback = %d %q, want index page", rec.Code, rec.Body.String())
	}

	// Auth routes exist (bad credentials -> 403, not the index page).
	req, _ := http.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST /api/login = %d, want 403 (route must exist)", rec.Code)
	}

	// Protected routes reject anonymous callers instead of serving index.
	for _, target := range []string{
		"/api/resources/", "/api/users", "/api/users/1", "/api/settings",
		"/api/shares", "/api/share/x", "/api/raw/x", "/api/search/x",
		"/api/tus/x", "/api/usage/", "/api/preview/thumb/x",
	} {
		if rec := serve(http.MethodGet, target, ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s = %d, want 401", target, rec.Code)
		}
	}

	// Bare prefixes redirect with a trailing slash, as before.
	if rec := serve(http.MethodGet, "/api/resources", ""); rec.Code != http.StatusMovedPermanently {
		t.Errorf("GET /api/resources = %d, want 301", rec.Code)
	}

	// Method constraints hold: logout is DELETE-only.
	if rec := serve(http.MethodGet, "/api/logout", "bogus"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/logout = %d, want 405", rec.Code)
	}
	if rec := serve(http.MethodPost, "/api/users/1", "bogus"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/users/1 = %d, want 405", rec.Code)
	}
}

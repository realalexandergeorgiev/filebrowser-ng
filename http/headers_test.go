package fbhttp

// Regression: every response must carry the hardened baseline headers, and
// negotiated gzip assets must declare Vary so shared caches cannot poison
// non-gzip clients.
import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	boltapi "go.etcd.io/bbolt"

	fbAuth "github.com/realalexandergeorgiev/filebrowser-ng/auth"
	"github.com/realalexandergeorgiev/filebrowser-ng/diskcache"
	"github.com/realalexandergeorgiev/filebrowser-ng/settings"
	"github.com/realalexandergeorgiev/filebrowser-ng/storage/bolt"
)

func TestSecurityHeadersOnHealth(t *testing.T) {
	db, err := boltapi.Open(filepath.Join(t.TempDir(), "db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := bolt.NewStorage(db)
	if err != nil {
		t.Fatal(err)
	}

	h, err := NewHandler(nil, diskcache.NewNoOp(), newMemoryUploadCache(), st, &settings.Server{}, fstest.MapFS{})
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/health", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health = %d, want 200", rec.Code)
	}

	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "object-src 'none'", "base-uri 'self'", "frame-ancestors 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q: %q", want, csp)
		}
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
}

func TestGzipAssetsVaryByEncoding(t *testing.T) {
	db, err := boltapi.Open(filepath.Join(t.TempDir(), "db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := bolt.NewStorage(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Settings.Save(&settings.Settings{Key: []byte("test-signing-key")}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte("console.log('hi')")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	_, static := getStaticHandlers(st, &settings.Server{}, fstest.MapFS{
		"app.js.gz": {Data: buf.Bytes()},
	})

	req, _ := http.NewRequest(http.MethodGet, "/static/app.js", http.NoBody)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	static.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("static gzip = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Errorf("Vary = %q, want Accept-Encoding", got)
	}
}

// Regression: the app shell must keep loading under the strict CSP. The one
// inline bootstrap script (window.FileBrowser) is allowed via a per-request
// nonce that must match between the CSP header and the script tag, and the
// external stylesheet must be allowed by style-src ('self' + inline).
func TestIndexCSPNonceMatchesInlineScript(t *testing.T) {
	db, err := boltapi.Open(filepath.Join(t.TempDir(), "db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := bolt.NewStorage(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Settings.Save(&settings.Settings{Key: []byte("test-signing-key"), AuthMethod: fbAuth.MethodJSONAuth}); err != nil {
		t.Fatal(err)
	}
	if err := st.Auth.Save(&fbAuth.JSONAuth{}); err != nil {
		t.Fatal(err)
	}

	const indexHTML = `<html><head>` +
		`<script nonce="[{[ .Nonce ]}]">window.FileBrowser=[{[ .Json ]}];</script>` +
		`</head><body><div id="app"></div></body></html>`

	h, err := NewHandler(nil, diskcache.NewNoOp(), newMemoryUploadCache(), st, &settings.Server{},
		fstest.MapFS{"public/index.html": {Data: []byte(indexHTML)}})
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("index = %d body=%q, want 200", rec.Code, rec.Body.String())
	}

	csp := rec.Header().Get("Content-Security-Policy")
	m := regexp.MustCompile(`'nonce-([0-9a-f]{32})'`).FindStringSubmatch(csp)
	if m == nil {
		t.Fatalf("CSP has no nonce: %q", csp)
	}
	nonce := m[1]
	if !strings.Contains(csp, "script-src 'self' 'nonce-"+nonce+"'") {
		t.Errorf("script-src does not scope to the nonce: %q", csp)
	}
	if !strings.Contains(csp, "style-src 'self' 'unsafe-inline'") {
		t.Errorf("style-src must allow self and inline: %q", csp)
	}
	if !strings.Contains(rec.Body.String(), `nonce="`+nonce+`"`) {
		t.Errorf("inline bootstrap script does not carry the CSP nonce %q", nonce)
	}
}

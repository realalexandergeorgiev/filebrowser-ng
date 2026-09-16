package fbhttp

// Regression: branding overrides joined the request path without containment
// (static.go), so /static/img/../../<file> could serve arbitrary host files
// when the branding directory was configured. Requests escaping the branding
// directory must be rejected; legitimate overrides must keep working.
import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	boltapi "go.etcd.io/bbolt"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/storage/bolt"
)

func TestBrandingTraversalRejected(t *testing.T) {
	root := t.TempDir()
	brandDir := filepath.Join(root, "brand", "files")
	if err := os.MkdirAll(filepath.Join(brandDir, "img"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(brandDir, "img", "ok.png"), []byte("branding-ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	secretInBrand := filepath.Join(root, "brand", "secret.txt")
	if err := os.WriteFile(secretInBrand, []byte("top-secret-brand"), 0o600); err != nil {
		t.Fatal(err)
	}
	secretAbove := filepath.Join(root, "secret.txt")
	if err := os.WriteFile(secretAbove, []byte("top-secret-root"), 0o600); err != nil {
		t.Fatal(err)
	}

	db, err := boltapi.Open(filepath.Join(t.TempDir(), "db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := bolt.NewStorage(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Settings.Save(&settings.Settings{
		Key:      []byte("test-signing-key"),
		Branding: settings.Branding{Files: brandDir},
	}); err != nil {
		t.Fatal(err)
	}

	_, static := getStaticHandlers(st, &settings.Server{}, fstest.MapFS{})
	get := func(target string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodGet, target, http.NoBody)
		rec := httptest.NewRecorder()
		static.ServeHTTP(rec, req)
		return rec
	}

	// Legitimate override still served.
	if rec := get("/static/img/ok.png"); rec.Code != http.StatusOK || rec.Body.String() != "branding-ok" {
		t.Fatalf("override = %d %q, want 200 %q", rec.Code, rec.Body.String(), "branding-ok")
	}

	// Traversal to host files outside the branding directory. With plain
	// filepath.Join (pre-fix), these resolve to real files and get served:
	// Join(brandDir,"img/../../secret.txt") = <root>/brand/secret.txt,
	// Join(brandDir,"img/../../../secret.txt") = <root>/secret.txt.
	for _, target := range []string{
		"/static/img/../../secret.txt",
		"/static/img/../../../secret.txt",
	} {
		rec := get(target)
		body := rec.Body.String()
		if body == "top-secret-brand" || body == "top-secret-root" {
			t.Fatalf("VULNERABLE: %s served host file", target)
		}
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s = %d %q, want 404", target, rec.Code, body)
		}
	}
}

func TestBrandingFileContainment(t *testing.T) {
	dir := filepath.Join("srv", "brand")
	for _, tc := range []struct {
		req string
		ok  bool
	}{
		{"img/logo.png", true},
		{"custom.css", true},
		{"img/../../secret.txt", false},
		{"../secret.txt", false},
		{"", false},
	} {
		_, ok := brandingFile(dir, tc.req)
		if ok != tc.ok {
			t.Errorf("brandingFile(%q) ok=%v, want %v", tc.req, ok, tc.ok)
		}
	}
	if _, ok := brandingFile("", "img/a.png"); ok {
		t.Errorf("empty branding dir must reject")
	}
}

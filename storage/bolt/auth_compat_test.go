package bolt

import (
	"path/filepath"
	"testing"

	"github.com/asdine/storm/v3"

	"github.com/filebrowser/filebrowser/v2/auth"
)

// The auth backend shares the "config" bucket with settings: rows written
// by storm (pre-migration) must stay readable by the raw backend and vice
// versa, so upgrades and rollbacks never strand the auth method.
func TestAuthBackendStormCompat(t *testing.T) {
	db, err := storm.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.Set("config", "auther", &auth.ProxyAuth{Header: "X-User"}); err != nil {
		t.Fatalf("storm save: %v", err)
	}

	raw := authBackend{db: db.Bolt}
	got, err := raw.Get(auth.MethodProxyAuth)
	if err != nil {
		t.Fatalf("raw Get of storm row: %v", err)
	}
	proxy, ok := got.(*auth.ProxyAuth)
	if !ok || proxy.Header != "X-User" {
		t.Fatalf("storm row misread: %#v", got)
	}

	if err := raw.Save(&auth.JSONAuth{}); err != nil {
		t.Fatalf("raw save: %v", err)
	}
	back := &auth.JSONAuth{}
	if err := db.Get("config", "auther", back); err != nil {
		t.Fatalf("storm read of raw row: %v", err)
	}

	if _, err := raw.Get("nope"); err == nil {
		t.Fatalf("unknown method accepted")
	}
}

package bolt

import (
	"path/filepath"
	"testing"

	"github.com/asdine/storm/v3"

	"github.com/filebrowser/filebrowser/v2/sessions"
)

// Rows written by storm (pre-migration format: bucket "Session", JSON
// values keyed by JTI) must stay readable by the raw bbolt backend, and
// vice versa, so upgrades and rollbacks never strand login sessions.
func TestSessionBackendStormCompat(t *testing.T) {
	db, err := storm.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	legacy := &sessions.Session{JTI: "legacy-jti", UserID: 7, CreatedAt: 111, ExpiresAt: 9999999999}
	if err := db.Save(legacy); err != nil {
		t.Fatalf("storm save: %v", err)
	}

	raw := sessionBackend{db: db.Bolt}
	got, err := raw.Get("legacy-jti")
	if err != nil {
		t.Fatalf("raw Get of storm row: %v", err)
	}
	if got.UserID != 7 || got.CreatedAt != 111 || got.ExpiresAt != 9999999999 {
		t.Fatalf("storm row misread: %+v", got)
	}

	fresh := &sessions.Session{JTI: "raw-jti", UserID: 7, CreatedAt: 222, ExpiresAt: 9999999999}
	if err := raw.Save(fresh); err != nil {
		t.Fatalf("raw save: %v", err)
	}
	var back sessions.Session
	if err := db.One("JTI", "raw-jti", &back); err != nil {
		t.Fatalf("storm read of raw row: %v", err)
	}
	if back.UserID != 7 || back.CreatedAt != 222 {
		t.Fatalf("raw row misread by storm: %+v", back)
	}

	list, err := raw.FindByUserID(7)
	if err != nil {
		t.Fatalf("FindByUserID: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("FindByUserID = %d rows, want 2", len(list))
	}

	if err := raw.Delete("legacy-jti"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := raw.Get("legacy-jti"); err == nil {
		t.Fatalf("deleted session still readable")
	}
}

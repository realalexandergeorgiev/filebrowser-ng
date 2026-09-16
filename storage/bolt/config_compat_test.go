package bolt

import (
	"path/filepath"
	"testing"

	"github.com/asdine/storm/v3"

	"github.com/filebrowser/filebrowser/v2/settings"
)

// Settings and server rows live in the shared "config" bucket: storm-written
// values must stay readable by the raw backend and vice versa.
func TestSettingsBackendStormCompat(t *testing.T) {
	db, err := storm.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.Set("config", "settings", &settings.Settings{Signup: true}); err != nil {
		t.Fatalf("storm save: %v", err)
	}
	if err := db.Set("config", "server", &settings.Server{Port: "8080"}); err != nil {
		t.Fatalf("storm save: %v", err)
	}

	raw := settingsBackend{db: db.Bolt}
	set, err := raw.Get()
	if err != nil {
		t.Fatalf("raw Get of storm row: %v", err)
	}
	if !set.Signup {
		t.Fatalf("storm settings misread: %+v", set)
	}
	srv, err := raw.GetServer()
	if err != nil {
		t.Fatalf("raw GetServer of storm row: %v", err)
	}
	if srv.Port != "8080" {
		t.Fatalf("storm server misread: %+v", srv)
	}

	set.Signup = false
	if err := raw.Save(set); err != nil {
		t.Fatalf("raw save: %v", err)
	}
	back := &settings.Settings{}
	if err := db.Get("config", "settings", back); err != nil {
		t.Fatalf("storm read of raw row: %v", err)
	}
	if back.Signup {
		t.Fatalf("raw row misread by storm: %+v", back)
	}
}

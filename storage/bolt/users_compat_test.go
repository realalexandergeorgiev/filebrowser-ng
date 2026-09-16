package bolt

import (
	"path/filepath"
	"testing"

	"github.com/asdine/storm/v3"

	"github.com/filebrowser/filebrowser/v2/users"
)

// User rows live in the "User" bucket keyed by big-endian ID: storm-written
// users must stay readable by the raw backend and vice versa, and IDs must
// continue past pre-migration rows without colliding.
func TestUsersBackendStormCompat(t *testing.T) {
	db, err := storm.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.Save(&users.User{Username: "alice", Scope: "/"}); err != nil {
		t.Fatalf("storm save: %v", err)
	}

	raw := usersBackend{db: db.Bolt}
	got, err := raw.GetBy("alice")
	if err != nil {
		t.Fatalf("raw GetBy of storm row: %v", err)
	}
	if got.ID != 1 || got.Scope != "/" {
		t.Fatalf("storm row misread: %+v", got)
	}
	if _, err := raw.GetBy(uint(1)); err != nil {
		t.Fatalf("raw GetBy ID: %v", err)
	}

	// IDs continue past storm rows instead of restarting at 1.
	fresh := &users.User{Username: "bob", Scope: "/b"}
	if err := raw.Save(fresh); err != nil {
		t.Fatalf("raw save: %v", err)
	}
	if fresh.ID != 2 {
		t.Fatalf("raw ID = %d, want 2 (past storm row)", fresh.ID)
	}
	var back users.User
	if err := db.One("Username", "bob", &back); err != nil {
		t.Fatalf("storm read of raw row: %v", err)
	}
	if back.ID != 2 {
		t.Fatalf("raw row misread by storm: %+v", back)
	}

	// The unique username rule survives the migration both ways.
	if err := raw.Save(&users.User{Username: "alice"}); err == nil {
		t.Fatalf("duplicate username accepted by raw backend")
	}
}

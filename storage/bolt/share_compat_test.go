package bolt

import (
	"path/filepath"
	"testing"

	"github.com/asdine/storm/v3"

	"github.com/filebrowser/filebrowser/v2/share"
)

// Share rows live in the "Link" bucket keyed by hash: storm-written links
// must stay readable by the raw backend and vice versa.
func TestShareBackendStormCompat(t *testing.T) {
	db, err := storm.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.Save(&share.Link{Hash: "h1", Path: "/a.txt", UserID: 3}); err != nil {
		t.Fatalf("storm save: %v", err)
	}

	raw := shareBackend{db: db.Bolt}
	got, err := raw.GetByHash("h1")
	if err != nil {
		t.Fatalf("raw GetByHash of storm row: %v", err)
	}
	if got.Path != "/a.txt" || got.UserID != 3 {
		t.Fatalf("storm row misread: %+v", got)
	}
	if found, err := raw.FindByUserID(3); err != nil || len(found) != 1 {
		t.Fatalf("FindByUserID = %d, %v", len(found), err)
	}
	if _, err := raw.Gets("/a.txt", 3); err != nil {
		t.Fatalf("Gets: %v", err)
	}

	fresh := &share.Link{Hash: "h2", Path: "/b.txt", UserID: 3}
	if err := raw.Save(fresh); err != nil {
		t.Fatalf("raw save: %v", err)
	}
	var back share.Link
	if err := db.One("Hash", "h2", &back); err != nil {
		t.Fatalf("storm read of raw row: %v", err)
	}
	if back.Path != "/b.txt" {
		t.Fatalf("raw row misread by storm: %+v", back)
	}

	if err := raw.DeleteWithPathPrefix("/a.txt", 3); err != nil {
		t.Fatalf("DeleteWithPathPrefix: %v", err)
	}
	if _, err := raw.GetByHash("h1"); err == nil {
		t.Fatalf("prefixed link survived delete")
	}
}

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/asdine/storm/v3"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/storage/bolt"
)

func TestMarshalCreatesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "export.json")
	if err := marshal(path, map[string]string{"a": "b"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("export perm = %o, want 600", perm)
	}

	// Overwriting a world-readable file must tighten it too.
	loose := filepath.Join(t.TempDir(), "loose.json")
	if err := os.WriteFile(loose, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := marshal(loose, map[string]string{"a": "b"}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(loose); err != nil {
		t.Fatal(err)
	} else if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("overwritten export perm = %o, want 600", perm)
	}
}

func TestWithoutKeyRedacts(t *testing.T) {
	s := &settings.Settings{Key: []byte("super-secret"), Signup: true}
	out := withoutKey(s)
	if len(out.Key) != 0 {
		t.Fatalf("export copy still carries key material")
	}
	if !out.Signup {
		t.Fatalf("redaction dropped other fields")
	}
	if len(s.Key) == 0 {
		t.Fatalf("redaction mutated the live settings")
	}
}

func TestRotateSettingsKey(t *testing.T) {
	db, err := storm.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := bolt.NewStorage(db)
	if err != nil {
		t.Fatal(err)
	}
	old := []byte("old-key-material-1234567890abcdef")
	if err := st.Settings.Save(&settings.Settings{Key: old}); err != nil {
		t.Fatal(err)
	}

	if err := rotateSettingsKey(st.Settings); err != nil {
		t.Fatal(err)
	}
	set, err := st.Settings.Get()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Key) == 0 || bytes.Equal(set.Key, old) {
		t.Fatalf("key was not rotated")
	}
}

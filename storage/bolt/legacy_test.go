package bolt

// Legacy readability: testdata/legacy-v2.db was written with storm, exactly
// as v2.63 wrote it (generated once, see git history). Every backend must
// read those rows, and new writes must continue past them, so upgrades keep
// working and rollbacks stay possible.
import (
	"os"
	"path/filepath"
	"testing"

	boltapi "go.etcd.io/bbolt"

	"github.com/filebrowser/filebrowser/v2/auth"
	"github.com/filebrowser/filebrowser/v2/storage"
	"github.com/filebrowser/filebrowser/v2/users"
)

func openLegacy(t *testing.T) (*storage.Storage, *boltapi.DB) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "legacy-v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy.db")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := boltapi.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := NewStorage(db)
	if err != nil {
		t.Fatal(err)
	}
	return st, db
}

func TestLegacyUsers(t *testing.T) {
	st, db := openLegacy(t)
	back := usersBackend{db: db}

	alice, err := back.GetBy("alice")
	if err != nil {
		t.Fatalf("GetBy alice: %v", err)
	}
	if alice.ID != 1 || !alice.Perm.Admin {
		t.Fatalf("legacy alice misread: %+v", alice)
	}
	if _, err := back.GetBy(uint(1)); err != nil {
		t.Fatalf("GetBy ID: %v", err)
	}
	bob, err := back.GetByScope("/B")
	if err != nil {
		t.Fatalf("GetByScope case-insensitive: %v", err)
	}
	if bob.Username != "bob" {
		t.Fatalf("wrong user for scope: %+v", bob)
	}

	fresh := &users.User{Username: "carol", Password: "pw"}
	if err := st.Users.Save(fresh); err != nil {
		t.Fatalf("save: %v", err)
	}
	if fresh.ID != 3 {
		t.Fatalf("new ID = %d, want 3 (past legacy rows)", fresh.ID)
	}
}

func TestLegacyShareSettingsAuthSessions(t *testing.T) {
	st, _ := openLegacy(t)

	link, err := st.Share.GetByHash("legacyhash")
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if link.Path != "/doc.txt" || link.UserID != 1 {
		t.Fatalf("legacy link misread: %+v", link)
	}

	set, err := st.Settings.Get()
	if err != nil {
		t.Fatalf("settings Get: %v", err)
	}
	if !set.Signup {
		t.Fatalf("legacy settings misread: %+v", set)
	}
	srv, err := st.Settings.GetServer()
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if srv.Port != "8080" {
		t.Fatalf("legacy server misread: %+v", srv)
	}

	auther, err := st.Auth.Get(auth.MethodProxyAuth)
	if err != nil {
		t.Fatalf("auth Get: %v", err)
	}
	if proxy, ok := auther.(*auth.ProxyAuth); !ok || proxy.Header != "X-User" {
		t.Fatalf("legacy auther misread: %#v", auther)
	}

	sess, err := st.Sessions.Get("legacy-jti")
	if err != nil {
		t.Fatalf("session Get: %v", err)
	}
	if sess.UserID != 1 {
		t.Fatalf("legacy session misread: %+v", sess)
	}
}

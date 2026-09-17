package files

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Metadata ops (Rename, Remove, Mkdir, Stat, ...) cannot pin their target
// with a descriptor like content opens do, so their only protection is the
// guard directly above the syscall. These tests plant an escaping symlink
// and assert every op refuses it — plus positive controls proving
// legitimate paths keep working.
func guardScope(t *testing.T) (string, *ScopedFs) {
	t.Helper()
	base, fs := verifyScope(t)
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "srv", "escape")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if err := os.WriteFile(filepath.Join(base, "srv", "real.txt"), []byte("real"), 0o600); err != nil {
		t.Fatal(err)
	}
	return base, fs
}

func TestMetadataOpsRefusePlantedEscape(t *testing.T) {
	_, fs := guardScope(t)

	if err := fs.Rename("/escape", "/renamed"); !os.IsPermission(err) {
		t.Errorf("rename escape = %v, want permission", err)
	}
	if err := fs.Rename("/real.txt", "/escape/clobbered.txt"); !os.IsPermission(err) {
		t.Errorf("rename into escape = %v, want permission", err)
	}
	if err := fs.Remove("/escape/secret.txt"); !os.IsPermission(err) {
		t.Errorf("remove through escape = %v, want permission", err)
	}
	if err := fs.RemoveAll("/escape"); !os.IsPermission(err) {
		t.Errorf("removeall escape = %v, want permission", err)
	}
	if err := fs.Mkdir("/escape/sub", 0o755); !os.IsPermission(err) {
		t.Errorf("mkdir through escape = %v, want permission", err)
	}
	if err := fs.MkdirAll("/escape/a/b", 0o755); !os.IsPermission(err) {
		t.Errorf("mkdirall through escape = %v, want permission", err)
	}
	if _, err := fs.Stat("/escape/secret.txt"); !os.IsPermission(err) {
		t.Errorf("stat through escape = %v, want permission", err)
	}
	if err := fs.Chmod("/escape/secret.txt", 0o600); !os.IsPermission(err) {
		t.Errorf("chmod through escape = %v, want permission", err)
	}
	if err := fs.Chtimes("/escape/secret.txt", time.Now(), time.Now()); !os.IsPermission(err) {
		t.Errorf("chtimes through escape = %v, want permission", err)
	}
	if _, _, err := fs.LstatIfPossible("/escape/secret.txt"); !os.IsPermission(err) {
		t.Errorf("lstat through escape = %v, want permission", err)
	}
}

func TestMetadataOpsAllowInScope(t *testing.T) {
	base, fs := guardScope(t)

	if err := fs.MkdirAll("/sub/dir", 0o755); err != nil {
		t.Fatalf("mkdirall in scope = %v", err)
	}
	if err := fs.Rename("/real.txt", "/sub/moved.txt"); err != nil {
		t.Fatalf("rename in scope = %v", err)
	}
	if _, err := fs.Stat("/sub/moved.txt"); err != nil {
		t.Fatalf("stat in scope = %v", err)
	}
	if err := fs.Chmod("/sub/moved.txt", 0o600); err != nil {
		t.Fatalf("chmod in scope = %v", err)
	}
	if err := fs.Remove("/sub/moved.txt"); err != nil {
		t.Fatalf("remove in scope = %v", err)
	}
	if err := fs.RemoveAll("/sub"); err != nil {
		t.Fatalf("removeall in scope = %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "outside", "secret.txt")); err != nil {
		t.Fatalf("outside file disturbed: %v", err)
	}
}

// TestGuardSeesSwap proves the guard reads current on-disk state on every
// call (nothing is cached): a link that was in-scope, swapped to escape,
// is refused by the very next guard — which is why the check must sit
// directly above each syscall.
func TestGuardSeesSwap(t *testing.T) {
	base, fs := guardScope(t)
	link := filepath.Join(base, "srv", "swap")
	inner := filepath.Join(base, "srv", "real.txt")
	outside := filepath.Join(base, "outside", "secret.txt")

	if err := os.Symlink(inner, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if err := fs.guard("/swap"); err != nil {
		t.Fatalf("guard before swap = %v, want nil", err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := fs.guard("/swap"); !os.IsPermission(err) {
		t.Fatalf("guard after swap = %v, want permission", err)
	}
	// And back again: legitimacy is restored, not latched.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(inner, link); err != nil {
		t.Fatal(err)
	}
	if err := fs.guard("/swap"); err != nil {
		t.Fatalf("guard after swap back = %v, want nil", err)
	}
}

package files

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/spf13/afero"
)

func verifyScope(t *testing.T) (string, *ScopedFs) {
	t.Helper()
	base := t.TempDir()
	scope := filepath.Join(base, "srv")
	if err := os.MkdirAll(scope, 0o755); err != nil {
		t.Fatal(err)
	}
	return base, NewScopedFs(afero.NewOsFs(), scope)
}

func TestVerifyActivation(t *testing.T) {
	_, verified := verifyScope(t)
	if !verified.verifyFD.Load() {
		t.Fatalf("OsFs-backed scope should verify opened files")
	}

	mem := NewScopedFs(afero.NewMemMapFs(), "/")
	if mem.verifyFD.Load() {
		t.Fatalf("MemMapFs-backed scope must not verify opened files")
	}

	rebased := NewScopedFs(verified, "/sub")
	if rebased.verifyFD.Load() != verified.verifyFD.Load() {
		t.Fatalf("rebase must inherit confinement mode")
	}
	rebasedMem := NewScopedFs(mem, "/sub")
	if rebasedMem.verifyFD.Load() {
		t.Fatalf("rebase of a MemMapFs scope must stay unverified")
	}
}

func TestVerifyEscapeRejected(t *testing.T) {
	base, fs := verifyScope(t)
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "srv", "escape")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	if _, err := fs.Open("/escape/secret.txt"); !os.IsPermission(err) {
		t.Fatalf("open through escape = %v, want permission", err)
	}
	f, err := fs.OpenFile("/escape/evil.txt", os.O_WRONLY|os.O_CREATE, 0o644)
	if err == nil {
		f.Close()
		t.Fatalf("write through escape succeeded")
	}
	if !os.IsPermission(err) {
		t.Fatalf("write through escape = %v, want permission", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "evil.txt")); !os.IsNotExist(err) {
		t.Fatalf("escape write landed outside: %v", err)
	}
}

// Absolute symlinks pointing inside the scope are legitimate and must keep
// working: verification compares the final target, unlike openat2 beneath
// semantics which would reject the transient escape.
func TestVerifyAbsoluteInternalSymlinkWorks(t *testing.T) {
	base, fs := verifyScope(t)
	target := filepath.Join(base, "srv", "real.txt")
	if err := os.WriteFile(target, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(base, "srv", "abslink")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	content, err := afero.ReadFile(fs, "/abslink")
	if err != nil {
		t.Fatalf("read through absolute internal link: %v", err)
	}
	if string(content) != "data" {
		t.Fatalf("got %q, want %q", content, "data")
	}
}

func TestVerifyInternalSymlinkWorks(t *testing.T) {
	base, fs := verifyScope(t)
	if err := os.WriteFile(filepath.Join(base, "srv", "real.txt"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.txt", filepath.Join(base, "srv", "link.txt")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	content, err := afero.ReadFile(fs, "/link.txt")
	if err != nil {
		t.Fatalf("read through internal link: %v", err)
	}
	if string(content) != "data" {
		t.Fatalf("got %q, want %q", content, "data")
	}
	if err := afero.WriteFile(fs, "/link.txt", []byte("changed"), 0o644); err != nil {
		t.Fatalf("write through internal link: %v", err)
	}
	if content, _ := os.ReadFile(filepath.Join(base, "srv", "real.txt")); string(content) != "changed" {
		t.Fatalf("write did not land on target: %q", content)
	}
}

// While a symlink flips between an in-scope and an out-of-scope target,
// reads must either see in-scope content or be refused — never the outside
// content. Verification inspects the opened descriptor itself, so unlike
// check-then-use this holds no matter when the swap lands. Linux-only: the
// fallback path cannot pin the check to the open file.
func TestVerifySwapNeverEscapes(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fd verification is linux-only")
	}
	base, fs := verifyScope(t)
	scope := filepath.Join(base, "srv")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scope, "inside.txt"), []byte("INSIDE"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("OUTSIDE-SECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkA := filepath.Join(scope, "a")
	linkB := filepath.Join(scope, "b")
	swap := filepath.Join(scope, "swap")
	if err := os.Symlink(filepath.Join(scope, "inside.txt"), linkA); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), linkB); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if err := os.Rename(linkA, swap); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		flip := false
		for {
			select {
			case <-stop:
				return
			default:
			}
			src := linkA
			if flip {
				src = linkB
			}
			flip = !flip
			// Best effort: a failed rename just retries; the link stays valid.
			_ = os.Rename(src, swap)
		}
	}()

	const reads = 2000
	leaks := 0
	refused := 0
	for i := 0; i < reads; i++ {
		content, err := afero.ReadFile(fs, "/swap")
		if err != nil {
			if !os.IsPermission(err) {
				t.Fatalf("unexpected error: %v", err)
			}
			refused++
			continue
		}
		if string(content) == "OUTSIDE-SECRET" {
			leaks++
			if link, lerr := os.Readlink(swap); lerr == nil {
				if dest, derr := os.Readlink(link); derr == nil {
					t.Logf("leak at iter %d: swap->%s->%s", i, link, dest)
				} else {
					t.Logf("leak at iter %d: swap->%s (direct file?)", i, link)
				}
			} else {
				t.Logf("leak at iter %d: swap unreadable: %v", i, lerr)
			}
		} else if string(content) != "INSIDE" {
			t.Fatalf("unexpected content %q", content)
		}
	}
	close(stop)
	wg.Wait()

	// Without observing the outside phase the test would prove nothing.
	if refused == 0 {
		t.Fatalf("swap race never hit the outside phase; test is vacuous")
	}
	if leaks > 0 {
		t.Fatalf("VULNERABLE: swap race leaked outside content %d/%d times", leaks, reads)
	}
}

func TestVerifyCreateSemantics(t *testing.T) {
	base, fs := verifyScope(t)
	scope := filepath.Join(base, "srv")

	// Plain create + truncate + append behave like the OS path.
	if err := afero.WriteFile(fs, "/f.txt", []byte("hello"), 0o644); err != nil {
		t.Fatalf("create: %v", err)
	}
	f, err := fs.OpenFile("/f.txt", os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("append open: %v", err)
	}
	if _, err := f.Write([]byte("!")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if content, _ := afero.ReadFile(fs, "/f.txt"); string(content) != "hello!" {
		t.Fatalf("got %q, want %q", content, "hello!")
	}

	// Creating through a dangling link that points outside is refused...
	if err := os.Symlink(filepath.Join(base, "outside.txt"), filepath.Join(scope, "evil")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if f, err := fs.OpenFile("/evil", os.O_WRONLY|os.O_CREATE, 0o644); err == nil {
		f.Close()
		t.Fatalf("create through escaping dangling link succeeded")
	} else if !os.IsPermission(err) {
		t.Fatalf("create through escaping dangling link = %v, want permission", err)
	}
	if _, err := os.Stat(filepath.Join(base, "outside.txt")); !os.IsNotExist(err) {
		t.Fatalf("escaping create landed outside: %v", err)
	}

	// ...while a dangling link inside the scope creates its target.
	if err := os.Symlink("fresh.txt", filepath.Join(scope, "oklink")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if err := afero.WriteFile(fs, "/oklink", []byte("new"), 0o644); err != nil {
		t.Fatalf("create through internal dangling link: %v", err)
	}
	if content, _ := os.ReadFile(filepath.Join(scope, "fresh.txt")); string(content) != "new" {
		t.Fatalf("internal create landed %q", content)
	}
}

// verify inspects the descriptor itself, not the path: an already-open
// outside file is rejected even though no guard runs for it here.
func TestVerifyInspectsDescriptor(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fd verification is linux-only")
	}
	base, fs := verifyScope(t)
	secret := filepath.Join(base, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(base, "srv", "in.txt")
	if err := os.WriteFile(inside, []byte("in"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := os.Open(secret)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if err := fs.verify(out); !os.IsPermission(err) {
		t.Fatalf("verify(outside fd) = %v, want permission", err)
	}

	in, err := os.Open(inside)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if err := fs.verify(in); err != nil {
		t.Fatalf("verify(inside fd) = %v, want nil", err)
	}
}

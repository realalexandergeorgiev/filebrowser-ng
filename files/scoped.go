package files

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spf13/afero"
)

// ScopedFs is an afero.Fs that confines every operation to a base directory and
// refuses to follow a symbolic link whose on-disk target resolves outside that
// base. It wraps an *afero.BasePathFs — which already provides the lexical
// confinement — and adds a per-operation scope check on every call that would
// dereference a symlink at the OS layer (open, stat, lstat, chmod, …).
//
// File content operations (Create, Open, OpenFile) additionally verify the
// opened file itself: resolving /proc/self/fd of the fresh descriptor pins
// the check to the file that was actually opened, so a symlink swapped
// between the guard and the open is caught instead of served. Everywhere
// the descriptor cannot be inspected (other platforms, non-OsFs backing)
// the same calls fall back to the guard alone.
type ScopedFs struct {
	base *afero.BasePathFs
	// verifyFD enables post-open verification. It is set when the scope is
	// (transitively) OsFs-backed.
	verifyFD atomic.Bool
}

var (
	_ afero.Fs      = (*ScopedFs)(nil)
	_ afero.Lstater = (*ScopedFs)(nil)
)

// maxSymlinkHops bounds how many dangling symlinks within() will follow before
// giving up, so a pathological chain cannot loop forever. It mirrors the kernel
// MAXSYMLINKS limit; the operation is rejected once the bound is exceeded.
const maxSymlinkHops = 255

func NewScopedFs(source afero.Fs, path string) *ScopedFs {
	verify := false
	if s, ok := source.(*ScopedFs); ok {
		// Rebasing (e.g. public shares) keeps the inner confinement mode.
		verify = s.verifyFD.Load()
		source = s.base
	} else if _, ok := source.(*afero.OsFs); ok {
		verify = true
	}
	s := &ScopedFs{base: afero.NewBasePathFs(source, path).(*afero.BasePathFs)}
	s.verifyFD.Store(verify)
	return s
}

// NewFs builds a user filesystem rooted at path. When followExternal is true it
// returns a bare BasePathFs, so symlinks whose target resolves outside the scope
// are followed; otherwise it returns a ScopedFs that refuses to follow them.
func NewFs(source afero.Fs, path string, followExternal bool) afero.Fs {
	if followExternal {
		return afero.NewBasePathFs(source, path)
	}
	return NewScopedFs(source, path)
}

// BasePath returns the underlying *afero.BasePathFs of a user filesystem built
// by NewFs, whether it is a *ScopedFs or a bare *afero.BasePathFs, or nil if it
// is neither.
func BasePath(fs afero.Fs) *afero.BasePathFs {
	switch f := fs.(type) {
	case *ScopedFs:
		return f.BasePathFs()
	case *afero.BasePathFs:
		return f
	}
	return nil
}

// BasePathFs returns the underlying *afero.BasePathFs.
func (s *ScopedFs) BasePathFs() *afero.BasePathFs { return s.base }

// RealPath resolves a scoped path to the real on-disk path by delegating to
// the underlying BasePathFs. This is needed by callers that need the actual
// filesystem path (e.g. disk.UsageWithContext).
func (s *ScopedFs) RealPath(name string) (string, error) {
	return s.base.RealPath(name)
}

// guard returns an error if name's on-disk target resolves outside the scope.
func (s *ScopedFs) guard(name string) error {
	ok, err := s.within(name)
	if err != nil {
		return err
	}
	if !ok {
		return os.ErrPermission
	}
	return nil
}

// within reports whether the on-disk target of p — after resolving any symbolic
// links — stays within the scoped root. It exists to stop a symlink that lives
// lexically inside the scope but points outside it from being followed for
// reads, writes, or shares.
//
// Paths that do not exist yet (e.g. a brand-new file being created) are
// validated against their nearest existing ancestor, so legitimate new files
// are always allowed. A dangling symlink — a link whose target does not exist
// yet — is the exception: it is followed to where it points and validated
// there, so a write cannot dereference the link to create a file outside the
// scope.
func (s *ScopedFs) within(p string) (bool, error) {
	root, err := filepath.EvalSymlinks(afero.FullBaseFsPath(s.base, "/"))
	if err != nil {
		return false, err
	}

	target := afero.FullBaseFsPath(s.base, p)
	resolved, err := filepath.EvalSymlinks(target)
	// When target does not resolve, work out where the operation would actually
	// land. A non-existent regular path resolves to the file that would be
	// created inside its containing directory, so walk up to the nearest
	// existing ancestor and validate that. But when target itself is a dangling
	// symlink, follow it one level instead: validating its lexical parent would
	// wrongly accept a link pointing outside the scope, letting a write follow
	// the link and create the file out of bounds.
	for hops := 0; errors.Is(err, fs.ErrNotExist); {
		if fi, lerr := os.Lstat(target); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
			hops++
			if hops > maxSymlinkHops {
				return false, os.ErrPermission
			}
			dest, rerr := os.Readlink(target)
			if rerr != nil {
				return false, rerr
			}
			if !filepath.IsAbs(dest) {
				// Resolve the link relative to the directory that really contains
				// it, not its lexical parent: a symlinked ancestor could otherwise
				// shift the computed target back into scope while the real write
				// lands outside it. The parent is guaranteed to resolve here
				// because os.Lstat above already traversed it.
				base, berr := filepath.EvalSymlinks(filepath.Dir(target))
				if berr != nil {
					return false, berr
				}
				dest = filepath.Join(base, dest)
			}
			target = filepath.Clean(dest)
		} else {
			parent := filepath.Dir(target)
			if parent == target {
				break
			}
			target = parent
		}
		resolved, err = filepath.EvalSymlinks(target)
	}
	if err != nil {
		return false, err
	}

	// Compare against root with a trailing separator so a sibling like
	// "/srvother" is not treated as being inside "/srv". When root is itself the
	// filesystem boundary (e.g. "/"), it already ends in a separator, so avoid
	// producing "//" — which no path would match — and accept any path under it.
	prefix := root
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}

	return resolved == root || strings.HasPrefix(resolved, prefix), nil
}

// osFileOf unwraps afero layers (notably BasePathFile, which BasePathFs
// returns for every open) down to the *os.File the kernel gave out, so
// descriptor checks inspect the real open file. Anything else yields nil.
func osFileOf(f afero.File) *os.File {
	for f != nil {
		if of, ok := f.(*os.File); ok {
			return of
		}
		bf, ok := f.(*afero.BasePathFile)
		if !ok {
			return nil
		}
		f = bf.File
	}
	return nil
}

func (s *ScopedFs) Create(name string) (afero.File, error) {
	if err := s.guard(name); err != nil {
		return nil, err
	}
	f, err := s.base.Create(name)
	if err != nil {
		return nil, err
	}
	if err := s.verify(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (s *ScopedFs) Mkdir(name string, perm os.FileMode) error {
	// The guard sits directly above the syscall on purpose: guard() then
	// op() is inherently racy against a concurrently swapped symlink, so
	// the check closest to the call is the one that counts. This narrows
	// the window to nanoseconds but cannot close it for metadata ops (no
	// descriptor to verify, unlike content opens); see ARCHITEKTUR.md §7.
	if err := s.guard(name); err != nil {
		return err
	}
	return s.base.Mkdir(name, perm)
}

func (s *ScopedFs) MkdirAll(path string, perm os.FileMode) error {
	// The guard sits directly above the syscall on purpose: guard() then
	// op() is inherently racy against a concurrently swapped symlink, so
	// the check closest to the call is the one that counts. This narrows
	// the window to nanoseconds but cannot close it for metadata ops (no
	// descriptor to verify, unlike content opens); see ARCHITEKTUR.md §7.
	if err := s.guard(path); err != nil {
		return err
	}
	return s.base.MkdirAll(path, perm)
}

func (s *ScopedFs) Open(name string) (afero.File, error) {
	if err := s.guard(name); err != nil {
		return nil, err
	}
	f, err := s.base.Open(name)
	if err != nil {
		return nil, err
	}
	if err := s.verify(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (s *ScopedFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	if err := s.guard(name); err != nil {
		return nil, err
	}
	f, err := s.base.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	if err := s.verify(f); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (s *ScopedFs) Remove(name string) error {
	// The guard sits directly above the syscall on purpose: guard() then
	// op() is inherently racy against a concurrently swapped symlink, so
	// the check closest to the call is the one that counts. This narrows
	// the window to nanoseconds but cannot close it for metadata ops (no
	// descriptor to verify, unlike content opens); see ARCHITEKTUR.md §7.
	if err := s.guard(name); err != nil {
		return err
	}
	return s.base.Remove(name)
}

func (s *ScopedFs) RemoveAll(path string) error {
	// The guard sits directly above the syscall on purpose: guard() then
	// op() is inherently racy against a concurrently swapped symlink, so
	// the check closest to the call is the one that counts. This narrows
	// the window to nanoseconds but cannot close it for metadata ops (no
	// descriptor to verify, unlike content opens); see ARCHITEKTUR.md §7.
	if err := s.guard(path); err != nil {
		return err
	}
	return s.base.RemoveAll(path)
}

func (s *ScopedFs) Rename(oldname, newname string) error {
	// The guard sits directly above the syscall on purpose: guard() then
	// op() is inherently racy against a concurrently swapped symlink, so
	// the check closest to the call is the one that counts. This narrows
	// the window to nanoseconds but cannot close it for metadata ops (no
	// descriptor to verify, unlike content opens); see ARCHITEKTUR.md §7.
	if err := s.guard(oldname); err != nil {
		return err
	}
	if err := s.guard(newname); err != nil {
		return err
	}
	return s.base.Rename(oldname, newname)
}

func (s *ScopedFs) Stat(name string) (os.FileInfo, error) {
	// The guard sits directly above the syscall on purpose: guard() then
	// op() is inherently racy against a concurrently swapped symlink, so
	// the check closest to the call is the one that counts. This narrows
	// the window to nanoseconds but cannot close it for metadata ops (no
	// descriptor to verify, unlike content opens); see ARCHITEKTUR.md §7.
	if err := s.guard(name); err != nil {
		return nil, err
	}
	return s.base.Stat(name)
}

func (s *ScopedFs) Name() string { return "ScopedFs" }

func (s *ScopedFs) Chmod(name string, mode os.FileMode) error {
	// The guard sits directly above the syscall on purpose: guard() then
	// op() is inherently racy against a concurrently swapped symlink, so
	// the check closest to the call is the one that counts. This narrows
	// the window to nanoseconds but cannot close it for metadata ops (no
	// descriptor to verify, unlike content opens); see ARCHITEKTUR.md §7.
	if err := s.guard(name); err != nil {
		return err
	}
	return s.base.Chmod(name, mode)
}

func (s *ScopedFs) Chown(name string, uid, gid int) error {
	// The guard sits directly above the syscall on purpose: guard() then
	// op() is inherently racy against a concurrently swapped symlink, so
	// the check closest to the call is the one that counts. This narrows
	// the window to nanoseconds but cannot close it for metadata ops (no
	// descriptor to verify, unlike content opens); see ARCHITEKTUR.md §7.
	if err := s.guard(name); err != nil {
		return err
	}
	return s.base.Chown(name, uid, gid)
}

func (s *ScopedFs) Chtimes(name string, atime, mtime time.Time) error {
	// The guard sits directly above the syscall on purpose: guard() then
	// op() is inherently racy against a concurrently swapped symlink, so
	// the check closest to the call is the one that counts. This narrows
	// the window to nanoseconds but cannot close it for metadata ops (no
	// descriptor to verify, unlike content opens); see ARCHITEKTUR.md §7.
	if err := s.guard(name); err != nil {
		return err
	}
	return s.base.Chtimes(name, atime, mtime)
}

func (s *ScopedFs) LstatIfPossible(name string) (os.FileInfo, bool, error) {
	// The guard sits directly above the syscall on purpose: guard() then
	// op() is inherently racy against a concurrently swapped symlink, so
	// the check closest to the call is the one that counts. This narrows
	// the window to nanoseconds but cannot close it for metadata ops (no
	// descriptor to verify, unlike content opens); see ARCHITEKTUR.md §7.
	if err := s.guard(name); err != nil {
		return nil, false, err
	}
	return s.base.LstatIfPossible(name)
}

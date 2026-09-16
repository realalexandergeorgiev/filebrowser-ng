//go:build linux

package files

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/afero"
)

var verifyUnavailableOnce sync.Once

// verify re-checks confinement against the file that was actually opened:
// resolving /proc/self/fd of the fresh descriptor pins the check to the
// open file description, so a symlink swapped between the guard and the
// open is caught instead of served. Reads and writes after this point use
// the verified descriptor and cannot be redirected by later swaps.
//
// Only positive proof of escape denies: anything the check cannot decide
// (no /proc, unlinked target, resolution errors) defers to the guard that
// already ran, so exotic environments keep working.
func (s *ScopedFs) verify(f afero.File) error {
	if !s.verifyFD.Load() {
		return nil
	}
	of, ok := f.(*os.File)
	if !ok {
		return nil
	}
	target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", of.Fd()))
	if err != nil {
		verifyUnavailableOnce.Do(func() {
			log.Printf("scopedfs: cannot inspect open files (%v), relying on path checks", err)
		})
		return nil
	}
	// An unlinked-but-open file reports a " (deleted)" suffix; the
	// descriptor stays valid, so resolve the original path.
	target = strings.TrimSuffix(target, " (deleted)")
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return nil
	}
	root, err := filepath.EvalSymlinks(afero.FullBaseFsPath(s.base, "/"))
	if err != nil {
		return nil
	}
	prefix := root
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	if resolved == root || strings.HasPrefix(resolved, prefix) {
		return nil
	}
	return os.ErrPermission
}

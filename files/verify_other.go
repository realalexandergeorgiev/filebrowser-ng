//go:build !linux

package files

import (
	"github.com/spf13/afero"
)

// verify is a no-op off Linux: without /proc/self/fd the opened file cannot
// be inspected portably, so opens rely on the guard alone.
func (s *ScopedFs) verify(_ afero.File) error {
	return nil
}

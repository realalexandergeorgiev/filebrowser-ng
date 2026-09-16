package diskcache

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/spf13/afero"
)

// lockStripes bounds the locking memory: one entry per cache key would grow
// forever, while a fixed stripe set keeps same-key access serialized.
const lockStripes = 64

type FileCache struct {
	fs afero.Fs

	stripes [lockStripes]sync.RWMutex
}

func New(fs afero.Fs, root string) *FileCache {
	return &FileCache{
		fs: afero.NewBasePathFs(fs, root),
	}
}

func (f *FileCache) Store(_ context.Context, key string, value []byte) error {
	stripe := f.stripe(key)
	stripe.Lock()
	defer stripe.Unlock()

	fileName := f.getFileName(key)
	if err := f.fs.MkdirAll(filepath.Dir(fileName), 0700); err != nil {
		return err
	}

	if err := afero.WriteFile(f.fs, fileName, value, 0700); err != nil {
		return err
	}

	return nil
}

func (f *FileCache) Load(_ context.Context, key string) (value []byte, exist bool, err error) {
	// Read-locked against concurrent stores of the same stripe so a load
	// never observes a half-written entry.
	stripe := f.stripe(key)
	stripe.RLock()
	defer stripe.RUnlock()

	r, ok, err := f.open(key)
	if err != nil || !ok {
		return nil, ok, err
	}
	defer r.Close()

	value, err = io.ReadAll(r)
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

func (f *FileCache) Delete(_ context.Context, key string) error {
	stripe := f.stripe(key)
	stripe.Lock()
	defer stripe.Unlock()

	fileName := f.getFileName(key)
	if err := f.fs.Remove(fileName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (f *FileCache) open(key string) (afero.File, bool, error) {
	fileName := f.getFileName(key)
	file, err := f.fs.Open(fileName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}

	return file, true, nil
}

// stripe maps a key onto a fixed lock set, so lock memory stays constant
// no matter how many keys pass through the cache.
func (f *FileCache) stripe(key string) *sync.RWMutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &f.stripes[h.Sum32()%lockStripes]
}

func (f *FileCache) getFileName(key string) string {
	hasher := sha1.New()
	_, _ = hasher.Write([]byte(key))
	hash := hex.EncodeToString(hasher.Sum(nil))
	return fmt.Sprintf("%s/%s/%s", hash[:1], hash[1:3], hash)
}

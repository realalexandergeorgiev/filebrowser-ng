package diskcache

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestFileCache(t *testing.T) {
	ctx := context.Background()
	const (
		key            = "key"
		value          = "some text"
		newValue       = "new text"
		cacheRoot      = "/cache"
		cachedFilePath = "a/62/a62f2225bf70bfaccbc7f1ef2a397836717377de"
	)

	fs := afero.NewMemMapFs()
	cache := New(fs, "/cache")

	// store new key
	err := cache.Store(ctx, key, []byte(value))
	require.NoError(t, err)
	checkValue(ctx, t, fs, filepath.Join(cacheRoot, cachedFilePath), cache, key, value)

	// update existing key
	err = cache.Store(ctx, key, []byte(newValue))
	require.NoError(t, err)
	checkValue(ctx, t, fs, filepath.Join(cacheRoot, cachedFilePath), cache, key, newValue)

	// delete key
	err = cache.Delete(ctx, key)
	require.NoError(t, err)
	exists, err := afero.Exists(fs, filepath.Join(cacheRoot, cachedFilePath))
	require.NoError(t, err)
	require.False(t, exists)
}

func TestFileCacheConcurrentSameKey(t *testing.T) {
	ctx := context.Background()
	fs := afero.NewMemMapFs()
	cache := New(fs, "/cache")

	const writers = 8
	values := make([]string, writers)
	for i := range values {
		values[i] = fmt.Sprintf("value-%d", i)
	}

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := cache.Store(ctx, "shared", []byte(values[i])); err != nil {
				t.Errorf("store: %v", err)
			}
			if _, _, err := cache.Load(ctx, "shared"); err != nil {
				t.Errorf("load: %v", err)
			}
		}(i)
	}
	// Distinct keys in parallel must all land intact.
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", i)
			if err := cache.Store(ctx, key, []byte(values[i])); err != nil {
				t.Errorf("store %s: %v", key, err)
			}
		}(i)
	}
	wg.Wait()

	// Same-key content must be one complete write, never an interleave.
	got, ok, err := cache.Load(ctx, "shared")
	require.NoError(t, err)
	require.True(t, ok)
	require.Contains(t, values, string(got))

	for i := 0; i < writers; i++ {
		key := fmt.Sprintf("key-%d", i)
		got, ok, err := cache.Load(ctx, key)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, values[i], string(got))
	}
}

func TestFileCacheStripesBounded(t *testing.T) {
	cache := New(afero.NewMemMapFs(), "/cache")
	a, b := cache.stripe("same"), cache.stripe("same")
	require.Same(t, a, b, "same key must map to the same stripe")
}

func checkValue(ctx context.Context, t *testing.T, fs afero.Fs, fileFullPath string, cache *FileCache, key, wantValue string) {
	t.Helper()
	// check actual file content
	b, err := afero.ReadFile(fs, fileFullPath)
	require.NoError(t, err)
	require.Equal(t, wantValue, string(b))

	// check cache content
	b, ok, err := cache.Load(ctx, key)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, wantValue, string(b))
}

package fbhttp

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

// A TUS PATCH must not write more than the declared Upload-Length. A client that
// declares a small length and then streams a large body must be rejected without
// the excess being written to disk, while a correctly-sized upload still works.
func TestTusPatchEnforcesUploadLength(t *testing.T) {
	root := t.TempDir()
	userScope := filepath.Join(root, "user")
	if err := os.MkdirAll(userScope, 0o755); err != nil {
		t.Fatal(err)
	}

	key := []byte("test-signing-key")
	perm := users.Permissions{Create: true, Modify: true}
	st := scopedUserStorage(t, userScope, perm, key)
	signed := signToken(t, st, perm, key)

	cache := newMemoryUploadCache()
	t.Cleanup(cache.Close)
	post := handle(tusPostHandler(cache), "", st, &settings.Server{})
	patch := handle(tusPatchHandler(cache), "", st, &settings.Server{})

	patchReq := func(body string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodPatch, "/file.txt", strings.NewReader(body))
		req.Header.Set("X-Auth", signed)
		req.Header.Set("Content-Type", "application/offset+octet-stream")
		req.Header.Set("Upload-Offset", "0")
		rec := httptest.NewRecorder()
		patch.ServeHTTP(rec, req)
		return rec
	}

	// Create an upload that declares only 5 bytes.
	reqPost, _ := http.NewRequest(http.MethodPost, "/file.txt", http.NoBody)
	reqPost.Header.Set("X-Auth", signed)
	reqPost.Header.Set("Upload-Length", "5")
	recPost := httptest.NewRecorder()
	post.ServeHTTP(recPost, reqPost)
	if recPost.Code != http.StatusCreated {
		t.Fatalf("POST expected 201, got %d body=%q", recPost.Code, recPost.Body.String())
	}

	// A body far larger than the declared length must be rejected, and nothing
	// beyond the declared length may reach disk.
	if rec := patchReq(strings.Repeat("A", 5000)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-length PATCH expected 413, got %d body=%q", rec.Code, rec.Body.String())
	}
	if fi, err := os.Stat(filepath.Join(userScope, "file.txt")); err != nil {
		t.Fatalf("stat file.txt: %v", err)
	} else if fi.Size() > 5 {
		t.Fatalf("wrote %d bytes despite Upload-Length 5", fi.Size())
	}

	// A correctly-sized upload still completes.
	if rec := patchReq("hello"); rec.Code != http.StatusNoContent {
		t.Fatalf("valid PATCH expected 204, got %d body=%q", rec.Code, rec.Body.String())
	}
	if data, _ := os.ReadFile(filepath.Join(userScope, "file.txt")); string(data) != "hello" {
		t.Fatalf("expected file content \"hello\", got %q", string(data))
	}
}

// Concurrent duplicate chunks must not corrupt the file: every PATCH writes
// positionally at its offset, so simultaneous retries overwrite the same
// range instead of appending past it (which O_APPEND used to force).
func TestTusPatchConcurrentDuplicates(t *testing.T) {
	root := t.TempDir()
	userScope := filepath.Join(root, "user")
	if err := os.MkdirAll(userScope, 0o755); err != nil {
		t.Fatal(err)
	}

	key := []byte("test-signing-key")
	perm := users.Permissions{Create: true, Modify: true}
	st := scopedUserStorage(t, userScope, perm, key)
	signed := signToken(t, st, perm, key)

	cache := newMemoryUploadCache()
	t.Cleanup(cache.Close)
	post := handle(tusPostHandler(cache), "", st, &settings.Server{})
	patch := handle(tusPatchHandler(cache), "", st, &settings.Server{})

	reqPost, _ := http.NewRequest(http.MethodPost, "/dup.txt", http.NoBody)
	reqPost.Header.Set("X-Auth", signed)
	reqPost.Header.Set("Upload-Length", "5")
	recPost := httptest.NewRecorder()
	post.ServeHTTP(recPost, reqPost)
	if recPost.Code != http.StatusCreated {
		t.Fatalf("POST expected 201, got %d body=%q", recPost.Code, recPost.Body.String())
	}

	const workers = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req, _ := http.NewRequest(http.MethodPatch, "/dup.txt", strings.NewReader("hello"))
			req.Header.Set("X-Auth", signed)
			req.Header.Set("Content-Type", "application/offset+octet-stream")
			req.Header.Set("Upload-Offset", "0")
			rec := httptest.NewRecorder()
			patch.ServeHTTP(rec, req)
		}()
	}
	close(start)
	wg.Wait()

	fi, err := os.Stat(filepath.Join(userScope, "dup.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 5 {
		t.Fatalf("VULNERABLE: concurrent duplicate chunks left %d bytes, want 5", fi.Size())
	}
	if data, _ := os.ReadFile(filepath.Join(userScope, "dup.txt")); string(data) != "hello" {
		t.Fatalf("expected %q, got %q", "hello", string(data))
	}
}

// An invalid Upload-Length must be rejected before anything is written: the
// POST used to open the file with O_TRUNC first and fail afterwards,
// emptying an existing file on a request that uploads nothing.
func TestTusPostInvalidLengthDoesNotTruncate(t *testing.T) {
	root := t.TempDir()
	userScope := filepath.Join(root, "user")
	if err := os.MkdirAll(userScope, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userScope, "keep.txt"), []byte("keepme"), 0o600); err != nil {
		t.Fatal(err)
	}

	key := []byte("test-signing-key")
	perm := users.Permissions{Create: true, Modify: true}
	st := scopedUserStorage(t, userScope, perm, key)
	signed := signToken(t, st, perm, key)

	cache := newMemoryUploadCache()
	t.Cleanup(cache.Close)
	post := handle(tusPostHandler(cache), "", st, &settings.Server{})

	for _, length := range []string{"not-a-number", "-5", ""} {
		reqPost, _ := http.NewRequest(http.MethodPost, "/keep.txt?override=true", http.NoBody)
		reqPost.Header.Set("X-Auth", signed)
		if length != "" {
			reqPost.Header.Set("Upload-Length", length)
		}
		recPost := httptest.NewRecorder()
		post.ServeHTTP(recPost, reqPost)
		if recPost.Code != http.StatusBadRequest {
			t.Fatalf("Upload-Length %q: expected 400, got %d body=%q", length, recPost.Code, recPost.Body.String())
		}
		if data, _ := os.ReadFile(filepath.Join(userScope, "keep.txt")); string(data) != "keepme" {
			t.Fatalf("VULNERABLE: Upload-Length %q truncated the file to %q", length, string(data))
		}
	}
}

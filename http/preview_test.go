package fbhttp

// Regression: preview resize ran on context.Background, so aborting the
// client kept burning CPU on an image nobody receives. Resize is bound to
// the request context now; context.Background().Done() is nil while a
// request context always carries a Done channel, which pins the behavior.
import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"github.com/filebrowser/filebrowser/v2/img"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

type ctxCaptureImgSvc struct {
	mu        sync.Mutex
	resizeCtx context.Context
	stored    map[string][]byte
}

func (f *ctxCaptureImgSvc) FormatFromExtension(string) (img.Format, error) {
	return img.FormatJpeg, nil
}

func (f *ctxCaptureImgSvc) Resize(ctx context.Context, _ io.Reader, _, _ int, out io.Writer, _ ...img.Option) error {
	f.resizeCtx = ctx
	_, err := io.WriteString(out, "resized")
	return err
}

func (f *ctxCaptureImgSvc) Store(_ context.Context, key string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stored == nil {
		f.stored = map[string][]byte{}
	}
	f.stored[key] = value
	return nil
}

func (f *ctxCaptureImgSvc) Load(context.Context, string) ([]byte, bool, error) {
	return nil, false, nil
}

func (f *ctxCaptureImgSvc) Delete(context.Context, string) error { return nil }

func TestPreviewResizeBoundToRequest(t *testing.T) {
	userScope := t.TempDir()
	if err := os.WriteFile(filepath.Join(userScope, "pic.png"), []byte("fakepng"), 0o600); err != nil {
		t.Fatal(err)
	}

	key := []byte("test-signing-key")
	perm := users.Permissions{Download: true}
	st := scopedUserStorage(t, userScope, perm, key)
	signed := signToken(t, st, perm, key)

	svc := &ctxCaptureImgSvc{}
	h := handle(previewHandler(svc, svc, true, true), "/api/preview", st, &settings.Server{})

	req, _ := http.NewRequest(http.MethodGet, "/thumb/pic.png", http.NoBody)
	req = mux.SetURLVars(req, map[string]string{"size": "thumb", "path": "pic.png"})
	// A real server request always carries a cancelable context;
	// httptest.NewRequest does not, so attach one explicitly.
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	req = req.WithContext(ctx)
	req.Header.Set("X-Auth", signed)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("preview = %d body=%q, want 200", rec.Code, rec.Body.String())
	}
	if svc.resizeCtx == nil || svc.resizeCtx.Done() == nil {
		t.Fatalf("VULNERABLE: resize not bound to the request context")
	}
	// The cache write is intentionally detached from the request: poll.
	cached := false
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		svc.mu.Lock()
		cached = len(svc.stored) == 1
		svc.mu.Unlock()
		if cached {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !cached {
		t.Fatalf("expected the resized image to be cached")
	}
}

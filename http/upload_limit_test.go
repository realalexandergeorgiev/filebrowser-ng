package fbhttp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/realalexandergeorgiev/filebrowser-ng/diskcache"
	"github.com/realalexandergeorgiev/filebrowser-ng/settings"
)

// unknownLength hides strings.Reader's Len so the request carries no usable
// Content-Length: exercises the streaming cap, not the upfront check.
type unknownLength struct{ io.Reader }

func limitServer(max uint64) *settings.Server {
	return &settings.Server{MaxUploadSize: max}
}

func TestResourcePostEnforcesUploadLimit(t *testing.T) {
	st, _ := sessionTestSetup(t)
	token := sessionLogin(t, st, sessionTestPassword)
	h := handle(resourcePostHandler(diskcache.NewNoOp()), "", st, limitServer(16))

	post := func(path, body string, hideLen bool) *httptest.ResponseRecorder {
		var r io.Reader = strings.NewReader(body)
		if hideLen {
			r = unknownLength{r}
		}
		req, _ := http.NewRequest(http.MethodPost, path, r)
		req.Header.Set("X-Auth", token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	get := func(path string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodGet, path, http.NoBody)
		req.Header.Set("X-Auth", token)
		rec := httptest.NewRecorder()
		handle(resourceGetHandler, "", st, limitServer(16)).ServeHTTP(rec, req)
		return rec
	}

	if rec := post("/small.txt", "1234567890123456", false); rec.Code != http.StatusOK {
		t.Fatalf("at-limit POST = %d, want 200", rec.Code)
	}
	if rec := post("/big.txt", "12345678901234567", false); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit POST = %d, want 413", rec.Code)
	}
	if rec := get("/big.txt"); rec.Code != http.StatusNotFound {
		t.Fatalf("over-limit file exists: GET = %d, want 404", rec.Code)
	}
	// Unknown Content-Length must not bypass the cap.
	if rec := post("/chunked.txt", strings.Repeat("c", 100), true); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("unknown-length POST = %d, want 413", rec.Code)
	}
	if rec := get("/chunked.txt"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown-length file exists: GET = %d, want 404", rec.Code)
	}
}

func TestResourcePutEnforcesUploadLimit(t *testing.T) {
	st, _ := sessionTestSetup(t)
	token := sessionLogin(t, st, sessionTestPassword)
	srv := limitServer(16)

	create := handle(resourcePostHandler(diskcache.NewNoOp()), "", st, &settings.Server{})
	putFile := func(path, body string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("X-Auth", token)
		rec := httptest.NewRecorder()
		create.ServeHTTP(rec, req)
		return rec
	}
	if rec := putFile("/victim.txt", "original"); rec.Code != http.StatusOK {
		t.Fatalf("setup POST = %d, want 200", rec.Code)
	}

	put := handle(resourcePutHandler, "", st, srv)
	replace := func(body string, hideLen bool) *httptest.ResponseRecorder {
		var r io.Reader = strings.NewReader(body)
		if hideLen {
			r = unknownLength{r}
		}
		req, _ := http.NewRequest(http.MethodPut, "/victim.txt", r)
		req.Header.Set("X-Auth", token)
		rec := httptest.NewRecorder()
		put.ServeHTTP(rec, req)
		return rec
	}
	get := func() *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodGet, "/victim.txt", http.NoBody)
		req.Header.Set("X-Auth", token)
		rec := httptest.NewRecorder()
		handle(resourceGetHandler, "", st, srv).ServeHTTP(rec, req)
		return rec
	}

	if rec := replace("1234567890123456", false); rec.Code != http.StatusOK {
		t.Fatalf("at-limit PUT = %d, want 200", rec.Code)
	}
	// Declared size: rejected before touching disk, original intact.
	if rec := replace(strings.Repeat("x", 100), false); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit PUT = %d, want 413", rec.Code)
	}
	if rec := get(); rec.Code != http.StatusOK {
		t.Fatalf("pre-checked PUT damaged the file: GET = %d, want 200", rec.Code)
	}
	// Unknown size: the partial replace is removed, no corrupt remnant.
	if rec := replace(strings.Repeat("y", 100), true); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("unknown-length PUT = %d, want 413", rec.Code)
	}
	if rec := get(); rec.Code != http.StatusNotFound {
		t.Fatalf("partial replace left a file: GET = %d, want 404", rec.Code)
	}
}

func TestTusPostEnforcesUploadLimit(t *testing.T) {
	st, _ := sessionTestSetup(t)
	token := sessionLogin(t, st, sessionTestPassword)
	cache := newMemoryUploadCache()
	t.Cleanup(cache.Close)
	post := handle(tusPostHandler(cache), "", st, limitServer(10))

	try := func(length string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodPost, "/big.iso", http.NoBody)
		req.Header.Set("X-Auth", token)
		req.Header.Set("Upload-Length", length)
		rec := httptest.NewRecorder()
		post.ServeHTTP(rec, req)
		return rec
	}

	if rec := try("5000"); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit TUS creation = %d, want 413", rec.Code)
	}
	if rec := try("10"); rec.Code != http.StatusCreated {
		t.Fatalf("at-limit TUS creation = %d, want 201", rec.Code)
	}
}

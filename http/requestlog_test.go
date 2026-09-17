package fbhttp

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestFormatRequestLog(t *testing.T) {
	if got := formatRequestLog("/api/login", 403, "1.2.3.4", nil); got != "/api/login: 403 1.2.3.4" {
		t.Errorf("nil error = %q, want no trailing field", got)
	}
	if got := formatRequestLog("/api/x", 500, "1.2.3.4", errors.New("boom")); got != "/api/x: 500 1.2.3.4 boom" {
		t.Errorf("real error = %q, want it appended", got)
	}
}

// A rejected login must log status and client IP, not a confusing "<nil>".
func TestRejectedLoginLogsWithoutNil(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	h := routingTestHandler(t)
	req, _ := http.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /api/login = %d, want 403", rec.Code)
	}
	if out := buf.String(); strings.Contains(out, "<nil>") {
		t.Errorf("rejection log contains <nil>: %q", out)
	} else if !strings.Contains(out, "/api/login: 403") {
		t.Errorf("rejection log missing path and status: %q", out)
	}
}

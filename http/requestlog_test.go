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

	"github.com/realalexandergeorgiev/filebrowser-ng/settings"
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

// Successful logins are logged (takeover visibility), and usernames cannot
// forge log lines: %q keeps even a newline username on a single line.
func TestLoginSuccessLoggedWithoutInjection(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	st, _ := sessionTestSetup(t)
	set, err := st.Settings.Get()
	if err != nil {
		t.Fatal(err)
	}
	set.Signup = true
	if err := st.Settings.Save(set); err != nil {
		t.Fatal(err)
	}

	h := handle(signupHandler(), "", st, &settings.Server{})
	req, _ := http.NewRequest(http.MethodPost, "/signup", strings.NewReader(`{"username":"evil\nINJECTED","password":"xQ9vL2mZ"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("signup = %d body=%q, want 200", rec.Code, rec.Body.String())
	}
	if out := buf.String(); strings.Contains(out, "\nINJECTED") {
		t.Errorf("log injection: raw newline in log:\n%s", out)
	} else if !strings.Contains(out, "INJECTED") {
		t.Errorf("signup not logged at all:\n%s", out)
	}

	sessionLogin(t, st, sessionTestPassword)
	if out := buf.String(); !strings.Contains(out, `login: user "u"`) {
		t.Errorf("successful login not logged:\n%s", out)
	}
}

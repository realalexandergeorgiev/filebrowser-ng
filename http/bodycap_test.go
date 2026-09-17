package fbhttp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/realalexandergeorgiev/filebrowser-ng/settings"
)

// capJSONBody must stop readers past the login/signup budget: an unbounded
// decode would buffer attacker-controlled input in memory.
func TestCapJSONBodyLimitsReads(t *testing.T) {
	big := strings.Repeat("a", 2<<20)
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(big))
	capJSONBody(httptest.NewRecorder(), req)

	n, err := io.Copy(io.Discard, req.Body)
	if err == nil || !strings.Contains(err.Error(), "request body too large") {
		t.Fatalf("read %d bytes err=%v, want the body-too-large error", n, err)
	}
	if n > maxAuthBodySize+4096 {
		t.Fatalf("read %d bytes, want the read capped near %d", n, maxAuthBodySize)
	}
}

// End to end: an oversized but otherwise valid settings body must fail to
// decode (400). Without the cap the unknown-field body would decode fine
// and answer 200.
func TestOversizedSettingsBodyRejected(t *testing.T) {
	st, _ := sessionTestSetup(t)
	u, err := st.Users.Get("", false, "u")
	if err != nil {
		t.Fatal(err)
	}
	u.Perm.Admin = true
	if err := st.Users.Update(u); err != nil {
		t.Fatal(err)
	}
	token := sessionLogin(t, st, sessionTestPassword)

	h := handle(settingsPutHandler, "", st, &settings.Server{})
	put := func(body string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodPut, "/settings", strings.NewReader(body))
		req.Header.Set("X-Auth", token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := put(`{"signup":false}`); rec.Code != http.StatusOK {
		t.Fatalf("small body = %d, want 200", rec.Code)
	}
	padded := `{"signup":false,"pad":` + strconv.Quote(strings.Repeat("p", 2<<20)) + `}`
	if rec := put(padded); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body = %d, want 400", rec.Code)
	}
}

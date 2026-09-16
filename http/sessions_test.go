package fbhttp

// End-to-end session guarantees for filebrowser-ng (#5216,
// GO-2025-3812/CVE-2025-53826): tokens are bearer pointers to server-side
// sessions. Unknown sessions, logout, password/security changes and user
// deletion all turn previously valid tokens into 401 immediately.
import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	fbAuth "github.com/filebrowser/filebrowser/v2/auth"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/storage"
	"github.com/filebrowser/filebrowser/v2/users"
)

const (
	sessionTestPassword    = "OldPw12345!"
	sessionTestNewPassword = "NewPw12345!"
)

func sessionTestSetup(t *testing.T) (*storage.Storage, []byte) {
	t.Helper()
	key := []byte("test-signing-key")
	perm := users.Permissions{Create: true, Rename: true, Modify: true, Delete: true, Share: true, Download: true}
	st := scopedUserStorage(t, t.TempDir(), perm, key)

	hashed, err := users.ValidateAndHashPwd(sessionTestPassword, 1)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	u, err := st.Users.Get("", false, "u")
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}
	u.Password = hashed
	if err := st.Users.Update(u); err != nil {
		t.Fatalf("failed to set password: %v", err)
	}
	if err := st.Settings.Save(&settings.Settings{
		Key:                   key,
		AuthMethod:            fbAuth.MethodJSONAuth,
		MinimumPasswordLength: 1,
	}); err != nil {
		t.Fatalf("failed to save settings: %v", err)
	}
	if err := st.Auth.Save(&fbAuth.JSONAuth{}); err != nil {
		t.Fatalf("failed to save auther: %v", err)
	}
	return st, key
}

func sessionLogin(t *testing.T, st *storage.Storage, password string) string {
	t.Helper()
	body := fmt.Sprintf(`{"username":"u","password":%q}`, password)
	req, _ := http.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handle(loginHandler(time.Hour), "", st, &settings.Server{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d body=%q, want 200", rec.Code, rec.Body.String())
	}
	token := strings.TrimSpace(rec.Body.String())
	if strings.Count(token, ".") != 2 {
		t.Fatalf("login did not return a JWT: %q", rec.Body.String())
	}
	return token
}

func sessionGet(t *testing.T, st *storage.Storage, token string) *httptest.ResponseRecorder {
	t.Helper()
	protected := withUser(func(w http.ResponseWriter, _ *http.Request, _ *data) (int, error) {
		_, err := w.Write([]byte("protected"))
		return 0, err
	})
	req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-Auth", token)
	rec := httptest.NewRecorder()
	handle(protected, "", st, &settings.Server{}).ServeHTTP(rec, req)
	return rec
}

func TestLoginLogoutRevokesToken(t *testing.T) {
	st, _ := sessionTestSetup(t)
	token := sessionLogin(t, st, sessionTestPassword)

	if rec := sessionGet(t, st, token); rec.Code != http.StatusOK {
		t.Fatalf("use before logout = %d, want 200", rec.Code)
	}

	req, _ := http.NewRequest(http.MethodDelete, "/logout", http.NoBody)
	req.Header.Set("X-Auth", token)
	rec := httptest.NewRecorder()
	handle(logoutHandler, "", st, &settings.Server{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d body=%q, want 200", rec.Code, rec.Body.String())
	}

	// The signature is still valid, but the session is gone.
	if rec := sessionGet(t, st, token); rec.Code != http.StatusUnauthorized {
		t.Fatalf("VULNERABLE: token usable after logout = %d; want 401", rec.Code)
	}
	// Logging out twice is not an error at the handler level, but the token
	// no longer authenticates, so the second call cannot reach it.
	req, _ = http.NewRequest(http.MethodDelete, "/logout", http.NoBody)
	req.Header.Set("X-Auth", token)
	rec = httptest.NewRecorder()
	handle(logoutHandler, "", st, &settings.Server{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("second logout = %d, want 401 (token dead)", rec.Code)
	}
}

func TestRenewSlidesSession(t *testing.T) {
	st, _ := sessionTestSetup(t)
	token := sessionLogin(t, st, sessionTestPassword)

	req, _ := http.NewRequest(http.MethodPost, "/renew", http.NoBody)
	req.Header.Set("X-Auth", token)
	rec := httptest.NewRecorder()
	handle(renewHandler(time.Hour), "", st, &settings.Server{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew = %d body=%q, want 200", rec.Code, rec.Body.String())
	}
	renewed := strings.TrimSpace(rec.Body.String())
	if strings.Count(renewed, ".") != 2 {
		t.Fatalf("renew did not return a JWT: %q", rec.Body.String())
	}
	if rec := sessionGet(t, st, renewed); rec.Code != http.StatusOK {
		t.Fatalf("renewed token unusable = %d, want 200", rec.Code)
	}

	// Same sliding session: logging out with the renewed token kills the
	// original token too.
	req, _ = http.NewRequest(http.MethodDelete, "/logout", http.NoBody)
	req.Header.Set("X-Auth", renewed)
	rec = httptest.NewRecorder()
	handle(logoutHandler, "", st, &settings.Server{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d, want 200", rec.Code)
	}
	if rec := sessionGet(t, st, token); rec.Code != http.StatusUnauthorized {
		t.Fatalf("VULNERABLE: pre-renew token usable after logout = %d; want 401", rec.Code)
	}
}

func TestForgedSessionJTIRejected(t *testing.T) {
	st, key := sessionTestSetup(t)
	claims := &authToken{
		User: userInfo{ID: 1, Username: "u"},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "deadbeefdeadbeefdeadbeefdeadbeef",
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if rec := sessionGet(t, st, forged); rec.Code != http.StatusUnauthorized {
		t.Fatalf("VULNERABLE: unknown session accepted = %d; want 401", rec.Code)
	}
}

func TestDeletedUserTokenRejected(t *testing.T) {
	st, key := sessionTestSetup(t)
	// A live session for a user that does not exist: must be 401 (used to
	// be 500), never usable.
	sess, err := st.Sessions.Create(4242, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims := &authToken{
		User: userInfo{ID: 4242, Username: "ghost"},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        sess.JTI,
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if rec := sessionGet(t, st, signed); rec.Code != http.StatusUnauthorized {
		t.Fatalf("ghost-user token = %d; want 401", rec.Code)
	}
}

func sessionPut(t *testing.T, st *storage.Storage, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, "/users/1", strings.NewReader(body))
	req.SetPathValue("id", "1")
	req.Header.Set("X-Auth", token)
	rec := httptest.NewRecorder()
	handle(userPutHandler, "", st, &settings.Server{}).ServeHTTP(rec, req)
	return rec
}

func TestPasswordChangeRevokesSessions(t *testing.T) {
	st, _ := sessionTestSetup(t)
	tokenA := sessionLogin(t, st, sessionTestPassword)
	tokenB := sessionLogin(t, st, sessionTestPassword)

	body := fmt.Sprintf(`{"what":"user","which":["password"],"data":{"id":1,"username":"u","password":%q},"current_password":%q}`,
		sessionTestNewPassword, sessionTestPassword)
	if rec := sessionPut(t, st, tokenA, body); rec.Code != http.StatusOK {
		t.Fatalf("password change = %d body=%q, want 200", rec.Code, rec.Body.String())
	}

	for name, tok := range map[string]string{"pre-change login": tokenA, "second login": tokenB} {
		if rec := sessionGet(t, st, tok); rec.Code != http.StatusUnauthorized {
			t.Fatalf("VULNERABLE: %s usable after password change = %d; want 401", name, rec.Code)
		}
	}

	// The new password works.
	tokenC := sessionLogin(t, st, sessionTestNewPassword)
	if rec := sessionGet(t, st, tokenC); rec.Code != http.StatusOK {
		t.Fatalf("new-password login unusable = %d, want 200", rec.Code)
	}
}

func TestCosmeticUpdateKeepsSession(t *testing.T) {
	st, _ := sessionTestSetup(t)
	token := sessionLogin(t, st, sessionTestPassword)

	body := `{"what":"user","which":["locale"],"data":{"id":1,"username":"u","locale":"de"}}`
	if rec := sessionPut(t, st, token, body); rec.Code != http.StatusOK {
		t.Fatalf("locale change = %d body=%q, want 200", rec.Code, rec.Body.String())
	}
	if rec := sessionGet(t, st, token); rec.Code != http.StatusOK {
		t.Fatalf("token killed by cosmetic update = %d, want 200", rec.Code)
	}
}

func TestDeleteRevokesSessions(t *testing.T) {
	st, _ := sessionTestSetup(t)
	token := sessionLogin(t, st, sessionTestPassword)

	body := fmt.Sprintf(`{"current_password":%q}`, sessionTestPassword)
	req, _ := http.NewRequest(http.MethodDelete, "/users/1", strings.NewReader(body))
	req.SetPathValue("id", "1")
	req.Header.Set("X-Auth", token)
	rec := httptest.NewRecorder()
	handle(userDeleteHandler, "", st, &settings.Server{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d body=%q, want 200", rec.Code, rec.Body.String())
	}
	if rec := sessionGet(t, st, token); rec.Code != http.StatusUnauthorized {
		t.Fatalf("VULNERABLE: deleted-user token usable = %d; want 401", rec.Code)
	}
}

func loginRaw(t *testing.T, st *storage.Storage, password string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"username":"u","password":%q}`, password)
	req, _ := http.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handle(loginHandler(time.Hour), "", st, &settings.Server{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d body=%q, want 200", rec.Code, rec.Body.String())
	}
	return rec
}

func authCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == "auth" {
			return c
		}
	}
	t.Fatalf("no auth cookie in %q", rec.Header().Get("Set-Cookie"))
	return nil
}

// Login must set an HttpOnly, SameSite=Strict cookie holding the token, so
// JavaScript (and XSS) cannot read it while the browser still sends it.
func TestLoginSetsHttpOnlyCookie(t *testing.T) {
	st, _ := sessionTestSetup(t)
	c := authCookie(t, loginRaw(t, st, sessionTestPassword))

	if c.Value == "" || strings.Count(c.Value, ".") != 2 {
		t.Fatalf("cookie holds no JWT: %q", c.Value)
	}
	if !c.HttpOnly {
		t.Fatalf("VULNERABLE: auth cookie without HttpOnly: %v", c)
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("auth cookie SameSite = %v, want Strict", c.SameSite)
	}
	if c.Path != "/" {
		t.Fatalf("auth cookie Path = %q, want /", c.Path)
	}
	if c.MaxAge <= 0 {
		t.Fatalf("auth cookie MaxAge = %d, want > 0", c.MaxAge)
	}

	// The cookie value is the token.
	req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("X-Auth", c.Value)
	rec := httptest.NewRecorder()
	protected := withUser(func(w http.ResponseWriter, _ *http.Request, _ *data) (int, error) {
		return 0, nil
	})
	handle(protected, "", st, &settings.Server{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cookie value as X-Auth = %d, want 200", rec.Code)
	}
}

// The cookie authenticates state-changing methods too (the browser has no
// other credential once localStorage is gone).
func TestCookieAuthenticatesPost(t *testing.T) {
	st, _ := sessionTestSetup(t)
	c := authCookie(t, loginRaw(t, st, sessionTestPassword))

	req, _ := http.NewRequest(http.MethodDelete, "/logout", http.NoBody)
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	handle(logoutHandler, "", st, &settings.Server{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cookie-only logout = %d, want 200", rec.Code)
	}
	if rec := sessionGet(t, st, c.Value); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token usable after cookie logout = %d, want 401", rec.Code)
	}
}

// Logout clears the cookie in the browser as well.
func TestLogoutClearsCookie(t *testing.T) {
	st, _ := sessionTestSetup(t)
	token := sessionLogin(t, st, sessionTestPassword)

	req, _ := http.NewRequest(http.MethodDelete, "/logout", http.NoBody)
	req.Header.Set("X-Auth", token)
	rec := httptest.NewRecorder()
	handle(logoutHandler, "", st, &settings.Server{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout = %d, want 200", rec.Code)
	}
	c := authCookie(t, rec)
	if c.Value != "" {
		t.Fatalf("logout left cookie value %q", c.Value)
	}
	if c.MaxAge >= 0 && c.Expires.IsZero() {
		t.Fatalf("logout cookie not expired: %+v", c)
	}
}

// Renew refreshes the cookie alongside the token.
func TestRenewRefreshesCookie(t *testing.T) {
	st, _ := sessionTestSetup(t)
	token := sessionLogin(t, st, sessionTestPassword)

	req, _ := http.NewRequest(http.MethodPost, "/renew", http.NoBody)
	req.Header.Set("X-Auth", token)
	rec := httptest.NewRecorder()
	handle(renewHandler(time.Hour), "", st, &settings.Server{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew = %d, want 200", rec.Code)
	}
	c := authCookie(t, rec)
	if !c.HttpOnly || c.Value == "" {
		t.Fatalf("renew did not refresh HttpOnly cookie: %+v", c)
	}
}

// /api/auth/me reports the user (never the password hash) plus the session
// expiry the frontend idle timer uses.
func TestMeEndpoint(t *testing.T) {
	st, _ := sessionTestSetup(t)
	token := sessionLogin(t, st, sessionTestPassword)

	req, _ := http.NewRequest(http.MethodGet, "/api/auth/me", http.NoBody)
	req.Header.Set("X-Auth", token)
	rec := httptest.NewRecorder()
	handle(meHandler, "", st, &settings.Server{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("me = %d body=%q, want 200", rec.Code, rec.Body.String())
	}
	var body struct {
		User      map[string]interface{} `json:"user"`
		ExpiresAt int64                  `json:"expiresAt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.User["username"] != "u" {
		t.Fatalf("me user = %v", body.User)
	}
	if body.User["password"] != "" {
		t.Fatalf("VULNERABLE: /me leaks password hash: %v", body.User["password"])
	}
	if body.ExpiresAt <= time.Now().Unix() {
		t.Fatalf("me expiresAt not in the future: %d", body.ExpiresAt)
	}

	req, _ = http.NewRequest(http.MethodGet, "/api/auth/me", http.NoBody)
	rec = httptest.NewRecorder()
	handle(meHandler, "", st, &settings.Server{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous me = %d, want 401", rec.Code)
	}
}

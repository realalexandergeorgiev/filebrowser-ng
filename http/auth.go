package fbhttp

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/golang-jwt/jwt/v5/request"
	"github.com/tomasen/realip"

	fbAuth "github.com/realalexandergeorgiev/filebrowser-ng/auth"
	fberrors "github.com/realalexandergeorgiev/filebrowser-ng/errors"
	"github.com/realalexandergeorgiev/filebrowser-ng/sessions"
	"github.com/realalexandergeorgiev/filebrowser-ng/settings"
	"github.com/realalexandergeorgiev/filebrowser-ng/users"
)

const (
	DefaultTokenExpirationTime = time.Hour * 2

	// tokenIssuer is minted into every token and verified on every request.
	// There is no audience or key ID: this is a single-issuer system and
	// the README must not claim otherwise.
	tokenIssuer = "filebrowser-ng"

	maxAuthBodySize = 1 << 20 // 1 MiB

	// Unauthenticated password-spray budgets per TCP peer and minute.
	maxLoginAttempts         = 10
	maxSignupAttempts        = 10
	maxSharePasswordAttempts = 30
	rateLimitWindow          = time.Minute
)

type userInfo struct {
	ID                    uint              `json:"id"`
	Locale                string            `json:"locale"`
	ViewMode              users.ViewMode    `json:"viewMode"`
	SingleClick           bool              `json:"singleClick"`
	RedirectAfterCopyMove bool              `json:"redirectAfterCopyMove"`
	Perm                  users.Permissions `json:"perm"`
	Commands              []string          `json:"commands"`
	LockPassword          bool              `json:"lockPassword"`
	HideDotfiles          bool              `json:"hideDotfiles"`
	DateFormat            bool              `json:"dateFormat"`
	Username              string            `json:"username"`
	AceEditorTheme        string            `json:"aceEditorTheme"`
}

type authToken struct {
	User userInfo `json:"user"`
	jwt.RegisteredClaims
}

type extractor []string

func (e extractor) ExtractToken(r *http.Request) (string, error) {
	token, _ := request.HeaderExtractor{"X-Auth"}.ExtractToken(r)

	// Checks if the token isn't empty and if it contains two dots.
	// The former prevents incompatibility with URLs that previously
	// used basic auth.
	if token != "" && strings.Count(token, ".") == 2 {
		return token, nil
	}

	// The browser holds the token in an HttpOnly cookie instead of
	// JavaScript storage, so XSS cannot steal it. SameSite=Strict plus no
	// CORS keeps cross-site requests from carrying it (see loginHandler).
	if cookie, _ := r.Cookie("auth"); cookie != nil && strings.Count(cookie.Value, ".") == 2 {
		return cookie.Value, nil
	}

	return "", request.ErrNoTokenInRequest
}

func renewableErr(err error, r *http.Request, d *data, tk *authToken) bool {
	if d.settings.AuthMethod != fbAuth.MethodProxyAuth || err == nil {
		return false
	}

	if d.settings.LogoutPage == settings.DefaultLogoutPage {
		return false
	}

	if !errors.Is(err, jwt.ErrTokenExpired) {
		return false
	}

	// The expiration is only waived because the trusted proxy, not the token,
	// decides when the session ends. Require the proxy to still assert the same
	// identity on this request, otherwise a token that leaked before it expired
	// would authenticate on its own forever.
	return proxyAsserts(r, d, tk.User.ID)
}

// proxyAsserts reports whether the proxy-auth header on r identifies the user
// the token was issued for. The username is resolved through the user store, so
// that it is matched exactly as a regular proxy login would match it.
func proxyAsserts(r *http.Request, d *data, id uint) bool {
	// The waiver is worthless if anyone off-proxy can spoof the header:
	// require the request to arrive via a trusted proxy peer first.
	if !fbAuth.TrustedProxyPeer(r, d.server.TrustedProxies) {
		return false
	}
	auther, err := d.store.Auth.Get(fbAuth.MethodProxyAuth)
	if err != nil {
		return false
	}

	proxy, ok := auther.(*fbAuth.ProxyAuth)
	if !ok || proxy.Header == "" {
		return false
	}

	username := r.Header.Get(proxy.Header)
	if username == "" {
		return false
	}

	user, err := d.store.Users.Get(d.server.Root, d.server.FollowExternalSymlinks, username)
	if err != nil {
		return false
	}

	return user.ID == id
}

// presentedToken mirrors extractor: it reports whether the request carries
// something shaped like a token, as opposed to no credential at all.
func presentedToken(r *http.Request) bool {
	if h := r.Header.Get("X-Auth"); h != "" && strings.Count(h, ".") == 2 {
		return true
	}
	if c, _ := r.Cookie("auth"); c != nil && strings.Count(c.Value, ".") == 2 {
		return true
	}
	return false
}

func withUser(fn handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		keyFunc := func(_ *jwt.Token) (interface{}, error) {
			return d.settings.Key, nil
		}

		var tk authToken
		p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithExpirationRequired(), jwt.WithIssuer(tokenIssuer))
		token, err := request.ParseFromRequest(r, &extractor{}, keyFunc, request.WithClaims(&tk), request.WithParser(p))
		if (err != nil || !token.Valid) && !renewableErr(err, r, d, &tk) {
			// Only forged tokens count towards a ban: missing, malformed or
			// expired tokens (and sessions that lapsed server-side) are
			// normal client state, not guessing. A bad signature means
			// someone mints tokens without the signing key.
			if presentedToken(r) && errors.Is(err, jwt.ErrTokenSignatureInvalid) {
				ipBans.fail(banKey(r, d.server.TrustedProxies))
			}
			return http.StatusUnauthorized, nil
		}

		// The token is only a bearer pointer: the session must exist
		// server-side, belong to the token's user and still be live.
		// Unknown, foreign or expired sessions are refused, so logout,
		// password/security changes and user deletion take effect at once.
		// Tokens issued before server-side sessions existed carry no jti
		// and are rejected: upgrade logs everyone out once.
		if tk.ID == "" {
			return http.StatusUnauthorized, nil
		}
		sess, err := d.store.Sessions.Get(tk.ID)
		if err != nil || sess.UserID != tk.User.ID || sess.Expired(time.Now()) {
			if err == nil {
				_ = d.store.Sessions.Revoke(tk.ID)
			}
			return http.StatusUnauthorized, nil
		}
		d.sessionJTI = tk.ID

		expiresSoon := tk.ExpiresAt != nil && time.Until(tk.ExpiresAt.Time) < time.Hour
		updated := tk.IssuedAt != nil && tk.IssuedAt.Unix() < d.store.Users.LastUpdate(tk.User.ID)

		if expiresSoon || updated {
			w.Header().Add("X-Renew-Token", "true")
		}

		d.user, err = d.store.Users.Get(d.server.Root, d.server.FollowExternalSymlinks, tk.User.ID)
		if errors.Is(err, fberrors.ErrNotExist) {
			return http.StatusUnauthorized, nil
		}
		if err != nil {
			return http.StatusInternalServerError, err
		}

		canonicalizeRequestPath(r)
		return fn(w, r, d)
	}
}

func withAdmin(fn handleFunc) handleFunc {
	return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if !d.user.Perm.Admin {
			return http.StatusForbidden, nil
		}

		return fn(w, r, d)
	})
}

// setAuthCookie stores the access token where JavaScript cannot read it.
// Secure is set on TLS connections; plain-HTTP instances (loopback, or TLS
// terminated at a reverse proxy) still work without it.
func setAuthCookie(w http.ResponseWriter, r *http.Request, token string, maxAge time.Duration) {
	c := &http.Cookie{
		Name:     "auth",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(maxAge.Seconds()),
	}
	if r.TLS != nil {
		c.Secure = true
	}
	http.SetCookie(w, c)
}

func clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
	})
}

func loginHandler(tokenExpireTime time.Duration) handleFunc {
	limit := newRateLimiter(maxLoginAttempts, rateLimitWindow)
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if !limit.check(w, r) {
			return http.StatusTooManyRequests, nil
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxAuthBodySize)
		}

		auther, err := d.store.Auth.Get(d.settings.AuthMethod)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		user, err := auther.Auth(r, d.store.Users, d.settings, d.server)
		switch {
		case errors.Is(err, os.ErrPermission):
			ipBans.fail(banKey(r, d.server.TrustedProxies))
			return http.StatusForbidden, nil
		case err != nil:
			return http.StatusInternalServerError, err
		}

		// A successful login proves legitimacy and clears the peer's record.
		ipBans.reset(banKey(r, d.server.TrustedProxies))
		log.Printf("login: user %q from %s", user.Username, realip.FromRequest(r))

		sess, err := d.store.Sessions.Create(user.ID, tokenExpireTime)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		return printToken(w, r, d, user, tokenExpireTime, sess.JTI)
	}
}

// logoutHandler revokes the session backing the request token and clears
// the cookie. Afterwards the token is refused even though its signature is
// still valid.
var logoutHandler = withUser(func(w http.ResponseWriter, _ *http.Request, d *data) (int, error) {
	// Idempotent: logging out twice is not an error.
	if err := d.store.Sessions.Revoke(d.sessionJTI); err != nil {
		return http.StatusInternalServerError, err
	}
	clearAuthCookie(w)
	return http.StatusOK, nil
})

// meHandler reports the logged-in user (without the password hash) plus the
// session expiry the frontend uses for its idle timer. It is the only user
// lookup the cookie flow needs after login.
var meHandler = withUser(func(w http.ResponseWriter, _ *http.Request, d *data) (int, error) {
	sess, err := d.store.Sessions.Get(d.sessionJTI)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	u := *d.user
	u.Password = ""
	return renderJSON(w, nil, map[string]interface{}{
		"user":      &u,
		"expiresAt": sess.ExpiresAt,
	})
})

type signupBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func signupHandler() handleFunc {
	limit := newRateLimiter(maxSignupAttempts, rateLimitWindow)
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if !limit.check(w, r) {
			return http.StatusTooManyRequests, nil
		}
		return signup(w, r, d)
	}
}

var signup = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if !d.settings.Signup {
		return http.StatusMethodNotAllowed, nil
	}

	if r.Body == nil {
		return http.StatusBadRequest, nil
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBodySize)

	info := &signupBody{}
	err := json.NewDecoder(r.Body).Decode(info)
	if err != nil {
		return http.StatusBadRequest, err
	}

	if info.Password == "" || info.Username == "" {
		return http.StatusBadRequest, nil
	}

	user := &users.User{
		Username: info.Username,
	}

	d.settings.Defaults.Apply(user)

	// Users signed up via the signup handler should never become admins, even
	// if that is the default permission.
	user.Perm.Admin = false

	// Self-registered users should not inherit execution capabilities from
	// default settings, regardless of what the administrator has configured
	// as the default. Execution rights must be explicitly granted by an admin.
	user.Perm.Execute = false
	user.Commands = []string{}

	pwd, err := users.ValidateAndHashPwd(info.Password, d.settings.MinimumPasswordLength)
	if err != nil {
		return http.StatusBadRequest, err
	}

	user.Password = pwd

	derivedScope, err := d.settings.CreateUserHome(user, d.server.Root, false)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	log.Printf("new user: %q, home dir: [%q].", user.Username, user.Scope)

	err = d.store.Users.SaveProvisioned(user, derivedScope)
	if errors.Is(err, fberrors.ErrExist) {
		return http.StatusConflict, err
	} else if err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func renewHandler(tokenExpireTime time.Duration) handleFunc {
	return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		w.Header().Set("X-Renew-Token", "false")
		// Slide the session within its max lifetime; past it the user must
		// log in again even with a cryptographically valid token.
		if _, err := d.store.Sessions.Touch(d.sessionJTI, tokenExpireTime); err != nil {
			if errors.Is(err, fberrors.ErrNotExist) || errors.Is(err, sessions.ErrExpired) {
				return http.StatusUnauthorized, nil
			}
			return http.StatusInternalServerError, err
		}
		return printToken(w, r, d, d.user, tokenExpireTime, d.sessionJTI)
	})
}

func printToken(w http.ResponseWriter, r *http.Request, d *data, user *users.User, tokenExpirationTime time.Duration, jti string) (int, error) {
	claims := &authToken{
		User: userInfo{
			ID:                    user.ID,
			Locale:                user.Locale,
			ViewMode:              user.ViewMode,
			SingleClick:           user.SingleClick,
			RedirectAfterCopyMove: user.RedirectAfterCopyMove,
			Perm:                  user.Perm,
			LockPassword:          user.LockPassword,
			Commands:              user.Commands,
			HideDotfiles:          user.HideDotfiles,
			DateFormat:            user.DateFormat,
			Username:              user.Username,
			AceEditorTheme:        user.AceEditorTheme,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpirationTime)),
			Issuer:    tokenIssuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(d.settings.Key)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	setAuthCookie(w, r, signed, tokenExpirationTime)
	w.Header().Set("Content-Type", "text/plain")
	if _, err := w.Write([]byte(signed)); err != nil {
		return http.StatusInternalServerError, err
	}
	return 0, nil
}

package auth

import (
	"net/http"
	"strings"
	"testing"

	fberrors "github.com/realalexandergeorgiev/filebrowser-ng/errors"
	"github.com/realalexandergeorgiev/filebrowser-ng/settings"
	"github.com/realalexandergeorgiev/filebrowser-ng/users"
)

type mockUserStore struct {
	users map[string]*users.User
}

func (m *mockUserStore) Get(_ string, _ bool, id interface{}) (*users.User, error) {
	if v, ok := id.(string); ok {
		if u, ok := m.users[v]; ok {
			return u, nil
		}
	}
	return nil, fberrors.ErrNotExist
}

func (m *mockUserStore) GetByScope(scope string) (*users.User, error) {
	for _, u := range m.users {
		if strings.EqualFold(u.Scope, scope) {
			return u, nil
		}
	}
	return nil, fberrors.ErrNotExist
}

func (m *mockUserStore) Gets(_ string, _ bool) ([]*users.User, error) { return nil, nil }
func (m *mockUserStore) Update(_ *users.User, _ ...string) error      { return nil }
func (m *mockUserStore) Save(user *users.User) error {
	m.users[user.Username] = user
	return nil
}

func (m *mockUserStore) SaveProvisioned(user *users.User, derivedScope bool) error {
	if derivedScope {
		if _, err := m.GetByScope(user.Scope); err == nil {
			return fberrors.ErrExist
		}
	}
	return m.Save(user)
}

func (m *mockUserStore) Delete(_ interface{}) error { return nil }
func (m *mockUserStore) LastUpdate(_ uint) int64    { return 0 }

func TestProxyAuthCreateUserRestrictsDefaults(t *testing.T) {
	t.Parallel()

	store := &mockUserStore{users: make(map[string]*users.User)}
	srv := &settings.Server{Root: t.TempDir()}

	s := &settings.Settings{
		Key:        []byte("key"),
		AuthMethod: MethodProxyAuth,
		Defaults: settings.UserDefaults{
			Perm: users.Permissions{
				Admin:    true,
				Execute:  true,
				Create:   true,
				Rename:   true,
				Modify:   true,
				Delete:   true,
				Share:    true,
				Download: true,
			},
			Commands: []string{"git", "ls", "cat", "id"},
		},
	}

	auth := ProxyAuth{Header: "X-Remote-User"}
	req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Remote-User", "newproxyuser")

	user, err := auth.Auth(req, store, s, srv)
	if err != nil {
		t.Fatalf("Auth() error: %v", err)
	}

	if user.Perm.Admin {
		t.Error("auto-provisioned proxy user should not have Admin permission")
	}
	if user.Perm.Execute {
		t.Error("auto-provisioned proxy user should not have Execute permission")
	}
	if len(user.Commands) != 0 {
		t.Errorf("auto-provisioned proxy user should have empty Commands, got %v", user.Commands)
	}
	if !user.Perm.Create {
		t.Error("auto-provisioned proxy user should retain Create permission from defaults")
	}
}

// Proxy auth must fail closed: the header is only honored from trusted
// peers (loopback by default, configured CIDRs/IPs otherwise), so a
// bypassed proxy no longer means admin access (GO-2026-5966).
func TestProxyAuthRejectsUntrustedPeer(t *testing.T) {
	t.Parallel()

	newReq := func(remoteAddr string) *http.Request {
		req, _ := http.NewRequest(http.MethodPost, "/api/login", http.NoBody)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Remote-User", "admin")
		return req
	}
	login := func(t *testing.T, srv *settings.Server, remoteAddr string) error {
		t.Helper()
		store := &mockUserStore{users: make(map[string]*users.User)}
		s := &settings.Settings{
			Key:                   []byte("key"),
			AuthMethod:            MethodProxyAuth,
			MinimumPasswordLength: 1,
		}
		_, err := ProxyAuth{Header: "X-Remote-User"}.Auth(newReq(remoteAddr), store, s, srv)
		return err
	}
	loopbackSrv := &settings.Server{Root: t.TempDir()}

	for _, remoteAddr := range []string{"", "203.0.113.5:443", "not-an-ip", "[::ffff:203.0.113.5]:443"} {
		if err := login(t, loopbackSrv, remoteAddr); err == nil {
			t.Errorf("Auth from %q succeeded with default trust; want rejection", remoteAddr)
		}
	}
	if err := login(t, loopbackSrv, "127.0.0.1:1234"); err != nil {
		t.Errorf("Auth from loopback with default trust = %v; want success", err)
	}
	if err := login(t, loopbackSrv, "[::1]:1234"); err != nil {
		t.Errorf("Auth from ::1 with default trust = %v; want success", err)
	}

	// A forged X-Forwarded-For must not smuggle an untrusted peer in.
	spoofed := newReq("203.0.113.5:443")
	spoofed.Header.Set("X-Forwarded-For", "127.0.0.1")
	store := &mockUserStore{users: make(map[string]*users.User)}
	s := &settings.Settings{Key: []byte("key"), AuthMethod: MethodProxyAuth, MinimumPasswordLength: 1}
	auther := ProxyAuth{Header: "X-Remote-User"}
	if _, err := auther.Auth(spoofed, store, s, loopbackSrv); err == nil {
		t.Errorf("Auth with spoofed X-Forwarded-For succeeded; want rejection")
	}

	cidrSrv := &settings.Server{Root: t.TempDir(), TrustedProxies: []string{"10.0.0.0/8", "198.51.100.7", "garbage["}}
	if err := login(t, cidrSrv, "10.1.2.3:80"); err != nil {
		t.Errorf("Auth from configured CIDR = %v; want success", err)
	}
	if err := login(t, cidrSrv, "198.51.100.7:80"); err != nil {
		t.Errorf("Auth from configured IP = %v; want success", err)
	}
	if err := login(t, cidrSrv, "127.0.0.1:1234"); err == nil {
		t.Errorf("Auth from loopback with explicit trust list succeeded; want rejection")
	}
	if err := login(t, cidrSrv, "11.0.0.1:80"); err == nil {
		t.Errorf("Auth from outside the CIDR succeeded; want rejection")
	}
}

func TestTrustedProxyPeer(t *testing.T) {
	t.Parallel()

	req := func(remoteAddr string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
		r.RemoteAddr = remoteAddr
		return r
	}
	for _, tc := range []struct {
		name    string
		trusted []string
		peer    string
		want    bool
	}{
		{"loopback default", nil, "127.0.0.1:1", true},
		{"loopback range default", nil, "127.0.0.2:1", true},
		{"ipv6 loopback default", nil, "[::1]:1", true},
		{"public default", nil, "203.0.113.5:1", false},
		{"empty peer", nil, "", false},
		{"no port peer", []string{"10.0.0.0/8"}, "10.9.9.9", true},
		{"cidr match", []string{"10.0.0.0/8"}, "10.9.9.9:1", true},
		{"cidr miss", []string{"10.0.0.0/8"}, "11.0.0.1:1", false},
		{"exact ip", []string{"198.51.100.7"}, "198.51.100.7:443", true},
		{"garbage entry ignored", []string{"garbage[", "10.0.0.0/8"}, "10.1.1.1:1", true},
		{"ipv4-mapped loopback", nil, "[::ffff:127.0.0.1]:1", true},
	} {
		if got := TrustedProxyPeer(req(tc.peer), tc.trusted); got != tc.want {
			t.Errorf("%s: TrustedProxyPeer(%q) = %v, want %v", tc.name, tc.peer, got, tc.want)
		}
	}
}

// With CreateUserDir enabled, two distinct proxy-authenticated users must each
// receive their own home directory instead of both inheriting the server root.
func TestProxyAuthCreateUserDirIsolatesScope(t *testing.T) {
	t.Parallel()

	store := &mockUserStore{users: make(map[string]*users.User)}
	srv := &settings.Server{Root: t.TempDir()}
	s := &settings.Settings{
		Key:              []byte("key"),
		AuthMethod:       MethodProxyAuth,
		CreateUserDir:    true,
		UserHomeBasePath: "/users",
		Defaults: settings.UserDefaults{
			Scope: ".",
			Perm:  users.Permissions{Create: true},
		},
	}

	auth := ProxyAuth{Header: "X-Remote-User"}
	provision := func(name string) *users.User {
		req, _ := http.NewRequest(http.MethodGet, "/", http.NoBody)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("X-Remote-User", name)
		u, err := auth.Auth(req, store, s, srv)
		if err != nil {
			t.Fatalf("Auth(%q) error: %v", name, err)
		}
		return u
	}

	alice := provision("alice")
	bob := provision("bob")

	if alice.Scope == "/" || bob.Scope == "/" {
		t.Fatalf("provisioned users inherited the server root: alice=%q bob=%q", alice.Scope, bob.Scope)
	}
	if alice.Scope == bob.Scope {
		t.Fatalf("distinct users must get distinct scopes, both got %q", alice.Scope)
	}
	if alice.Scope != "/users/alice" {
		t.Errorf("expected /users/alice, got %q", alice.Scope)
	}
}

package auth

import (
	"errors"
	"net"
	"net/http"
	"os"
	"strings"

	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

// MethodProxyAuth is used to identify no auth.
const MethodProxyAuth settings.AuthMethod = "proxy"

// ProxyAuth is a proxy implementation of an auther.
type ProxyAuth struct {
	Header string `json:"header"`
}

// Auth authenticates the user via an HTTP header. The header is only
// honored when the request arrived via a trusted proxy (see
// TrustedProxyPeer); otherwise anyone reaching the app directly could
// attach the header and log in as any user, including an admin.
func (a ProxyAuth) Auth(r *http.Request, usr users.Store, setting *settings.Settings, srv *settings.Server) (*users.User, error) {
	if !TrustedProxyPeer(r, srv.TrustedProxies) {
		return nil, os.ErrPermission
	}
	username := r.Header.Get(a.Header)
	user, err := usr.Get(srv.Root, srv.FollowExternalSymlinks, username)
	if errors.Is(err, fberrors.ErrNotExist) {
		return a.createUser(usr, setting, srv, username)
	}
	return user, err
}

func (a ProxyAuth) createUser(usr users.Store, setting *settings.Settings, srv *settings.Server, username string) (*users.User, error) {
	const randomPasswordLength = settings.DefaultMinimumPasswordLength + 10
	pwd, err := users.RandomPwd(randomPasswordLength)
	if err != nil {
		return nil, err
	}

	var hashedRandomPassword string
	hashedRandomPassword, err = users.ValidateAndHashPwd(pwd, setting.MinimumPasswordLength)
	if err != nil {
		return nil, err
	}

	user := &users.User{
		Username:     username,
		Password:     hashedRandomPassword,
		LockPassword: true,
	}
	setting.Defaults.Apply(user)
	user.Perm.Admin = false
	user.Perm.Execute = false
	user.Commands = []string{}

	var derivedScope bool
	if derivedScope, err = setting.CreateUserHome(user, srv.Root, false); err != nil {
		return nil, err
	}

	if err = usr.SaveProvisioned(user, derivedScope); err != nil {
		return nil, err
	}

	return user, nil
}

// TrustedProxyPeer reports whether r arrived via a trusted proxy. Entries
// are plain IPs or CIDRs matched against the direct TCP peer; forwarded
// headers are deliberately ignored because clients can spoof them. An empty
// list trusts loopback only, so proxy auth keeps working for a co-located
// proxy while direct exposure authenticates nobody.
func TrustedProxyPeer(r *http.Request, trusted []string) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	if len(trusted) == 0 {
		trusted = []string{"127.0.0.0/8", "::1/128"}
	}
	for _, entry := range trusted {
		entry = strings.TrimSpace(entry)
		if strings.Contains(entry, "/") {
			_, cidr, err := net.ParseCIDR(entry)
			if err != nil {
				continue
			}
			if cidr.Contains(ip) {
				return true
			}
			continue
		}
		if ip.Equal(net.ParseIP(entry)) {
			return true
		}
	}
	return false
}

// LoginPage tells that proxy auth doesn't require a login page.
func (a ProxyAuth) LoginPage() bool {
	return false
}

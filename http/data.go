package fbhttp

import (
	"log"
	"net/http"
	gopath "path"
	"strconv"

	"github.com/tomasen/realip"

	"github.com/realalexandergeorgiev/filebrowser-ng/rules"
	"github.com/realalexandergeorgiev/filebrowser-ng/settings"
	"github.com/realalexandergeorgiev/filebrowser-ng/storage"
	"github.com/realalexandergeorgiev/filebrowser-ng/users"
)

type handleFunc func(w http.ResponseWriter, r *http.Request, d *data) (int, error)

type data struct {
	settings *settings.Settings
	server   *settings.Server
	store    *storage.Storage
	user     *users.User
	raw      interface{}

	// sessionJTI is the server-side session backing the request's access
	// token, verified by withUser. Handlers use it for renew and logout.
	sessionJTI string

	// checkerPrefix is prepended to every path before evaluating rules. It is
	// set when the user's filesystem has been rebased onto a subdirectory (as
	// done for public shares), so that rules — which are relative to the user's
	// original scope — are still matched against the real path instead of the
	// rebased one. Empty for regular requests.
	checkerPrefix string
}

// Check implements rules.Checker.
func (d *data) Check(path string) bool {
	if d.user.HideDotfiles && rules.MatchHidden(d.rulePath(path)) {
		return false
	}

	return d.CheckRules(path)
}

// CheckRules reports whether the global and user rules allow path. Unlike
// Check, it ignores HideDotfiles: hiding dotfiles is a display preference, so
// it must not stop a user from operating on a tree that contains one.
func (d *data) CheckRules(path string) bool {
	path = d.rulePath(path)

	allow := true
	for _, rule := range d.settings.Rules {
		if rule.Matches(path, d.server.CaseInsensitiveFs) {
			allow = rule.Allow
		}
	}

	for _, rule := range d.user.Rules {
		if rule.Matches(path, d.server.CaseInsensitiveFs) {
			allow = rule.Allow
		}
	}

	return allow
}

// rulePath canonicalizes path into the form the rules are written in.
func (d *data) rulePath(path string) string {
	// Rules are written as "/"-separated virtual paths, but callers hand us
	// paths built by the OS as well as ones taken from the request: afero.Walk
	// and filepath.Join use "\" on Windows, where the filesystem also treats it
	// as a separator. Canonicalize first so the authorization decision does not
	// depend on which separator the caller happened to use.
	path = slashClean(path)

	// When the filesystem has been rebased (e.g. a public share rooted at a
	// subdirectory), the incoming path is relative to that root. Resolve it
	// back to the user's original scope before matching rules, otherwise rules
	// targeting paths below the share root would be silently bypassed.
	if d.checkerPrefix != "" {
		path = gopath.Join(d.checkerPrefix, path)
	}

	return path
}

// formatRequestLog renders one rejected-request log line. Expected rejections
// (wrong credentials, missing token, ...) carry no error, so the line omits
// the trailing field instead of printing a confusing "<nil>".
func formatRequestLog(path string, status int, clientIP string, err error) string {
	if err != nil {
		return path + ": " + strconv.Itoa(status) + " " + clientIP + " " + err.Error()
	}
	return path + ": " + strconv.Itoa(status) + " " + clientIP
}

func handle(fn handleFunc, prefix string, store *storage.Storage, server *settings.Server) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range globalHeaders {
			w.Header().Set(k, v)
		}

		// Banned peers are refused before anything else: no settings load,
		// no auth parsing, no handler work.
		if !ipBans.check(w, r, server.TrustedProxies) {
			http.Error(w, strconv.Itoa(http.StatusTooManyRequests)+" "+http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		settings, err := store.Settings.Get()
		if err != nil {
			log.Fatalf("ERROR: couldn't get settings: %v\n", err)
			return
		}

		status, err := fn(w, r, &data{
			store:    store,
			settings: settings,
			server:   server,
		})

		if status >= 400 || err != nil {
			clientIP := realip.FromRequest(r)
			log.Print(formatRequestLog(r.URL.Path, status, clientIP, err))
		}

		if status != 0 {
			txt := http.StatusText(status)
			if status == http.StatusBadRequest && err != nil {
				txt += " (" + err.Error() + ")"
			}
			http.Error(w, strconv.Itoa(status)+" "+txt, status)
			return
		}
	})

	return stripPrefix(prefix, handler)
}

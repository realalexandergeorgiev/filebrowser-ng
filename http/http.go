package fbhttp

import (
	"io/fs"
	"net/http"
	"sort"
	"strings"

	"github.com/spf13/afero"

	"github.com/filebrowser/filebrowser/v2/files"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/storage"
)

type modifyRequest struct {
	What            string   `json:"what"`             // Answer to: what data type?
	Which           []string `json:"which"`            // Answer to: which fields?
	CurrentPassword string   `json:"current_password"` // Answer to: user logged password
}

func NewHandler(
	imgSvc ImgService,
	fileCache FileCache,
	uploadCache UploadCache,
	store *storage.Storage,
	server *settings.Server,
	assetsFs fs.FS,
) (http.Handler, error) {
	server.Clean()
	server.CaseInsensitiveFs = files.CaseInsensitive(afero.NewOsFs(), server.Root)

	mux := http.NewServeMux()
	index, static := getStaticHandlers(store, server, assetsFs)

	monkey := func(fn handleFunc, prefix string) http.Handler {
		return handle(fn, prefix, store, server)
	}
	// Prefix routes need both the bare path (root operations) and the
	// subtree, mirroring the old PathPrefix behavior.
	route := func(prefix string, routes map[string]http.Handler) {
		h := switchMethod(routes)
		mux.Handle(prefix, h)
		mux.Handle(prefix+"/", h)
	}

	mux.Handle("/health", http.HandlerFunc(healthHandler))
	mux.Handle("/static/", static)
	mux.Handle("/", index)

	tokenExpirationTime := server.GetTokenExpirationTime(DefaultTokenExpirationTime)
	mux.Handle("/api/login", monkey(loginHandler(tokenExpirationTime), ""))
	mux.Handle("/api/logout", requireMethod(monkey(logoutHandler, ""), "DELETE"))
	mux.Handle("/api/signup", monkey(signupHandler(), ""))
	mux.Handle("/api/renew", monkey(renewHandler(tokenExpirationTime), ""))

	mux.Handle("/api/users", switchMethod(map[string]http.Handler{
		"GET":  monkey(usersGetHandler, ""),
		"POST": monkey(userPostHandler, ""),
	}))
	mux.Handle("/api/users/{id}", switchMethod(map[string]http.Handler{
		"PUT":    monkey(userPutHandler, ""),
		"GET":    monkey(userGetHandler, ""),
		"DELETE": monkey(userDeleteHandler, ""),
	}))

	route("/api/resources/recursive", map[string]http.Handler{
		"GET": monkey(resourceGetRecursiveHandler, "/api/resources/recursive"),
	})
	route("/api/resources", map[string]http.Handler{
		"GET":    monkey(resourceGetHandler, "/api/resources"),
		"DELETE": monkey(resourceDeleteHandler(fileCache), "/api/resources"),
		"POST":   monkey(resourcePostHandler(fileCache), "/api/resources"),
		"PUT":    monkey(resourcePutHandler, "/api/resources"),
		"PATCH":  monkey(resourcePatchHandler(fileCache), "/api/resources"),
	})

	route("/api/tus", map[string]http.Handler{
		"POST":   monkey(tusPostHandler(uploadCache), "/api/tus"),
		"HEAD":   monkey(tusHeadHandler(uploadCache), "/api/tus"),
		"GET":    monkey(tusHeadHandler(uploadCache), "/api/tus"),
		"PATCH":  monkey(tusPatchHandler(uploadCache), "/api/tus"),
		"DELETE": monkey(tusDeleteHandler(uploadCache, fileCache), "/api/tus"),
	})

	route("/api/usage", map[string]http.Handler{
		"GET": monkey(diskUsage, "/api/usage"),
	})

	mux.Handle("/api/shares", requireMethod(monkey(shareListHandler, ""), "GET"))
	route("/api/share", map[string]http.Handler{
		"GET":    monkey(shareGetsHandler, "/api/share"),
		"POST":   monkey(sharePostHandler, "/api/share"),
		"DELETE": monkey(shareDeleteHandler, "/api/share"),
	})

	mux.Handle("/api/settings", switchMethod(map[string]http.Handler{
		"GET": monkey(settingsGetHandler, ""),
		"PUT": monkey(settingsPutHandler, ""),
	}))

	route("/api/raw", map[string]http.Handler{
		"GET": monkey(rawHandler, "/api/raw"),
	})
	mux.Handle("/api/preview/{size}/{path...}", switchMethod(map[string]http.Handler{
		"GET": monkey(previewHandler(imgSvc, fileCache, server.EnableThumbnails, server.ResizePreview), "/api/preview"),
	}))
	route("/api/search", map[string]http.Handler{
		"GET": monkey(searchHandler, "/api/search"),
	})
	route("/api/subtitle", map[string]http.Handler{
		"GET": monkey(subtitleHandler, "/api/subtitle"),
	})

	route("/api/public/dl", map[string]http.Handler{
		"GET": monkey(publicDlHandler, "/api/public/dl/"),
	})
	route("/api/public/share", map[string]http.Handler{
		"GET": monkey(publicShareHandler, "/api/public/share/"),
	})

	return stripPrefix(server.BaseURL, secureHeaders(mux)), nil
}

// switchMethod dispatches one path to per-verb handlers and answers 405
// with an Allow header otherwise. This preserves the old router's method
// semantics: the stdlib mux would fall through to the catch-all index page
// on method mismatch instead.
func switchMethod(routes map[string]http.Handler) http.Handler {
	allow := make([]string, 0, len(routes))
	for verb := range routes {
		allow = append(allow, verb)
	}
	sort.Strings(allow)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := routes[r.Method]; ok {
			h.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Allow", strings.Join(allow, ", "))
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	})
}

// requireMethod is switchMethod for a single verb.
func requireMethod(h http.Handler, verb string) http.Handler {
	return switchMethod(map[string]http.Handler{verb: h})
}

// secureHeaders is the baseline hardening for every response (raw/subtitle
// tighten script-src further for untrusted file content). frame-ancestors
// blocks clickjacking; object-src/base-uri close plugin and base-tag
// injection; no-referrer keeps share ?token= URLs and paths out of Referer
// headers to third parties.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", `default-src 'self'; style-src 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'`)
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

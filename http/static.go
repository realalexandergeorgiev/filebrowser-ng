package fbhttp

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/realalexandergeorgiev/filebrowser-ng/auth"
	"github.com/realalexandergeorgiev/filebrowser-ng/settings"
	"github.com/realalexandergeorgiev/filebrowser-ng/storage"
	"github.com/realalexandergeorgiev/filebrowser-ng/version"
)

// newNonce returns a fresh CSP nonce for the inline bootstrap script. Using a
// nonce lets the app shell run its one inline <script> while keeping
// `script-src` strict ('self' + nonce) instead of enabling 'unsafe-inline'.
func newNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("filebrowser-ng: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// indexCSP is the baseline policy hardened for the app shell: scripts only
// from self or the per-request nonce; styles from self plus inline (Vue sets
// inline style attributes at runtime).
func indexCSP(nonce string) string {
	return "default-src 'self'; " +
		"script-src 'self' 'nonce-" + nonce + "'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data: blob:; " +
		"font-src 'self' data:; " +
		"manifest-src 'self' blob:; " +
		"object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
}

func handleWithStaticData(w http.ResponseWriter, _ *http.Request, d *data, fSys fs.FS, file, contentType string) (int, error) {
	w.Header().Set("Content-Type", contentType)

	nonce := newNonce()
	w.Header().Set("Content-Security-Policy", indexCSP(nonce))

	auther, err := d.store.Auth.Get(d.settings.AuthMethod)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	data := map[string]interface{}{
		"Nonce":                 nonce,
		"Name":                  d.settings.Branding.Name,
		"DisableExternal":       d.settings.Branding.DisableExternal,
		"DisableUsedPercentage": d.settings.Branding.DisableUsedPercentage,
		"Color":                 d.settings.Branding.Color,
		"BaseURL":               d.server.BaseURL,
		"Version":               version.Version,
		"StaticURL":             path.Join(d.server.BaseURL, "/static"),
		"Signup":                d.settings.Signup,
		"NoAuth":                d.settings.AuthMethod == auth.MethodNoAuth,
		"AuthMethod":            d.settings.AuthMethod,
		"LogoutPage":            d.settings.LogoutPage,
		"LoginPage":             auther.LoginPage(),
		"CSS":                   false,
		"ReCaptcha":             false,
		"Theme":                 d.settings.Branding.Theme,
		"EnableThumbs":          d.server.EnableThumbnails,
		"ResizePreview":         d.server.ResizePreview,
		"TusSettings":           d.settings.Tus,
		"HideLoginButton":       d.settings.HideLoginButton,
	}

	if d.settings.Branding.Files != "" {
		fPath := filepath.Join(d.settings.Branding.Files, "custom.css")
		_, err := os.Stat(fPath)

		if err != nil && !os.IsNotExist(err) {
			log.Printf("couldn't load custom styles: %v", err)
		}

		if err == nil {
			data["CSS"] = true
		}
	}

	if d.settings.AuthMethod == auth.MethodJSONAuth {
		raw, err := d.store.Auth.Get(d.settings.AuthMethod)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		auther := raw.(*auth.JSONAuth)

		if auther.ReCaptcha != nil {
			data["ReCaptcha"] = auther.ReCaptcha.Key != "" && auther.ReCaptcha.Secret != ""
			data["ReCaptchaHost"] = auther.ReCaptcha.Host
			data["ReCaptchaKey"] = auther.ReCaptcha.Key
		}
	}

	b, err := json.Marshal(data)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	data["Json"] = template.JS(strings.ReplaceAll(string(b), `'`, `\'`))

	fileContents, err := fs.ReadFile(fSys, file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return http.StatusNotFound, err
		}
		return http.StatusInternalServerError, err
	}
	index := template.Must(template.New("index").Delims("[{[", "]}]").Parse(string(fileContents)))
	err = index.Execute(w, data)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	return 0, nil
}

// brandingFile resolves a static override request path (e.g. "img/logo.png"
// or "custom.css") inside the branding directory. It returns false when the
// request would escape it (e.g. "img/../../secret"), so callers fall through
// to the embedded assets instead of serving arbitrary host files.
func brandingFile(brandingDir, reqPath string) (string, bool) {
	if brandingDir == "" || reqPath == "" {
		return "", false
	}
	cleaned := filepath.Join(brandingDir, filepath.FromSlash(reqPath))
	rel, err := filepath.Rel(brandingDir, cleaned)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return cleaned, true
}

func getStaticHandlers(store *storage.Storage, server *settings.Server, assetsFs fs.FS) (index, static http.Handler) {
	index = handle(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if r.Method != http.MethodGet {
			return http.StatusNotFound, nil
		}

		w.Header().Set("x-xss-protection", "1; mode=block")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		return handleWithStaticData(w, r, d, assetsFs, "public/index.html", "text/html; charset=utf-8")
	}, "", store, server)

	static = handle(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if r.Method != http.MethodGet {
			return http.StatusNotFound, nil
		}

		if strings.HasSuffix(r.URL.Path, "/") {
			return http.StatusNotFound, nil
		}

		const maxAge = 86400 // 1 day
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%v", maxAge))
		w.Header().Set("X-Content-Type-Options", "nosniff")

		if d.settings.Branding.Files != "" {
			if strings.HasPrefix(r.URL.Path, "img/") {
				fPath, ok := brandingFile(d.settings.Branding.Files, r.URL.Path)
				if !ok {
					return http.StatusNotFound, nil
				}
				_, err := os.Stat(fPath)
				if err != nil && !os.IsNotExist(err) {
					log.Printf("could not load branding file override: %v", err)
				} else if err == nil {
					http.ServeFile(w, r, fPath)
					return 0, nil
				}
			} else if r.URL.Path == "custom.css" && d.settings.Branding.Files != "" {
				if fPath, ok := brandingFile(d.settings.Branding.Files, "custom.css"); ok {
					http.ServeFile(w, r, fPath)
					return 0, nil
				}
				return http.StatusNotFound, nil
			}
		}

		if !strings.HasSuffix(r.URL.Path, ".js") {
			http.FileServer(http.FS(assetsFs)).ServeHTTP(w, r)
			return 0, nil
		}

		f, err := assetsFs.Open(r.URL.Path + ".gz")
		if err != nil {
			return http.StatusNotFound, err
		}
		defer f.Close()

		acceptEncoding := r.Header.Get("Accept-Encoding")
		// The representation varies by encoding: without Vary a shared cache
		// could serve the gzip bytes to clients that cannot decode them.
		w.Header().Set("Vary", "Accept-Encoding")
		if strings.Contains(acceptEncoding, "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")

			if _, err := io.Copy(w, f); err != nil {
				return http.StatusInternalServerError, err
			}
		} else {
			gzReader, err := gzip.NewReader(f)
			if err != nil {
				return http.StatusInternalServerError, err
			}
			defer gzReader.Close()

			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")

			if _, err := io.Copy(w, gzReader); err != nil {
				return http.StatusInternalServerError, err
			}
		}

		return 0, nil
	}, "/static/", store, server)

	return index, static
}

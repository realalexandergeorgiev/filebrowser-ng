package fbhttp

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	boltapi "go.etcd.io/bbolt"

	"github.com/realalexandergeorgiev/filebrowser-ng/diskcache"
	"github.com/realalexandergeorgiev/filebrowser-ng/settings"
	"github.com/realalexandergeorgiev/filebrowser-ng/share"
	"github.com/realalexandergeorgiev/filebrowser-ng/storage"
	"github.com/realalexandergeorgiev/filebrowser-ng/storage/bolt"
	"github.com/realalexandergeorgiev/filebrowser-ng/users"
)

func TestAdminShareGetsHandlerMatchesOwnerScope(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	ownerScope := filepath.Join(root, "owner")
	if err := os.MkdirAll(ownerScope, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ownerScope, "file.txt"), []byte("shared"), 0o600); err != nil {
		t.Fatal(err)
	}

	db, err := boltapi.Open(filepath.Join(t.TempDir(), "db"), 0o600, nil)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	st, err := bolt.NewStorage(db)
	if err != nil {
		t.Fatalf("failed to get storage: %v", err)
	}

	owner := &users.User{
		Username: "owner",
		Password: "pw",
		Scope:    "/owner",
		Perm:     users.Permissions{Share: true, Download: true},
	}
	if err := st.Users.Save(owner); err != nil {
		t.Fatalf("failed to save owner: %v", err)
	}

	adminPerm := users.Permissions{Admin: true, Share: true, Download: true}
	admin := &users.User{
		Username: "admin",
		Password: "pw",
		Scope:    "/",
		Perm:     adminPerm,
	}
	if err := st.Users.Save(admin); err != nil {
		t.Fatalf("failed to save admin: %v", err)
	}

	if err := st.Share.Save(&share.Link{Hash: "h", UserID: owner.ID, Path: "/file.txt"}); err != nil {
		t.Fatalf("failed to save share: %v", err)
	}
	key := []byte("test-signing-key")
	if err := st.Settings.Save(&settings.Settings{Key: key}); err != nil {
		t.Fatalf("failed to save settings: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "/owner/file.txt", http.NoBody)
	if err != nil {
		t.Fatalf("failed to construct request: %v", err)
	}
	req.Header.Set("X-Auth", signShareTestToken(t, st, admin.ID, admin.Username, adminPerm, key))

	rec := httptest.NewRecorder()
	handle(shareGetsHandler, "", st, &settings.Server{Root: root}).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var links []*share.Link
	if err := json.Unmarshal(rec.Body.Bytes(), &links); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(links) != 1 || links[0].Hash != "h" {
		t.Fatalf("expected admin to see owner share h, got %#v", links)
	}
}

// Regression for the share secret exposure (GHSA-833g-cqhp-h72j): the share API
// must not serialize the bcrypt password hash or the bypass token, while still
// persisting them server-side so password-protected shares keep working.
func TestSharePostHandlerDoesNotLeakSecrets(t *testing.T) {
	root := t.TempDir()
	userScope := filepath.Join(root, "user")
	if err := os.MkdirAll(userScope, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userScope, "file.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	key := []byte("test-signing-key")
	perm := users.Permissions{Share: true, Download: true}
	st := scopedUserStorage(t, userScope, perm, key)
	signed := signToken(t, st, perm, key)

	body := `{"password":"ShareSecret123!","expires":"24","unit":"hours"}`
	req, _ := http.NewRequest(http.MethodPost, "/file.txt", strings.NewReader(body))
	req.Header.Set("X-Auth", signed)
	rec := httptest.NewRecorder()
	handle(sharePostHandler, "", st, &settings.Server{Root: root}).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%q", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := resp["password_hash"]; ok {
		t.Errorf("VULNERABLE: response leaks password_hash: %s", rec.Body.String())
	}
	if _, ok := resp["token"]; ok {
		t.Errorf("VULNERABLE: response leaks token: %s", rec.Body.String())
	}
	if resp["hasPassword"] != true {
		t.Errorf("expected hasPassword=true, got %v", resp["hasPassword"])
	}

	// The secrets must still be persisted server-side (storm uses the JSON codec,
	// so the storage struct's tags must keep emitting them).
	stored, err := st.Share.GetByHash(resp["hash"].(string))
	if err != nil {
		t.Fatalf("share not stored: %v", err)
	}
	if stored.PasswordHash == "" || stored.Token == "" {
		t.Fatalf("server-side secrets not persisted: hash=%q token=%q", stored.PasswordHash, stored.Token)
	}
}

func signShareTestToken(t *testing.T, st *storage.Storage, id uint, username string, perm users.Permissions, key []byte) string {
	t.Helper()

	sess, err := st.Sessions.Create(id, time.Hour)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	claims := &authToken{
		User: userInfo{ID: id, Username: username, Perm: perm},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tokenIssuer,
			Subject:   strconv.FormatUint(uint64(id), 10),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ID:        sess.JTI,
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

// Share hashes must carry 128 bits: the old 6-byte hashes were enumerable.
func TestShareHashEntropy(t *testing.T) {
	root := t.TempDir()
	userScope := filepath.Join(root, "user")
	if err := os.MkdirAll(userScope, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userScope, "f.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	key := []byte("test-signing-key")
	perm := users.Permissions{Share: true, Download: true}
	st := scopedUserStorage(t, userScope, perm, key)
	signed := signToken(t, st, perm, key)

	seen := map[string]struct{}{}
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest(http.MethodPost, "/f.txt", strings.NewReader(`{}`))
		req.Header.Set("X-Auth", signed)
		rec := httptest.NewRecorder()
		handle(sharePostHandler, "", st, &settings.Server{Root: root}).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("share = %d body=%q, want 200", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		hash, _ := resp["hash"].(string)
		raw, err := base64.RawURLEncoding.DecodeString(hash)
		if err != nil {
			t.Fatalf("hash %q is not raw URL-safe base64: %v", hash, err)
		}
		if len(raw) != 16 {
			t.Fatalf("VULNERABLE: hash carries %d bytes, want 16 (128-bit)", len(raw))
		}
		if _, dup := seen[hash]; dup {
			t.Fatalf("duplicate hash %q", hash)
		}
		seen[hash] = struct{}{}
	}
}

// would oracle-expose the denial even though access is refused later.
func TestSharePostDeniedPathForbidden(t *testing.T) {
	root := t.TempDir()
	userScope := filepath.Join(root, "user")
	if err := os.MkdirAll(userScope, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Secret.txt", "public.txt"} {
		if err := os.WriteFile(filepath.Join(userScope, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	key := []byte("test-signing-key")
	perm := users.Permissions{Share: true, Download: true}
	st := denyRuleStorage(t, userScope, "/Secret.txt", perm, key)
	signed := signToken(t, st, perm, key)

	post := func(target string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodPost, target, strings.NewReader(`{}`))
		req.Header.Set("X-Auth", signed)
		rec := httptest.NewRecorder()
		handle(sharePostHandler, "", st, &settings.Server{Root: root}).ServeHTTP(rec, req)
		return rec
	}

	if rec := post("/Secret.txt"); rec.Code != http.StatusForbidden {
		t.Fatalf("share on denied path = %d, want 403", rec.Code)
	}
	if links, err := st.Share.Gets("/Secret.txt", 1); err == nil && len(links) != 0 {
		t.Fatalf("VULNERABLE: share minted for denied path: %+v", links)
	}
	if rec := post("/public.txt"); rec.Code != http.StatusOK {
		t.Fatalf("share on allowed path = %d body=%q, want 200", rec.Code, rec.Body.String())
	}
}

// Renaming must invalidate shares under the source and the destination:
// otherwise a share keeps serving whatever lands on the old path next, and
// a share on an overwritten destination serves the replacement content.
func TestRenameInvalidatesShares(t *testing.T) {
	root := t.TempDir()
	userScope := filepath.Join(root, "user")
	if err := os.MkdirAll(userScope, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"a.txt": "A", "b.txt": "B"} {
		if err := os.WriteFile(filepath.Join(userScope, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	key := []byte("test-signing-key")
	perm := users.Permissions{Share: true, Download: true, Rename: true, Modify: true, Create: true}
	st := scopedUserStorage(t, userScope, perm, key)
	signed := signToken(t, st, perm, key)
	srv := &settings.Server{Root: root}

	shareIt := func(target string) string {
		req, _ := http.NewRequest(http.MethodPost, target, strings.NewReader(`{}`))
		req.Header.Set("X-Auth", signed)
		rec := httptest.NewRecorder()
		handle(sharePostHandler, "", st, srv).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("share %s = %d body=%q, want 200", target, rec.Code, rec.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp["hash"].(string)
	}
	hashA := shareIt("/a.txt")
	hashB := shareIt("/b.txt")

	req, _ := http.NewRequest(http.MethodPatch, "/a.txt?action=rename&destination=/b.txt&override=true", http.NoBody)
	req.Header.Set("X-Auth", signed)
	rec := httptest.NewRecorder()
	handle(resourcePatchHandler(diskcache.NewNoOp()), "", st, srv).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename = %d body=%q, want 200", rec.Code, rec.Body.String())
	}
	for name, hash := range map[string]string{"source": hashA, "overwritten destination": hashB} {
		if _, err := st.Share.GetByHash(hash); err == nil {
			t.Fatalf("VULNERABLE: %s share survives rename", name)
		}
	}
}

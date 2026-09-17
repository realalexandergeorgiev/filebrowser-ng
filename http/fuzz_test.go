package fbhttp

import (
	"net/http"
	"strings"
	"testing"

	gopath "path"
)

// FuzzSlashClean pins the canonicalization contract against malformed
// input: the result must always be absolute, Clean-stable, free of ".."
// segments, and must never panic.
func FuzzSlashClean(f *testing.F) {
	for _, seed := range []string{
		"", "/", "/a/b", "/a/../b", "/a/./b/", "..", "../..", "/..",
		`a\b`, `/a\b/..\c`, "%2e%2e", "a//b", "/a//b//", "\x00",
		"üñî/ß", "/a/.../b", "/a/..hidden", ".", "/.",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := slashClean(s)
		if !strings.HasPrefix(out, "/") {
			t.Fatalf("slashClean(%q) = %q, want absolute path", s, out)
		}
		if out != "/" && strings.HasSuffix(out, "/") {
			t.Fatalf("slashClean(%q) = %q, want no trailing slash", s, out)
		}
		if gopath.Clean(out) != out {
			t.Fatalf("slashClean(%q) = %q, not Clean-stable", s, out)
		}
		for _, seg := range strings.Split(out, "/") {
			if seg == ".." {
				t.Fatalf("slashClean(%q) = %q, traversal survived", s, out)
			}
		}
	})
}

// FuzzIfPathWithName feeds hostile share-link remainders at the public
// share path splitter: it must never panic and the file path must stay
// absolute (callers join it under the share root).
func FuzzIfPathWithName(f *testing.F) {
	for _, seed := range []string{
		"abc123", "abc123/file.txt", "abc123/a/b/c", "abc123/",
		"abc123/..", "abc123/%2e%2e/x", "notokenhash12345?token=",
		"a,b,c", "x//y",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, target string) {
		req, err := http.NewRequest(http.MethodGet, "http://example.com/api/public/share/"+target, http.NoBody)
		if err != nil {
			t.Skip("unbuildable URL, nothing to split")
		}
		id, filePath := ifPathWithName(req)
		_ = id
		if !strings.HasPrefix(filePath, "/") {
			t.Fatalf("ifPathWithName(%q) filePath = %q, want absolute", target, filePath)
		}
	})
}

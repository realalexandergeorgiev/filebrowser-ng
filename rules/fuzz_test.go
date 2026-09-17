package rules

import (
	"strings"
	"testing"
)

// FuzzRulePathMatches pins the path-rule boundary contract: a rule for
// "/a" covers exactly "/a" and "/a/..." — never the sibling "/ab".
// The property mirrors the Matches spec over random inputs so a future
// refactor cannot silently widen a deny rule (or narrow an allow rule).
func FuzzRulePathMatches(f *testing.F) {
	for _, seed := range [][2]string{
		{"/a", "/a"}, {"/a", "/ab"}, {"/a", "/a/b"}, {"/", "/x"},
		{"/A", "/a"}, {"", "/"}, {"/a/", "/a/b"},
	} {
		f.Add(seed[0], seed[1], false)
		f.Add(seed[0], seed[1], true)
	}
	f.Fuzz(func(t *testing.T, rulePath, path string, fold bool) {
		r := &Rule{Regex: false, Path: rulePath}
		got := r.Matches(path, fold)

		fp, fr := path, rulePath
		if fold {
			fp, fr = strings.ToLower(fp), strings.ToLower(fr)
		}
		prefix := fr
		if prefix != "/" && !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		want := fp == fr || strings.HasPrefix(fp, prefix)
		if got != want {
			t.Fatalf("rule %q matches %q (fold=%v) = %v, want %v", rulePath, path, fold, got, want)
		}
	})
}

// FuzzRegexpNoPanic throws hostile patterns and subjects at regex rules:
// matching must never panic (invalid patterns simply never match;
// Validate rejects them at input).
func FuzzRegexpNoPanic(f *testing.F) {
	for _, seed := range [][2]string{
		{"(", "x"}, {"[a-", "x"}, {`\`, "x"}, {"a{2,1}", "x"},
		{"(?P<>x)", "x"}, {".*", "/etc/passwd"}, {"", ""},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, pattern, s string) {
		r := &Rule{Regex: true, Regexp: &Regexp{Raw: pattern}}
		_ = r.Matches(s, false)
		_ = r.Matches(s, true)
	})
}

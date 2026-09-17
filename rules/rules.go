package rules

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
)

// Checker is a Rules checker.
type Checker interface {
	Check(path string) bool
}

// Rule is a allow/disallow rule.
type Rule struct {
	Regex  bool    `json:"regex"`
	Allow  bool    `json:"allow"`
	Path   string  `json:"path"`
	Regexp *Regexp `json:"regexp"`
}

// Validate rejects rules that could never work, currently regex rules with
// an uncompilable pattern (which would otherwise panic on first match).
func (r *Rule) Validate() error {
	if r.Regex {
		if r.Regexp == nil {
			return errors.New("regex rule without expression")
		}
		return r.Regexp.Compile()
	}
	return nil
}

// MatchHidden matches paths with a basename
// that begins with a dot.
func MatchHidden(path string) bool {
	return path != "" && strings.HasPrefix(filepath.Base(path), ".")
}

// Matches matches a path against a rule. When fold is true the comparison is
// case-insensitive: on a case-insensitive filesystem two paths differing only
// in case name the same file, so a rule written for one spelling has to cover
// the others or it can be trivially evaded.
//
// Regex rules are never folded. An admin-authored pattern means what it says,
// and lowering its input would silently change it; use (?i) for those.
func (r *Rule) Matches(path string, fold bool) bool {
	if r.Regex {
		return r.Regexp.MatchString(path)
	}

	rulePath := r.Path
	if fold {
		path = strings.ToLower(path)
		rulePath = strings.ToLower(rulePath)
	}

	if path == rulePath {
		return true
	}

	prefix := rulePath
	if prefix != "/" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	return strings.HasPrefix(path, prefix)
}

// Regexp is a wrapper to the native regexp type where we
// save the raw expression.
type Regexp struct {
	Raw    string `json:"raw"`
	regexp *regexp.Regexp
}

// Compile parses the raw expression now, so invalid patterns are rejected
// at input (admin API, CLI, import) instead of panicking on first match.
func (r *Regexp) Compile() error {
	re, err := regexp.Compile(r.Raw)
	if err != nil {
		return err
	}
	r.regexp = re
	return nil
}

// MatchString checks if a string matches the regexp. An uncompilable
// pattern never matches instead of panicking: inputs are validated by
// Compile, so this only guards rows written before validation existed.
func (r *Regexp) MatchString(s string) bool {
	if r.regexp == nil {
		if err := r.Compile(); err != nil {
			return false
		}
	}

	return r.regexp.MatchString(s)
}

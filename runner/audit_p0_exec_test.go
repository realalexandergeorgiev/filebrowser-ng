package runner

// Audit characterization for P0-C4 (ARCHITEKTUR.md §3, #5199,
// GHSA-8c9q-7855-wfxq/CVE-2026-54090): with a shell configured, ParseCommand
// passes the ENTIRE raw input to the shell while the allowlist in
// http/commands.go only checks the first token (`name`).
//
// Pinned v2 behavior: Shell=[sh -c] + raw="echo hi; id" yields
// command=[sh -c "echo hi; id"], name="echo" — so an allowlist of ["echo"]
// passes while the shell runs `id` too.
//
// filebrowser-ng target: exec removed entirely; this file is deleted with it.
import (
	"slices"
	"testing"

	"github.com/filebrowser/filebrowser/v2/settings"
)

func TestAuditParseCommandShellPassesFullRaw(t *testing.T) {
	s := &settings.Settings{Shell: []string{"sh", "-c"}}
	raw := "echo hi; id"

	command, name, err := ParseCommand(s, raw)
	if err != nil {
		t.Fatalf("ParseCommand failed: %v", err)
	}
	if name != "echo" {
		t.Fatalf("AUDIT CHANGED: name = %q, want %q", name, "echo")
	}
	want := []string{"sh", "-c", raw}
	if !slices.Equal(command, want) {
		t.Fatalf("AUDIT CHANGED: command = %q, want %q", command, want)
	}
	// The allowlist check as done by http/commands.go would pass here,
	// while the shell executes the injected second command.
	if !slices.Contains([]string{"echo"}, name) {
		t.Fatalf("expected allowlist [echo] to contain %q", name)
	}
}

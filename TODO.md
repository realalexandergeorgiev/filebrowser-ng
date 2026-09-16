# TODO — filebrowser-ng

AI-oriented backlog. Read this top-to-bottom in a fresh session before touching code.

## 0. Project facts (do not rediscover)

- **Repo:** `github.com/realalexandergeorgiev/filebrowser-ng` (fork of the archived
  `filebrowser/filebrowser`, last upstream `v2.63.23`).
- **Go module path:** `github.com/realalexandergeorgiev/filebrowser-ng`.
  All imports use this path; there is **no** `.../v2` suffix anymore.
- **Language/toolchain:** Go 1.26 (`go.mod`), Node >= 24 + pnpm 10 for `frontend/`.
- **Branch:** `filebrowser-ng`. **Tags:** `v0.1.0-ng`, `v0.2.0-ng`.
- **Version string:** `version/version.go` defaults to `0.2.0-ng`; release builds
  inject `version.Version` / `version.CommitSHA` via `-ldflags`.
- **Prebuilt binaries:** `releases/filebrowser-ng_<os>_<arch>[.exe]` + `releases/checksums.txt`.
  Rebuild with the script in §2, then refresh `checksums.txt`.
- **Docs to keep updated with every change:** `CHANGELOG.md` (root, `Unreleased` section),
  `README.md`, `ARCHITEKTUR.md`, `SECURITY.md`, `MIGRATION.md`. Keep `MIGRATION.md` accurate
  for v2 users. Docs language is English.

## 1. How to work (guardrails)

- One logical fix = one commit. Conventional Commits (`fix:`, `feat!:`, `refactor!:`,
  `test:`, `chore:`, `docs:`). Update `CHANGELOG.md` in the same commit.
- Security-sensitive fixes: add a regression test that **fails before / passes after**
  (existing tests do this; see `files/verify_test.go`, `http/sessions_test.go`).
- Never commit secrets. Never push to a remote you did not confirm.
- Prefer stdlib / maintained deps. `govulncheck` must stay clean.

## 2. Verify commands

```bash
# Backend
go build ./... && go vet ./... && go test -count=1 ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Frontend (needs Node>=24, pnpm>=10)
cd frontend && pnpm install --frozen-lockfile
pnpm run typecheck && pnpm run lint && pnpm test && pnpm run build

# Rebuild all release binaries + checksums (run from repo root)
VERSION=0.2.0-ng; COMMIT=$(git rev-parse --short HEAD); MOD=github.com/realalexandergeorgiev/filebrowser-ng
for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  GOOS=${t%/*} GOARCH=${t#*/}; n="filebrowser-ng_${GOOS}_${GOARCH}"
  [ "$GOOS" = windows ] && n="$n.exe"
  GOOS=$GOOS GOARCH=$GOARCH go build -trimpath \
    -ldflags="-s -w -X ${MOD}/version.Version=$VERSION -X ${MOD}/version.CommitSHA=$COMMIT" \
    -o "releases/$n" .
done
(cd releases && sha256sum filebrowser-ng_* > checksums.txt && sha256sum -c checksums.txt)
```

Environment note (this sandbox): Node/pnpm were installed under `/tmp/opencode`
(`PATH=/tmp/opencode/bin:/tmp/opencode/node24/bin`). Reinstall if missing:
Node 24 tarball from nodejs.org, then `corepack prepare pnpm@10.33.4 --activate`.
The `pnpm` shim used was `/tmp/opencode/bin/pnpm` invoking the corepack `pnpm.cjs`.

## 3. Open work items (priority order)

### P1 — Fuzzing / property tests (Go native `testing.F`)
Goal: cover the security-critical parsers/paths against malformed input.
- **Path canonicalization:** `http/utils.go` `slashClean`, `cleanSeparators`,
  `canonicalizeRequestPath`. Property: output is always absolute, `/`-separated,
  starts with `/`, and `Clean`-stable; `..` never survives as a traversal.
- **Rules matching:** `rules/rules.go` `Matches` (incl. `CaseInsensitiveFs` folding,
  `/`-boundary prefix). Property: a rule for `/a` never matches `/ab`; folding on
  Windows-style input cannot widen a deny rule.
- **Share hash/token parsing:** `http/public.go` `ifPathWithName`, token compare.
- **Sessions:** `sessions/sessions.go` (JTI format, expiry math, prune caps).
- Acceptance: `go test -run=Fuzz -fuzz=Fuzz... -fuzztime=30s` finds no crash and no
  property violation on seeds + generated input. Add seed corpora from existing
  regression cases.

### P2 — JWT claims hardening (`http/auth.go`)
Goal: tokens are bound to this deployment and not replayable across instances.
- Current `authToken` (`http/auth.go`) sets only `IssuedAt/ExpiresAt/Issuer`. Parser uses
  `WithValidMethods([HS256]) + WithExpirationRequired`.
- Add and enforce: `Subject` (user id), `NotBefore` always present, and verify
  `Issuer` via `jwt.WithIssuer(...)`. Consider `Audience` = realm/baseURL.
  A `jti` already exists (= session id, enforced by `withUser`).
- Acceptance: a token with a wrong/absent issuer or a future `nbf` is rejected (401);
  regression test in `http/sessions_test.go`.

### P2 — TOCTOU for metadata ops (`files/scoped.go`)
Goal: close the guard→op race for non-content operations too.
- `Rename`, `Remove`, `RemoveAll`, `Stat`, `Chmod`, `Chown`, `Chtimes`, `Mkdir(All)`
  currently do `guard(name)` then `base.<op>(name)`. Content opens are already hardened
  via `verify` (`files/verify_linux.go`, `/proc/self/fd`). Metadata ops have no
  descriptor to verify; best portable mitigation is re-checking `within()` immediately
  before the syscall and documenting the residual race.
- Acceptance: document residual risk in code comment + `ARCHITEKTUR.md`; add tests that
  a symlink swapped between guard and op cannot escape for the ops that can be made
  atomic (`Rename` with both paths re-guarded, `RemoveAll`).
- Note: `openat2`/`RESOLVE_BENEATH` was evaluated and rejected (it rejects legitimate
  absolute in-scope symlinks); see `files/scoped.go` history. Do not reintroduce blindly.

### P3 — Remove external CDN / unify CSP
- `frontend/src/views/files/Editor.vue` configures ACE from jsdelivr; global CSP is
  `default-src 'self'`. Either self-host ACE assets (preferred) or document the CSP
  exception. `frontend/public/index.html` injects `ReCaptchaHost` (admin-set) — validate
  the host scheme and restrict to https.
- Acceptance: editor loads with `default-src 'self'` (no CDN), or CSP is explicitly
  widened with a comment; no new console CSP errors.

### P3 — Share `?token=` ergonomics
- `http/public.go` token survives 24h sliding (see `maxShareTokenAge`). Long-lived
  secret-in-URL remains a leak vector (logs/history/Referer — Referer is mitigated via
  `Referrer-Policy: no-referrer`). Consider issuing a short per-request signed token or
  switching the share frontend to a cookie/header credential.
- Acceptance: design note in `ARCHITEKTUR.md`; if changed, update `MIGRATION.md`.

### P3 — Rebrand leftovers (consistency)
- `cmd/root.go` default DB path is still `./filebrowser.db`; the container init scripts
  in `docker/` and `docker/common/defaults/settings.json` still reference the old binary
  name `filebrowser` and DB. Decide: rename to `filebrowser-ng.db` / `filebrowser-ng`
  (full-break fork) or keep for compatibility, then make it consistent everywhere.
- `docs/installation.md` still points at the upstream Docker Hub image
  (`filebrowser/filebrowser`); update to this project's image/build instructions.
- `rg -n 'filebrowser/filebrowser'` (excluding `CHANGELOG.md` and the two fork-attribution
  lines in `README.md`/`ARCHITEKTUR.md`) should be empty after this.

### P4 — CI
- Add GitHub Actions: `go build/vet/test`, `govulncheck`, frontend
  `typecheck/lint/test/build`, and a job that fails if `releases/checksums.txt` does not
  verify. Keep the module path `github.com/realalexandergeorgiev/filebrowser-ng` in the
  workflow cache keys.

### P4 — Dependency hygiene
- Re-evaluate `github.com/dsoprea/go-exif/v3` (EXIF metadata parsing) and any remaining
  EOL deps with `govulncheck -show verbose`. `gorilla/*`, `asdine/storm`,
  `mholt/archives`, `flynn/go-shlex`, `mitchellh/go-homedir` are already removed.
- Rate limiter (`http/ratelimit.go`) is in-process; document that multi-replica
  deployments behind a load balancer do not share budgets, or back it with Redis
  (`upload_cache_redis.go` shows the Redis client wiring).

### P5 — i18n nice-to-have
- Other locale files under `frontend/src/i18n/*.json` may still contain dead keys for the
  removed exec UI (Transifex integration stopped). `en.json` is already cleaned. Low risk;
  only do this if churn is acceptable.

## 4. Completed (do not redo)

- Audited the v2 baseline; documented P0–P3 in `ARCHITEKTUR.md` §3.
- Removed command execution / runner / hooks / web shell (backend + frontend UI).
- Removed hook authentication (`CVE-2026-54088`).
- Server-side sessions with revocation + HttpOnly cookies (`#5216`).
- Proxy auth gated on `Server.TrustedProxies` (loopback by default) (`GO-2026-5966`).
- Share: expiry sweep fixed, create enforces rules, rename no longer hijacks, 128-bit
  hashes, 24h sliding URL-token, per-peer/link password budget.
- TUS: validate-before-truncate, positional writes (no `O_APPEND`), delete parity,
  no server-path leaks in 400s.
- TOCTOU: content opens verified via `/proc/self/fd` (`files/verify_linux.go`); the
  `BasePathFile` unwrap bug was fixed (verification had silently no-op'd).
- Headers/CSP/Referrer/Vary, login/signup rate limits, secrets hygiene (`0600` exports,
  key redaction, `config rotate-key`), search nil panic, server timeouts, preview request
  context, diskcache striped locks, reCaptcha timeout, compose hardening + JSON.sh
  checksum.
- Deps: storm→raw bbolt, archives→stdlib, gorilla/mux→stdlib, homedir removed;
  `govulncheck` clean.
- Rebrand to `filebrowser-ng`, version `0.2.0-ng`, module path renamed to
  `github.com/realalexandergeorgiev/filebrowser-ng`, release binaries + checksums.

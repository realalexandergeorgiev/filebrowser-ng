# TODO — filebrowser-ng

AI-oriented backlog. Read this top-to-bottom in a fresh session before touching code.

## 0. Project facts (do not rediscover)

- **Repo:** `github.com/realalexandergeorgiev/filebrowser-ng` (fork of the archived
  `filebrowser/filebrowser`, last upstream `v2.63.23`).
- **Go module path:** `github.com/realalexandergeorgiev/filebrowser-ng`.
  All imports use this path; there is **no** `.../v2` suffix anymore.
- **Language/toolchain:** Go 1.26.8 (`go.mod`), Node >= 24 + pnpm 10 for `frontend/`.
- **Branch:** `filebrowser-ng`. **Tags:** `v0.1.0-ng`, `v0.2.0-ng`, `v0.3.0-ng`, `v0.3.1-ng`, `v0.3.2-ng`, `v0.3.3-ng`, `v0.4.0-ng`, `v0.5.0-ng`, `v0.6.0-ng`.
- **Version string:** `version/version.go` defaults to `0.6.0-ng`; release builds
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
VERSION=0.6.0-ng; COMMIT=$(git rev-parse --short HEAD); MOD=github.com/realalexandergeorgiev/filebrowser-ng
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

Browser smoke test (do this for any CSP / frontend-shell change — `curl` alone
misses CSP violations): `chromium` (snap) + Node 24 CDP. Start the server, then in
a separate process launch
`chromium --headless=new --no-sandbox --remote-debugging-port=9223 about:blank`
and drive it via the DevTools protocol from Node
(`Runtime.enable`, `Log.enable`, `Page.navigate`, `Runtime.evaluate`). Check
`document.querySelector('#app').__vue_app__` is truthy and the loading element is
gone; inspect `Log.entryAdded` for "violates the following Content Security
Policy". This is how the nonce regression was found.

## 3. Open work items (priority order)

### P1 — Fuzzing / property tests (Go native `testing.F`)
Done 2026-09-17 (6 targets, 30 s each, no crash/violation; keep running on
touched parsers):
- **Path canonicalization:** `http/fuzz_test.go` `FuzzSlashClean` (absolute,
  Clean-stable, no trailing slash, no `..` segment) and `FuzzIfPathWithName`
  (no panic, absolute file path).
- **Rules matching:** `rules/fuzz_test.go` `FuzzRulePathMatches` (rule `/a`
  covers exactly `/a` and `/a/...`, never `/ab`, both foldings) and
  `FuzzRegexpNoPanic` (hostile patterns never panic; invalid ones never
  match, `Validate` rejects them at input).
- **Sessions:** `sessions/fuzz_test.go` `FuzzSessionExpired` (expiry math +
  monotonicity) and `FuzzCreatePruneCap` (unique 32-hex JTIs, stored count
  capped at `MaxSessionsPerUser`).
- Acceptance: `go test -run=Fuzz -fuzz=Fuzz... -fuzztime=30s` finds no crash and no
  property violation on seeds + generated input. Add seed corpora from existing
  regression cases.

### P2 — JWT claims hardening (`http/auth.go`)
Done 2026-09-17: parser enforces `WithValidMethods([HS256]) +
WithExpirationRequired + WithIssuer("filebrowser-ng")` (`tokenIssuer`);
minting always sets `Subject` (= user id) and `NotBefore` (= issued-at),
and `withUser` rejects absent/mismatched `sub` and absent `nbf` (future
`nbf` fails in the parser). Tested in `http/sessions_test.go`
(`TestTokenClaimsEnforced`, `TestTokenWithoutIssuerRejected`); pre-claim
tokens are rejected, logging everyone out once.
- Open: `Audience`. Skipped deliberately: single-issuer HS256 with per-
  instance keys gives `aud` nothing to bind — a foreign instance's token
  never verifies here. Revisit only if key sharing across realms appears.
  A `jti` already exists (= session id, enforced by `withUser`).

### P2 — TOCTOU for metadata ops (`files/scoped.go`)
Done 2026-09-17 (best portable mitigation + proof, race itself is
unfixable without descriptors): every metadata op keeps its guard
directly above the syscall with a comment pinning that adjacency
(`files/scoped.go`); `files/scoped_guard_test.go` asserts planted-escape
refusal per op (`Rename` both paths, `Remove(All)`, `Mkdir(All)`, `Stat`,
`Chmod`, `Chtimes`, `LstatIfPossible`), in-scope controls, and that the
guard sees swaps (no caching). Residual race documented in
`ARCHITEKTUR.md` §7. Content opens stay descriptor-verified on Linux.
- Note: `openat2`/`RESOLVE_BENEATH` was evaluated and rejected (it rejects legitimate
  absolute in-scope symlinks); see `files/scoped.go` history. Do not reintroduce blindly.

### P3 — CSP follow-ups
- ACE editor: fixed — vendored under `dist/ace` (build-time copy in
  `frontend/vite.config.ts`) and loaded from `/static/ace/`, so `script-src
  'self'` stays strict. `worker-src 'self' blob:` is set.
- reCAPTCHA: fixed — the index CSP allows the admin-configured https host plus
  `https://www.gstatic.com` only while reCAPTCHA is enabled; non-https hosts
  disable it. Re-check when touching CSP: `http/static.go` `indexCSP` /
  `recaptchaCSPOrigins`, and verify in a real browser (see §2 smoke test).
- Remaining hardening: consider SRI/self-hosting is N/A for reCAPTCHA; keep
  `script-src` free of `'unsafe-inline'` and any CDN.

### P3 — Share `?token=` ergonomics
Done 2026-09-17 as a design decision (no code change): `ARCHITEKTUR.md`
§4 records why the sliding URL token stays (per-request tokens or share
cookies trade the leak for complexity/UX loss). Revisit only with a
`MIGRATION.md` update, since link format is user-visible.

### P3 — Rebrand leftovers (consistency)
Done 2026-09-17 (full-break decision: rename): default DB is
`./filebrowser-ng.db` (`cmd/root.go`, message in `cmd/utils.go`,
`/database/filebrowser-ng.db` in `docker/common/defaults/settings.json`);
`docs/installation.md` points at the fork releases page and locally built
`filebrowser-ng[:s6]` images (no registry image published); upstream
`brew`/`get.sh` blocks labeled as v2-only; code comment in
`http/public.go` keeps the PR reference without the URL.
- The upstream `org/repo` path appears nowhere anymore except `CHANGELOG.md`
  history and the two fork-attribution lines in `README.md`/`ARCHITEKTUR.md`.

### P4 — CI
Done 2026-09-17: `.github/workflows/ci.yaml` rewritten for the fork —
triggers on `main`/`filebrowser-ng` + `v*` tags and PRs (upstream file
still pointed at `master`); jobs for backend build/vet/`test -race`,
golangci-lint, `govulncheck`, frontend typecheck/lint/test/`audit`,
`sha256sum -c releases/checksums.txt`, and tag-only release-artifact
builds (frontend + 6 binaries with version ldflags, uploaded as
artifacts) replacing the upstream Docker-Hub/GoReleaser release.
`go-version-file: go.mod` pins the toolchain; cache keys carry the
module path. PR-title lint (`lint-pr.yaml`) kept as is.

### P4 — Dependency hygiene
- Re-scanned 2026-09-17: `govulncheck` 0 affecting (same uncalled
  `GO-2026-5932` N/A); no direct Go module updates pending (only
  indirect/test-only); `go-exif/v3` current, the older `v2` line is a
  clean transitive. npm `audit` 0; `video.js`/`vue` patches applied.
  Intentionally held majors: `@vueuse` 15, `pinia` 4, `typescript` 7,
  `vitest` 5 (new).
- Audited 2026-09-17: Go toolchain 1.26.8, direct modules bumped (astisub,
  go-redis, gopsutil, testify, x/net); `govulncheck` clean except uncalled
  `GO-2026-5932` (`x/crypto`, no fix available). npm updated in-range plus
  `pnpm.overrides` for `@xmldom/xmldom`/`rollup`/`esbuild`; `pnpm audit` is 0.
  Intentionally held majors: `@vueuse` 15, `pinia` 4, `typescript` 7.
- Re-evaluate `github.com/dsoprea/go-exif/v3` (EXIF metadata parsing) and any remaining
  EOL deps with `govulncheck -show verbose`. `gorilla/*`, `asdine/storm`,
  `mholt/archives`, `flynn/go-shlex`, `mitchellh/go-homedir` are already removed.
- Rate limiter (`http/ratelimit.go`) and IP bans (`http/ipban.go`) are
  in-process; document that multi-replica deployments behind a load balancer
  do not share budgets/bans, or back them with Redis
  (`upload_cache_redis.go` shows the Redis client wiring).

### P5 — i18n nice-to-have
Done 2026-09-17: every non-`en` locale carried the same 10 stale exec-UI
keys (`buttons.shell`, `settings.allowCommands/commandRunner/
commandRunnerHelp/commandsUpdated/executeOnShell/
executeOnShellDescription/perm.execute/userCommands/userCommandsHelp`) —
all unreferenced in `src/` (only dynamic `$t` is `search.<label>` with a
closed label set, verified). Removed 320 keys across 32 locales, pure
deletions; `en.json` untouched.

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
- App shell fixed to run under a strict nonce-based CSP; ACE editor vendored under
  `/static/ace` (no CDN) and reCAPTCHA host allowed by CSP while enabled; sidebar
  credits link corrected.
- Markdown preview font size follows the editor font-size control
  (`--preview-font-size`).
- Rejected-request log no longer prints `<nil>` for expected rejections
  (`http/data.go` `formatRequestLog`, tested in `http/requestlog_test.go`).
- Dependency audit 2026-09-17: Go 1.26.8, modules bumped, npm updated +
  overrides, `govulncheck` and `pnpm audit` clean (see P4 hygiene note).
- Brute-force IP bans (`http/ipban.go`): 10 failed logins/share-passwords/
  forged tokens in 10 min bans the peer API-wide for 1 h; trusted-proxy-aware
  keying, capped/expiring, tested in `http/ipban_test.go`.
- Audit batch v0.5.0-ng: admin-bootstrap warning, JSON body caps, JWT issuer
  enforcement, auth logging, frontend hardening, branding symlink
  containment, EPUB sandbox, `--maxUploadSize`, archive cycle guard,
  residual-risk docs (`ARCHITEKTUR.md` §7).
- Backlog batch v0.6.0-ng: Go fuzz targets (+ regex-rule validation),
  JWT `sub`/`nbf` binding, metadata-op guard adjacency, rebrand leftovers,
  fork CI, i18n dead-key cleanup.

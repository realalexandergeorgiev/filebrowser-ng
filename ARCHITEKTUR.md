# ARCHITECTURE — filebrowser-ng

> Fork of `filebrowser/filebrowser` (archived 2026-09-01, last release `v2.63.23`).
> Goal: security-hardened, maintainable rewrite. Docs language: English.
> Status: audit complete; fixes landing per commit (see `CHANGELOG.md`):
> exec/runner/hooks/web shell removed (backend + frontend UI), hook auth
> removed, share sweep fixed, TUS path disclosure fixed, branding traversal
> fixed, server-side sessions done. Module path rename
> (`github.com/filebrowser/filebrowser/v2` →
> `github.com/filebrowser-ng/...`) is deferred to the rewrite start to keep
> the baseline buildable.

## 1. Goals / Non-Goals

Goals:

- Fix all known + unknown security issues, critical first (sessions, exec, proxy, scope escape, share, TUS, headers, secrets).
- Full rewrite of the backend with a clean API (`/api/v1`, OpenAPI), strict layering `http → service → storage/fs`.
- Single-binary selfhosted deployment (Bolt default, Redis optional for sessions/cache), Docker non-root, `0700` for DB/cache.
- One logical fix = one commit (Conventional Commits), `CHANGELOG.md` updated per commit.

Non-goals / breaking decisions (confirmed):

- No backward compatibility with v2 DB/config/API/CLI. Fresh install; import tool for users/settings only (never imports `Settings.Key`).
- Command execution / runner / hooks / web shell removed entirely (`#5199`). No `--disable-exec` flag anymore.
- Server-side sessions (short access JWT + opaque rotating refresh, revocation). No stateless-only sessions (`#5216`).
- No direct internet exposure without reverse proxy + TLS + own auth in front.

## 2. Current v2 System (audit baseline)

```
Browser (Vue 3 + Pinia + tus-js-client)
  │  X-Auth header (POST/PUT/PATCH/DELETE) / auth cookie (GET only) / ?token= for shares
  ▼
gorilla/mux router (http/http.go:32-97)
  ├─ /api/login|signup|renew (http/auth.go) — HS256 JWT, 2h default
  ├─ /api/resources|tus|raw|preview|search|subtitle|usage|command (WS)
  ├─ /api/users|settings|shares|share
  └─ /api/public/dl|share (share hash, no JWT)
        │  withUser/withAdmin per request (http/auth.go:116-154, http/data.go:87-122)
        ▼
  services: files.ScopedFs, fileutils Copy/Move, share.Storage, diskcache, img.Service, runner.Runner
        ▼
  storage: storm/v3 → bbolt (users, settings incl. JWT Key, shares, auth method)
  frontend state: localStorage jwt + document.cookie auth (frontend/src/utils/auth.ts)
```

Key files:

- Auth: `auth/auth.go`, `auth/json.go`, `auth/proxy.go`, `auth/hook.go`, `http/auth.go`, `users/storage.go` (`LastUpdate` hint only), `settings/settings.go` (`Key []byte`, `Shell`, `Commands`).
- FS: `files/scoped.go` (`within`+`guard`), `files/file.go` (`RealPath`, listing filter), `fileutils/*` (no checker inside), `http/resource.go` (`checkDescendants`), `rules/rules.go`, `http/data.go` (`Check` vs `CheckRules`, `checkerPrefix` for shares).
- Upload/share/preview: `http/tus_handlers.go`, `http/upload_cache_{memory,redis}.go`, `http/raw.go` (zip pack, ZipSlip guards), `http/share.go`, `http/public.go`, `share/share.go` (6B hash, 96B token), `share/storage.go` (expiry sweep bug), `http/preview.go`, `http/subtitle.go`, `diskcache/file_cache.go` (scoped locks leak).
- Exec: `runner/runner.go`, `runner/parser.go`, `http/commands.go` (WS), `http/settings.go` (`Shell`/`Commands` persist), `docs/command-execution.md`.
- Edge: `http/static.go` (branding traversal, `.gz` without `Vary`), `http/headers.go`, `http/http.go` (weak CSP), `cmd/root.go` (timeouts, perms, pwd log), `compose.yaml` (hardcoded secrets).

## 3. Known Vulnerability Classes (audit 2026-09-16)

P0 — must die in rewrite:

- C1 stateless JWT without revocation: logout/password-change/delete/renew leave old tokens valid until `exp`, refresh infinitely reusable. `README.md` documents as won't-fix. Maps to `GO-2025-3812`, `CVE-2025-53826`, `GHSA-7xwp-2cpp-p8r7`, `#5216`.
- C2 proxy header blind trust + auto-provision, expired-token waiver via header. Maps to `GO-2026-5966`.
- C3 hook-auth priv-esc (`user.perm.admin/scope/commands` from script output) + creds in env + pre-auth RCE via `os.Expand`. Maps to `CVE-2026-54088`, `GHSA-m93h-4hw7-5qcm`.
- C4 runner/hook/WS RCE: allowlist bypass with `Shell=[sh,-c]` (`runner/parser.go:16-22` vs `http/commands.go:80`), `$FILE` injection via `os.Expand`, WS without `CheckOrigin`/limits/timeout, `settingsPut` persists `Shell`/`Commands`. Maps to `#5199`, `GHSA-jvpw-637p-h3pw`, `GHSA-8c9q-7855-wfxq`/`CVE-2026-54090`, `GO-2025-3793`.

P1 — rebuild correctly:

- TUS truncate-before-validate, no quota, `O_APPEND+Seek`, `RealPath` cache key, Redis eviction ignores delete, `tusDelete` without descendants check, `RealPath` in 400 errors. Partly `GO-2026-4713`, `GO-2025-3811`.
- FS TOCTOU (`guard` then `open`), lexical `RealPath`/`FullPath` vs resolved `within`, global `FollowExternalSymlinks`, `CopyDir` follows symlink-dir while walk does not.
- Share: create without `Check`, rename hijack, 48-bit hash without rate-limit, long-lived `?token=` in URL, sweep `append` in `range` skips expiries. Partly `GO-2025-3790`.
- Secrets/transport: `Key` in cleartext DB + `config export` (world-readable), JWT in `localStorage` + JS-readable cookie, no `HttpOnly/Secure`, pwd in logs (`cmd/root.go:510`), `PASSWORD` in hook env, hardcoded `compose.yaml` secrets, no rate-limit (delegated to fail2ban).
- Preview/static DoS + traversal: `context.Background` in resize/store, unlimited decode (`preview`, `subtitle`), lock-map leak, branding `Join` without containment, `.gz` without `Vary`.

P2/P3: search nil-`FileInfo` panic, missing `aud/jti/nbf` + unchecked `iss`, weak CSP (no `frame-ancestors/object-src/base-uri`), `template.JS` single-quote-only escaping, external CDN (`ace`, `ReCaptchaHost`) vs `default-src 'self'`, EOL deps (`gorilla/*` archived, `storm/v3` 2020, `mholt/archives v0.1.5`, `flynn/go-shlex` 2015), missing tests for `runner.exec`/`commandsHandler`/`preview`/`search`/`settingsPut`/`static`.

Positive patterns to keep: `dummyHash`, `WithValidMethods([HS256])+WithExpirationRequired`, `MaxBytesReader 1MiB`, signup `Execute=false`, share `HasPassword` (no hash leak), `attachment+nosniff+private`, `script-src 'none'` on raw/subtitle, pack-side ZipSlip guards, `slashClean` canonicalization, default-deny external symlinks.

## 4. Target Architecture (filebrowser-ng)

```
Vue frontend (keep, harden: no localStorage JWT, HttpOnly cookies, strict CSP)
  │  Bearer short access JWT (5–15 min) + HttpOnly Secure Strict refresh cookie
  ▼
chi/stdlib router, middleware: request-id, timeouts, rate-limit, audit-log, CSP/nosniff/frame-ancestors
  ├─ /api/v1/auth/{login,logout,refresh,sessions} — session store, rotation, reuse-detection
  ├─ /api/v1/files|uploads(tus)|archives|preview|search|shares|users|settings
  └─ /api/v1/public/{dl,share} — 128-bit hash, attempt-limit, re-check scope+rules
        │  service layer (pure, tested): authSvc, sessionSvc, fsSvc, shareSvc, uploadSvc
        ▼
  storage: bbolt directly (no storm) — buckets: users, sessions (jti, hash, exp, ua), shares, settings (no Key export)
  fs: new ScopedFS (RESOLVE_BENEATH semantics, no global follow-external, fail-closed rules, no RealPath leak)
  cache: diskcache with bounded locks + ctx-cancel; redis optional for sessions only
```

Auth design:

- Access: short JWT (`exp` 5–15 min, `iss`+`aud`+`jti` verified, `kid` key rotation with grace).
- Refresh: opaque 256-bit, SHA-256 stored, single-use rotation, reuse = revoke chain, max lifetime + idle timeout.
- Revoke on: logout (single + all), password change, perm/scope change, admin revoke, user delete. `GET /sessions` lists active.
- Proxy (if kept): `trusted_proxies` CIDR + forced strip/overwrite, never direct; auto-provision never inherits `execute/commands/admin`.
- No hook-exec auth; only `json` (+ optional `noauth` for home LAN). Rate-limit + lockout everywhere.

FS/share/upload design:

- One `ScopedFS` with `EvalSymlinks` + `openat`-style containment, `within` on FD not path string, no `RealPath` to client (ids only).
- `checkDescendants`-equivalent inside FS ops (not caller duty), atomic move, quota + count/size limits on archives/preview/search.
- TUS: validate-before-truncate, server-enforced quota, offset without `O_APPEND`, scoped eviction on all backends.
- Share: `Create` requires `Check`, rename/delete invalidate, constant-time compare, per-hash attempt bucket, expiry sweeper (no `append`-in-`range`).

## 5. Repo Layout (current → target)

Current: `auth/ http/ files/ fileutils/ share/ storage/bolt/ settings/ users/ rules/ runner/ diskcache/ img/ search/ cmd/ frontend/ docs/`.

Target: `cmd/server/ internal/{http,auth,session,files,share,upload,storage,config} frontend/ docs/`.
Delete at rewrite start: `runner/`, `http/commands.go`, `docs/command-execution.md`, `Shell`/`Commands` fields, `auth/hook.go` exec path.

## 6. Build / Test / Conventions

- Backend: `go build -trimpath -ldflags='-s -w ...'` (add `-trimpath`, fix `git describe` fallback without tags).
- Frontend: `pnpm install --frozen-lockfile`, `vitest run`, `vue-tsc --noEmit`.
- Security CI (to add): `govulncheck`, `pnpm audit`, `golangci-lint`, header/cookie e2e tests, `race` + fuzz on path/rules/share/session-reuse.
- Commits: Conventional Commits (`fix!:`, `feat!:`, `docs:`, `chore:`, `test:`), one logical fix = one commit, `CHANGELOG.md` (`Unreleased → Added/Fixed/Removed/Breaking`) + `README.md` updated per user-visible change. This file updated when target changes.

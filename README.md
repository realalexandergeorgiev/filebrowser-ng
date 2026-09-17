<p align="center">
  <img src="./branding/banner.png" width="550" alt="filebrowser-ng"/>
</p>

# filebrowser-ng

Security-hardened fork of [`filebrowser/filebrowser`](https://github.com/filebrowser/filebrowser) (archived 2026-09-01, last upstream `v2.63.23`).

> [!WARNING]
> Upstream is unmaintained with known unfixed classes: command execution/runner/hooks (`#5199`) and session/JWT handling (`#5216`). Do not expose upstream directly to the internet. This fork exists to fix all known + unknown issues, critical first, via a full rewrite. Until the first hardened release, treat this branch as work-in-progress.

Background: [Goodbye File Browser, for Real This Time](https://hacdias.com/2026/07/28/filebrowser/) (July 2026).

## What changes vs upstream

- **Full rewrite, full break:** no DB/config/API/CLI compatibility with v2. Fresh install; import tool for users/settings only (never imports `Settings.Key`).
- **Command execution removed:** `runner/`, web shell (`GET /api/command`), hooks, `Shell`/`Commands` fields deleted. There is no `--disable-exec` anymore because there is nothing to enable.
- **Server-side sessions:** short access JWT (5–15 min, `iss`/`aud`/`jti` verified, `kid` rotation) + opaque rotating refresh tokens (single-use, reuse-detection, max lifetime). Revocation on logout, password change, permission/scope change, admin revoke, user delete.
- **Single-binary selfhosted:** Bolt default, Redis optional for sessions/cache only. Non-root Docker, `0700` for DB/cache, no secrets in logs/exports.
- See [`ARCHITEKTUR.md`](ARCHITEKTUR.md) (target design, audit findings with file refs) and [`CHANGELOG.md`](CHANGELOG.md) (per-fix entries). Upgrading from v2? Read [`MIGRATION.md`](MIGRATION.md) first.

## Security status

Current branch: `filebrowser-ng` (rewrite landed; released as `v0.1.0-ng` → `v0.3.2-ng`). Upstream P0 classes and their state here:

- ~~Command execution/runner/hooks (`#5199`)~~ — **removed** backend (no `runner/`, no web shell, no hooks, no `--disable-exec`) and frontend (no terminal, no runner settings, no per-user commands field).
- ~~Hook authentication (`CVE-2026-54088`)~~ — **removed** (remaining: `json`, `proxy`, `noauth`); the hook-auth priv-esc / pre-auth RCE path is gone with it.
- ~~Stateless JWT without revocation (`GO-2025-3812`/`CVE-2025-53826`/`#5216`)~~ — **done**: server-side sessions (`sessions/`, `DELETE /api/logout`, revocation on password/security change and delete).
- ~~Proxy header blind trust (`GO-2026-5966`)~~ — **done**: header only honored from `TrustedProxies` (loopback-only by default).

If you run anything pre-rewrite: do not expose directly, put behind a reverse proxy with TLS + own auth, keep exec disabled (default), run unprivileged in a container with only the served directory mounted.

Reporting: see [`SECURITY.md`](SECURITY.md).

## Quickstart (upstream baseline, will change)

```bash
# backend (Go >= 1.26)
go build -trimpath -o filebrowser-ng .
# frontend (Node >= 24, pnpm >= 10)
cd frontend && pnpm install --frozen-lockfile && pnpm run build
```

Docker / compose files are being reworked for non-root + `0700` + no hardcoded secrets. `docs/` still describes v2 and will be rewritten with the new API (`/api/v1`, OpenAPI).

## Roadmap

Open work is tracked in [`TODO.md`](TODO.md) (AI-oriented backlog). Milestones so far:

1. `v0.1.0-ng`: audit, docs, tooling, failing-first PoCs, P0 classes fixed (exec removal, hook auth, server-side sessions, proxy trust).
2. `v0.2.0-ng`: HttpOnly cookies, share/TOCTOU/TUS/header/secrets hardening, deps swap.
3. `v0.3.0-ng`: rebrand, module path rename (`github.com/realalexandergeorgiev/filebrowser-ng`), strict nonce-based CSP for the app shell, release binaries.
4. `v0.3.1-ng`: ACE editor vendored (no CDN) and reCAPTCHA host allowed by CSP, so both work under the strict policy.
5. `v0.3.2-ng`: markdown preview font size follows the editor font-size control.
6. `v0.3.3-ng`: rejected-request log no longer prints `<nil>`; Go toolchain 1.26.8 (23 stdlib findings fixed), Go modules + npm dependencies updated, `govulncheck` and `pnpm audit` clean.

Each fix = one commit (Conventional Commits), `CHANGELOG.md` updated per commit.

## How this fork was built

Everything in this repository — the security audit, the rewrite, every fix,
the rebrand, the docs and the releases — was done in a **single session**
with [OpenCode](https://opencode.ai), powered by **Muse Spark 1.3 (free
tier)**: one fix per commit, each with a regression test and a `CHANGELOG.md`
entry. The full history is the proof: `git log`.

## Contributing

One logical fix per PR, with regression test + `CHANGELOG.md` entry + docs update if user-visible. English for all docs. Run `go test ./...`, `govulncheck ./...`, `pnpm --dir frontend test` + `typecheck` + `audit` before pushing. Release builds require Go >= 1.26 (the `go.mod` toolchain).

## License

[Apache License 2.0](LICENSE) © File Browser Contributors + filebrowser-ng contributors.

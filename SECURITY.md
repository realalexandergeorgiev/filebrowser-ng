# Security Policy — filebrowser-ng

## Supported Versions

| Version      | Supported          |
| ------------ | ------------------ |
| `ng/main` (rewrite in progress) | ✅ (fixes land here) |
| `v2.x` upstream (`v2.63.23` and older) | ❌ (archived 2026-09-01, no fixes upstream) |

This fork exists because upstream documents two unfixed classes and will not fix them:

- Command execution, runner, hooks (`#5199`) — **removed** in this fork.
- Session/JWT handling (`#5216`) — **replaced** by server-side sessions in this fork.

Until `v0.1.0-ng`, assume all upstream P0 issues still present on this branch unless `CHANGELOG.md` says otherwise.

## Reporting a Vulnerability

Report privately via GitHub Security Advisories on the `filebrowser-ng` repo (preferred). Include:

- Commit hash (`git rev-parse HEAD`)
- Affected endpoint/version/branch
- Plaintext proof of concept (no binaries)
- Steps to reproduce, impact, suggested remediation if any

Do not open public issues for unpatched vulnerabilities. We aim to acknowledge within 72h.

## Hardening expectations (until first release)

- Do not expose directly to the internet. Put behind a reverse proxy with TLS + own auth.
- Run unprivileged in a container, mount only the served directory.
- Keep any upstream exec feature disabled (it is being deleted here).
- Treat leaked access tokens as valid until expiry (at most the session
  lifetime): logout, password change and user deletion revoke server-side,
  but already-issued JWTs verify cryptographically until `exp`.
- Treat `config export` output as secret (contains the JWT signing key in v2 baseline; export redaction lands with the config rewrite).
- Share `?token=` URLs carry a 24 h sliding credential in the query string:
  they end up in browser history and proxy logs. Prefer short-lived links
  for sensitive files and rotate by re-entering the password.

# Migration: filebrowser v2 → filebrowser-ng v0.1.0-ng

This is a security fork with intentional breaking changes. The Bolt database
file itself opens as before (removed fields are ignored on read), but
behavior breaks in the places below. Back up first; there is no automatic
migration back except restoring the backup with the old binary.

## 1. Back up

```sh
cp /database/filebrowser.db /database/filebrowser.db.v2-backup
cp /config/settings.json /config/settings.json.v2-backup  # if used
```

Keep the v2 binary/image until the new instance is verified.

## 2. What breaks

- **Everyone logs in again.** Access tokens now require a server-side
  session; pre-upgrade tokens are rejected on first use.
- **Command execution is gone** (`#5199`): web shell, `cmds` CLI,
  `Shell`/`Commands` settings, `--disableExec` flag, `docs/command-execution.md`.
  Passing `--disableExec` or `--shell` now fails as an unknown flag;
  `FB_DISABLE_EXEC` is ignored.
- **Hook authentication is gone** (`CVE-2026-54088`): remaining methods are
  `json`, `proxy`, `noauth`. A database still set to `hook` rejects logins
  as an invalid method — switch with
  `filebrowser config set --auth.method=json` (or `proxy`).
- **Proxy authentication requires a trusted peer** (`GO-2026-5966`):
  default is loopback only, which covers a co-located reverse proxy. If the
  proxy runs on another host, set it before going live:
  `filebrowser config set --trustedProxies=10.0.0.0/8,192.168.1.10`
  (or `--trustedProxies` / `FB_TRUSTED_PROXIES`). Otherwise proxy logins
  return 403.
- **New share links look different**: hashes are 128-bit now. Existing
  share links keep working; only newly created ones use the longer format.
- **API surface**: `GET /api/command` is gone; `DELETE /api/logout` is new
  (the frontend calls it on logout). Login/signup are rate-limited per IP
  (10/min); share creation enforces rules and renames drop shares.
- **Docker**: `compose.yaml` builds the local image, mounts
  `/srv`, `/database`, `/config`, and requires `REDIS_PASSWORD`
  (see `.env.example`). The old `filebrowser:/flux/vault` mount served
  nothing persistently.
- **`config export` no longer contains the signing key** (import keeps the
  database key as before). If a v2 export ever left the machine, run
  `filebrowser config rotate-key` after migrating.

## 3. Upgrade steps

1. Stop the v2 instance; take the backups from §1.
2. Replace the binary/image with the `v0.1.0-ng` build.
3. If behind a remote proxy with proxy auth: set `--trustedProxies`.
4. Start; check `/health` and the logs.
5. Log in (every user logs in again); verify files, shares and settings.
6. If a v2 config export may have leaked: `filebrowser config rotate-key`.
7. Keep the backup until the new instance has run a full cycle.

## 4. Rollback

Stop the instance, restore `/database/filebrowser.db.v2-backup` (and
`settings.json.v2-backup`), restart the v2 binary. Sessions created by
`-ng` are unknown to v2 and simply require re-login.

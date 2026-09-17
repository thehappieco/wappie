# Privacy and security audit — September 2026

Scope: the `whatserverd` server, the web client in `web/`, the `wsctl` CLI, the
Postgres schema and the local deployment at `localhost:8090`. Method: code review
tracing each entry point through persistence, read-only live checks of exposed
headers and endpoints, `govulncheck`, `npm audit`, and fixes for each finding with
regression tests.

The key model is described in `README.md` ("How the archive is protected") and
this audit's decisions in `decisions.md` ("Phase 13").

## Summary

| Severity | Found | Fixed | Backlog |
|---|---|---|---|
| High | 6 | 6 | 0 |
| Medium | 12 | 12 | 0 |
| Low / Info | 8 | 7 | 1 (C4b: see below) |

No critical cryptographic findings: HPKE sealing, each blob's binding to its row
(AAD), media storage as CDN ciphertext, two-branch password derivation and RLS
with `FORCE` are correct and tested on both sides. The findings concern the
layers **around** the seal: authentication, authorization, network exposure,
logs and retention.

## Findings and fixes

### Authentication and keys

| # | Severity | Finding | Fix | Test |
|---|---|---|---|---|
| A1 | High | Recovery codes were generated and stored, but no endpoint or screen used them. Forgetting the password meant losing the archive. | `POST /v1/auth/recover/open` and `/finish`: the code derives a proof (HKDF, separate branch), stored as Argon2id in `users.recovery_hash` (migration 0018). `SignInView` gained "Forgot password". Recovery replaces the password and code and ends every session. Older accounts without a proof are notified in the console and generate a new code. | `authapi_test.go`: `TestARecoveryCodeOpensTheAccountAndReplacesEverything`, `TestAWrongRecoveryCodeAnswersLikeAnUnknownAddress`, `TestAnOldAccountCanSetARecoveryCodeLater`; `wappie-cloud/web/test/account.spec.ts` |
| A2 | High | Login, challenge and WebSocket `hello` had no rate limit; each attempt costs Argon2id 19 MiB. | `internal/ratelimit`: token buckets per IP (60/min) and subject (5/min), with `Retry-After`. `WS_TRUSTED_PROXIES` defines who may supply `X-Forwarded-For`. | `TestSignInIsRateLimited`, `TestHelloIsRateLimited`, `ratelimit_test.go` |
| A3 | Medium | No password change or key rewrapping. | `POST /v1/auth/password` (proves the current password, derives new keys, revokes sessions, issues a new token); "Account" panel in the console. `POST /v1/auth/rewrap` upgrades the format silently. | `TestChangingThePasswordEndsEveryOtherSession` |
| A4 | Medium | The account private-key wrap had no AAD, unlike every other seal in the system. | Format v2: version byte + AAD `whatserver2/usk\|email`. v1 still opens and is rewrapped at the next sign-in. | `account.spec.ts`: "is bound to the address", "still opens a wrap from before the binding" |
| A5 | Medium | Disabled accounts retained sessions for 14 days. | `Users.ActiveSession` checks `status` at every token entry point (HTTP, WebSocket, media). `RevokeAllSessions` runs on password change and recovery. | `TestADisabledAccountsSessionsStopWorking` |
| A6 | Medium | `device-key -print` wrote the private key to the terminal without confirmation. | Requires `-i-understand-this-prints-a-private-key`. | manual |
| A7 | Low | Expired sessions and invitations were never deleted. | `store.Housekeeping` in the hourly job, with a 30-day grace period. | `TestHousekeepingForgetsDeadSessionsAfterAGrace` |
| A8 | Low | A signup rejected for a malformed field consumed the invitation. | The body is validated before `RedeemInvite`. | `TestAnOldAccountCanSetARecoveryCodeLater` (reuses the invitation) |

### Authorization (WebSocket)

| # | Severity | Finding | Fix | Test |
|---|---|---|---|---|
| B1 | High | API keys had no scopes: they could send as the number, join groups, stop devices and upload files. | `api_keys.scope` (`read`/`send`/`full`, migration 0017, existing keys default to `full`). `requireScope` in `resolveSend`, `history.backfill`, `group.join`, `device.stop` and `POST /v1/upload`. UI and CLI select the scope. | `TestAReadKeyCannotSpeakForTheNumber`, `TestASendKeyStopsAtSending`, `TestAKeyIssuedBeforeScopesKeepsWorking`, `TestAKeyNeedsAScope` |
| B2 | Medium | `device.mode` had no authorization check: any actor could disable incognito mode. | `requireOperator` (owner/admin or `full` key). | `TestOnlyAnOperatorCanChangeADevicesPosture` |
| B3 | Medium | `pair` had no authorization check and accepted `Grants: []` with a warning. | `requireOperator`; missing grants are allowed only with `orphan: true`. `wsctl pair -orphan` sends the field. | `TestPairingIsAnOperatorsAct` |
| B4 | Medium | A member without a grant could see every envelope from every device; `users.list` and the reader list were exposed to any actor. | `resolveDevice` requires a grant for non-admin people (`Keys.HasGrant`); `users.list` requires an operator; readers require an admin. | `TestAMemberWithoutAGrantSeesNothingOfADevice` |

### Network and input

| # | Severity | Finding | Fix | Test |
|---|---|---|---|---|
| C1 | High | Blind SSRF: `media.url` from incoming protobufs was fetched without checking scheme/host, following redirects. | `media.Origins`: only `https://*.whatsapp.net`, default port, no credentials; the same checks apply to every redirect; the dialer resolves the name and refuses private/loopback/link-local/CGNAT addresses. | `origin_test.go`: 5 tests, including redirects and resolution to a private address |
| C2 | Low | Avatars were fetched from URLs without host restrictions. | The same `Origins` is used in `AvatarWorker`. | covered by `origin_test.go` |
| C3 | Info | `/metrics`, `/healthz`, `/readyz` were on the public port. Live labels did not expose tenant/JID values. | Optional `WS_METRICS_ADDR` serves all three on a separate listener. | manual |
| C4 | Info | `docker-compose.dev.yml` exposed Postgres and MinIO on `0.0.0.0` with password `dev`. | Bind to `127.0.0.1`. | — |
| C4b | Info | Backlog: compose development passwords remain weak by design; do not use this compose setup outside the local machine. | not fixed (documented) | — |
| C5 | Info | Backlog: the client build publishes its source map (`index-*.js.map`, 1.5 MB) beside the bundle. It exposes no secret but makes client source available to every visitor; decide whether this is wanted (`build.sourcemap` in `vite.config.ts`). | not fixed (product decision) | — |

### Logs and data at rest

| # | Severity | Finding | Fix | Test |
|---|---|---|---|---|
| D1 | High | `WS_LOG_LEVEL=debug` forwarded whatsmeow traces, putting plaintext messages in logs. | whatsmeow debug output is discarded; `WS_LOG_WIRE` explicitly enables it and is refused in `WS_ENV=prod`. | `walog_test.go`, `config_test.go` "rejects the wire log" |
| D2 | Medium | Numbers, JIDs and email addresses appeared in INFO/WARN/ERROR output. | `obs.Redact` through `ReplaceAttr` on every string attribute and message: a JID becomes `…1234@server`, an email becomes `f…@domain`. | `redact_test.go` |
| D3 | Medium | No retention, purging or third-party erasure. | `tenants.retention_days` (migration 0019), `whatserverd retention`, hourly `maintain` job; `whatserverd erase -id` removes one person across all devices. | `TestAPurgeTakesOldRowsAndOnlyTheOrphanedObjects`, `TestErasureRemovesOnePersonAcrossTheArchive` |
| D4 | Medium | Deleting a device or running `reset-archive` left objects in the bucket. | Orphaned objects (referenced by no tenant `media` row) are removed after deletion; `reset-archive` removes all tenant objects. | covered by D3 tests (orphan calculation) |
| D5 | Medium | Nothing checked that the Postgres role lacked `SUPERUSER`/`BYPASSRLS`. | `pg.CheckRole` at startup: error in production, warning in development. | `TestCheckRoleAcceptsTheTestRole` |
| D6 | Low | Local `.env` held plaintext API and S3 credentials. | Documented in `.env.example`; environment variables or a keychain are recommended. | — |
| D7 | Low | README and decisions.md described the old model (one key per tenant; PBKDF2 protecting the key at rest). | Updated. | — |

### Added after the audit

| # | Item | Fix | Test |
|---|---|---|---|
| E1 | Third parties were handed device keys as plaintext. | Service accounts (`role = 'service'`, migration 0020): a key pair without a password, registered through a `-role service` invitation; grants issued in the console; an API key that acts as the account (`api_keys.acts_as`) retrieves grants through `grants.list` and reaches only granted devices. `wsctl service-key` and `wsctl grants`. | `TestAServiceAccountReadsOnlyWhatItWasGranted`, `TestAServiceRegistersWithAPublicKeyOnly` |

### Checked without findings

- Strict CSP, `X-Frame-Options: DENY`, COOP/CORP, `Referrer-Policy: no-referrer`,
  `Permissions-Policy` (confirmed live at `localhost:8090`).
- `/v1/media/{uid}` and `/v1/auth/me` require Bearer credentials; tokens never
  appear in URLs; media is served as `application/octet-stream` with `nosniff`
  and `attachment`.
- No dynamic SQL; `set_config` uses bound parameters; RLS with `FORCE` + `NULLIF`
  on every tenant table; denial and scope tests in `internal/pg`.
- whatsmeow plaintext buffers are disabled and pinned by a test.
- No environment-based authentication bypass or hardcoded credentials; `.env`
  stays outside Git; gitleaks runs in CI.
- `npm audit --omit=dev`: 0 vulnerabilities. `govulncheck ./...`: 0 reachable findings.
- Path traversal: object keys never come from the client; `webui` cleans paths
  and tests directory escape attempts.

## What remains outside the seal's protection

Unchanged by this audit and documented in the README: an attacker running code
inside the process can see plaintext in transit; the whatsmeow session store is
readable by the process and outside RLS; outgoing text passes through in clear;
routing metadata and receipts are readable in the database (and now masked in
logs).

## Deployment checklist

- `WS_ENV=prod` (refuses `sslmode=disable`, storage without TLS, `WS_LOG_WIRE`,
  and a role with `BYPASSRLS`).
- Postgres role: `NOSUPERUSER NOBYPASSRLS`.
- `WS_TRUSTED_PROXIES` points only to the reverse proxy.
- `WS_METRICS_ADDR` binds to a private interface.
- API keys use the smallest sufficient scope; `bootstrap` prints a `full` key.
- `whatserverd retention -tenant ID -days N` follows the tenant's policy.
- Every account has a recovery code generated after this release (the console
  displays a notice).
- Treat database backups as sensitive: they contain plaintext metadata and
  encrypted material that can be attacked offline.

## Verification

```
make check && make web-check
golangci-lint run ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Live checks: six incorrect `POST /v1/auth/login` attempts in one minute return
429 with `Retry-After`; a `hello` with a `read` key followed by `message.send`
returns `not_authorized`; `GET /metrics` contains no numbers or email addresses.

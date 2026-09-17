# Distribution and deployment

## Public server

Go 1.26.7 and PostgreSQL 18 build and run the server, API administration and Go
CLIs. Node is required only for the optional public TypeScript SDK/account CLI.
The public repository contains no app, console or billing sources. Standalone
installations require no Wappie subscription. `WS_WEB_DIR` defaults to empty.

Follow the README for database bootstrap, an owner invitation and optional S3
storage. Create the human account with the public CLI before pairing. Keep the
application database role non-superuser and without BYPASSRLS.

`WS_ENV=prod` requires verified TLS for PostgreSQL and HTTPS for configured object
storage. Put the API behind an HTTPS proxy that preserves Host and WebSocket
upgrades. Keep metrics on a private listener with `WS_METRICS_ADDR`.
`deploy/compose.yaml` builds the public-only image and uses your external
PostgreSQL/S3 settings from `.env`; `docker-compose.dev.yml` provides local test
services. These two configurations are independent.

### Name in WhatsApp's Linked devices

`WS_WA_DEVICE_NAME` defaults to `whappie` for independent installations. Managed
hosting sets `WS_WA_DEVICE_NAME=whappie cloud` in its runtime environment. These
are the two supported values. Restart the server after changing the setting.

The name is sent during registration, for both QR and code pairing. The optional
CLI `-display-name` / API `display_name` is a separate browser descriptor for code
pairing and keeps its required `Browser (OS)` format, such as `Chrome (Linux)`.

Existing links retain their registered name: WhatsApp's reconnect payload does
not resend these device properties. This update does not unlink or re-pair any
number. Verify the new name on the phone after a new pairing; do not remove a
working link solely to apply a cosmetic change. Protocol details are covered by
the [pinned upstream registration and login payloads](https://github.com/tulir/whatsmeow/blob/33cfac511629/store/clientpayload.go).

```
make build
make client-install client-check
make public-source
```

The source exporter uses explicit public roots, excludes private checkouts,
dependencies, generated assets and Git history, and refuses UI components or
secret configuration files. CI extracts that archive and builds it independently.
The public container copies only server/CLI binaries. Publish the SDK with its
own package metadata; inspect `npm pack --dry-run` before publishing.

## Private hosted product

The private `wappie-cloud` checkout owns `web/`, UI tests, billing, deployment
files and the hosted build pipeline. It is developed at `commercial/` inside a
compatible core checkout; this directory is ignored by public Git. Its own
Makefile and CI install dependencies, verify Go/UI tests and build the hosted
app. CI's `WAPPIE_CORE_REF` must identify the matching public core revision.

The private release script accepts only built assets and explicit binaries,
refuses source maps, and requires a new destination so the previous artifact
remains available. Existing URLs and archive formats remain unchanged. The
hosted operations guide is in the private repository's `docs/deployment.md`.

## Enabling external clients

Configure each remote installation with the exact allowed app origins:

```
WS_BROWSER_ORIGINS=https://app.wappie.thehappie.co
```

HTTP, WebSocket, media and calling use the same policy. Non-browser clients still
use ordinary credentials. Discovery is public, but archive endpoints are not.
See [external clients](external-clients.md).

## Storage rollout

Migration 0034 introduces versioned persistent accounting with unlimited policy
by default. Apply and measure existing workspaces before setting a limit. Use
`whatserverd storage -tenant UUID -reconcile` for a measured baseline. Configure
hosted packages in the private catalog; an external installation sets its own
policy and is not charged Wappie storage. See [storage](storage.md).

Retain a matching previous private artifact and database/object backups before
rollout. Database migrations are forward-only; verify old binary compatibility
before reverting an executable. Do not restore an older archive over newer
messages. Restore backups into separate storage when testing rollback. Never
run two runtimes against the same WhatsApp session. No archive migration or
re-pairing is necessary for frontend extraction.

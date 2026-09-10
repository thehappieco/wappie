# Wappie deployment

The public core is independent of commercial hosting. Keep the existing module/binary names (`whatserver2`, `whatserverd`, `wsctl`) for compatibility. Build with Go 1.26.7 and PostgreSQL 18; the Vue client builds independently with the package lockfile.

## Self-hosted

Follow README for database bootstrap, a workspace, an owner invite, storage and frontend build. A single origin can serve both the client and `/v1/*`; `/console` starts administration. No commercial module is needed. Workspace capacity is unlimited unless explicitly set by the operator. Use separate non-superuser database roles and backups. Never use a superuser application connection: it bypasses row-level security.

`WS_ENV=prod` requires encrypted database and object-storage connections. Configure `sslmode=verify-full` and a trusted CA for Postgres, and HTTPS for S3-compatible storage. Keep metrics on a private listener using `WS_METRICS_ADDR`. The public reverse proxy must forward WebSocket upgrades and retain the browser's Host header.

## Official pilot topology

| Address | Destination |
| --- | --- |
| wappie.thehappie.co | Static homepage and `/docs/` |
| console.wappie.thehappie.co | Public console entry; HTML redirects to `https://app.wappie.thehappie.co/console` |
| app.wappie.thehappie.co | Messaging at `/`, administration at `/console`; same-origin `/v1` proxy |
| api.wappie.thehappie.co | HTTP and `/v1/ws` API |

Both interactive screens use the app origin so the browser's encrypted session
survives navigation in Safari as well as Chromium. The console entry preserves
workspace, device and Stripe-return query parameters. Its existing API and asset
routes remain available; only HTML navigation redirects. The API's web handler
implements this temporary redirect, so the existing four-name Nginx and TLS
configuration stays valid. See [browser session lifecycle](browser-sessions.md).

The EC2 runs the compiled ARM64 API and private simulated billing binaries directly under systemd (`wappie-api` and `wappie-billing`). The unit files in `deploy/` use a dedicated unprivileged `wappie` user, a read-only filesystem and `/opt/wappie/release` as their working directory. Runtime configuration is `/opt/wappie/runtime.env`, owned by root with mode 0600; systemd reads it before dropping privileges. No application source or build toolchain is needed on the host.

Build with `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`; deploy binaries to `/opt/wappie/release/bin` and the hosted frontend to `/opt/wappie/release/web`. Create the system user with `useradd --system --home-dir /opt/wappie --shell /usr/sbin/nologin wappie`. Install the two units in `/etc/systemd/system`, reload systemd, then enable them with `systemctl enable --now wappie-api wappie-billing`. Stop the corresponding container services before starting native services on the same ports. The billing binary and hosted UI come from the private cloud repository; self-hosters omit billing.

PostgreSQL and MinIO remain in the isolated Compose project `wappie`. Start them with `docker compose -f compose.yaml -f compose-native.yaml up -d db objects`. On a native-only installation, link `compose.override.yaml` to `compose-native.yaml` so ordinary Compose commands also use this configuration. `WAPPIE_OBJECTS_VOLUME` selects an existing migrated volume (default: `wappie_objects`). For a fresh installation, create it first with `docker volume create wappie_objects`. It is declared external so removing the Compose stack does not remove its attachments. The override exposes only loopback ports 15432 and 19000 and places containerized API/billing behind an optional rollback profile. Nginx continues to proxy the native API on loopback 18090, billing on 18091 and does not expose metrics on 19090. Set `WS_TRUSTED_PROXIES=127.0.0.1/32` for the native API. Existing Nginx sites remain independent.

Use `sslmode=verify-full` for PostgreSQL and HTTPS for object storage. Internal certificates must include `localhost` and `127.0.0.1` when accessing the loopback ports; copy the public CA certificate to `/opt/wappie/release/ca.crt` (mode 0644) and reference it in the database DSN and `SSL_CERT_FILE`. Keep private certificate directories restricted. Preserve the CA and credentials outside source control. Bind every application listener explicitly to `127.0.0.1`.

For a migration, pause the source API before taking its database and object-store snapshots. Keep the source stopped while the destination runs the same WhatsApp session. Restore into a separate database and object volume, preserve existing hosted accounts and invites, verify checksums and table counts, then switch services. Keep the original destination database and object volume for rollback. Set `WAPPIE_DATABASE` and `WAPPIE_MEDIA_BUCKET` in the Compose environment to the same migrated database and bucket used by `runtime.env`. If falling back to the container runtime, stop both native services first, then start the `container-runtime` profile; continue using the migrated data so new messages are preserved. Never run both runtimes against the same WhatsApp session. Do not reset or re-pair devices as part of a storage migration.

## DNS and HTTPS

Create A records `wappie`, `console.wappie`, `app.wappie`, and `api.wappie` in the `thehappie.co` zone, pointing to the existing EC2 public address. Verify all four public DNS responses before requesting a certificate. Install only the Wappie Nginx site; validate the complete configuration before reloading. Obtain one certificate with all four names via the webroot `/var/www/wappie-acme`. After issuance, activate `nginx-https.conf`. HTTP only serves ACME until TLS is ready; it does not expose account logins in cleartext.

## Operations

Pin pulled container images by their verified digest for repeatable releases. Deploy a validated frontend and matching API together. Preserve release artifacts and database backups before updates. SQL migrations are forward-only; roll back application binaries only after checking schema compatibility. Restore a database backup into a separate volume for destructive rollback.

Take database dumps using a dedicated backup identity capable of reading all tenants (the isolated pilot uses its database administrator only for backup) and store encrypted backups separately from the EC2; back up the object-store volume as well. A dump without stored media is not a complete attachment backup. Verify restoration before relying on backups. The pilot has one host and is not highly available.

Internal leaf certificates expire after one year; rotate them before expiry and restart the database/object store after replacing files. Preserve the CA securely. Public certificate renewal should use the installed Certbot timer and reload Nginx. Test renewal after DNS/TLS activation.

The pilot has no live charging, prices, SLA, automated off-host backup or real WhatsApp test-number pairing configured by the code. Those operational steps must be verified on the running environment; do not infer them from a successful build.

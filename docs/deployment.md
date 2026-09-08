# Wappie deployment

The public core is independent of commercial hosting. Keep the existing module/binary names (`whatserver2`, `whatserverd`, `wsctl`) for compatibility. Build with Go 1.26.7 and PostgreSQL 18; the Vue client builds independently with the package lockfile.

## Self-hosted

Follow README for database bootstrap, a workspace, an owner invite, storage and frontend build. A single origin can serve both the client and `/v1/*`; `/console` starts administration. No commercial module is needed. Workspace capacity is unlimited unless explicitly set by the operator. Use separate non-superuser database roles and backups. Never use a superuser application connection: it bypasses row-level security.

`WS_ENV=prod` requires encrypted database and object-storage connections. Configure `sslmode=verify-full` and a trusted CA for Postgres, and HTTPS for S3-compatible storage. Keep metrics on a private listener using `WS_METRICS_ADDR`. The public reverse proxy must forward WebSocket upgrades and retain the browser's Host header.

## Official pilot topology

| Address | Destination |
| --- | --- |
| wappie.thehappie.co | Static homepage and `/docs/` |
| console.wappie.thehappie.co | Client in administration mode; same-origin `/v1` proxy |
| app.wappie.thehappie.co | Messaging client; same-origin `/v1` proxy |
| api.wappie.thehappie.co | HTTP and `/v1/ws` API |

The Compose project in `deploy/` is named `wappie` and uses independent volumes. Nginx remains shared with the host's existing sites. API and billing bind only to host loopback ports 18090 and 18091. Metrics use loopback 19090. Database and object storage have no host ports. Internal TLS uses a local CA and hostname verification; private keys and generated credentials stay in `/opt/wappie`, outside source control.

The provided Compose profile includes the private pilot billing binary. For self-hosting, use the core's README and omit that service; the commercial binary and UI are not distributed in the public core. The runtime Dockerfile expects an already built `release/bin/`, `release/web/`, and `release/ca.crt` build context. The EC2 is ARM64: build `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`.

Initial setup: prepare the host, start the database and object store, build/start the API (which applies the core migrations), apply the private billing schema as the application role, then start billing. Provision two pilot workspaces with two slots each and issue owner invites. Use test numbers only. No WhatsApp device is paired by deployment.

## DNS and HTTPS

Create A records `wappie`, `console.wappie`, `app.wappie`, and `api.wappie` in the `thehappie.co` zone, pointing to the existing EC2 public address. Verify all four public DNS responses before requesting a certificate. Install only the Wappie Nginx site; validate the complete configuration before reloading. Obtain one certificate with all four names via the webroot `/var/www/wappie-acme`. After issuance, activate `nginx-https.conf`. HTTP only serves ACME until TLS is ready; it does not expose account logins in cleartext.

## Operations

Pin pulled container images by their verified digest for repeatable releases. Deploy a validated frontend and matching API together. Preserve release artifacts and database backups before updates. SQL migrations are forward-only; roll back application binaries only after checking schema compatibility. Restore a database backup into a separate volume for destructive rollback.

Take database dumps using a dedicated backup identity capable of reading all tenants (the isolated pilot uses its database administrator only for backup) and store encrypted backups separately from the EC2; back up the object-store volume as well. A dump without stored media is not a complete attachment backup. Verify restoration before relying on backups. The pilot has one host and is not highly available.

Internal leaf certificates expire after one year; rotate them before expiry and restart the database/object store after replacing files. Preserve the CA securely. Public certificate renewal should use the installed Certbot timer and reload Nginx. Test renewal after DNS/TLS activation.

The pilot has no live charging, prices, SLA, automated off-host backup or real WhatsApp test-number pairing configured by the code. Those operational steps must be verified on the running environment; do not infer them from a successful build.

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

### Remote MCP connector

The optional [remote MCP connector](mcp.md) is a second process, the Node 22
reader in `packages/mcp-http`. It is the OAuth 2.1 resource and authorization
server for `/mcp`; the Go server only keeps the connection registry and relays
opaque blobs to it. The reader holds no archive private key and cannot open
sealed content, so a compromise of that process exposes metadata, API keys of
consented connections and OAuth tokens, not message text. Leave it off unless
you want claude.ai or ChatGPT connectors; without `WS_MCP_ENABLED=true` the
`/v1/mcp/*` routes are not mounted and discovery is unchanged.

Both processes bind loopback only and are published by the same HTTPS proxy.
Set `WS_MCP_ENABLED`, `WS_MCP_READER_URL` (an `http://127.0.0.1` URL),
`WS_MCP_RELAY_SECRET` (at least 32 bytes, shared with the reader through a
0600 file owned by the reader's service user, `wappie-mcp`, and named by
`WAPPIE_MCP_RELAY_SECRET_FILE`; the reader refuses a file owned by anyone else),
`WS_MCP_PUBLIC_ORIGIN` (the HTTPS origin whose `/mcp` path is the OAuth
resource) and `WS_MCP_REDIRECT_HOSTS` on the server; give the reader the same
public origin, the console URL used for consent and the archive server's
loopback address. The redirect-host list must be identical on both sides. The
internal relay routes accept only loopback peers carrying the relay secret and
refuse any request with `X-Forwarded-For`; the proxy must still return 404 for
`/v1/mcp/internal` so they are never reachable by name. Fetching client
metadata documents (CIMD) goes through the Go relay, because the reader is
denied outbound network access and the relay applies the redirect-host
allowlist, an 8 KiB cap and a 5 s timeout.

nginx locations, ahead of the catch-all `location /` of the API host:

```
location ^~ /v1/mcp/internal { return 404; }
location ^~ /mcp {
    proxy_pass http://127.0.0.1:18093;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto https;
    proxy_buffering off;
    proxy_read_timeout 120s;
    client_max_body_size 1m;
}
location ^~ /.well-known/oauth-protected-resource { proxy_pass http://127.0.0.1:18093; proxy_set_header Host $host; }
location ^~ /.well-known/oauth-authorization-server { proxy_pass http://127.0.0.1:18093; proxy_set_header Host $host; }
```

`/mcp/register` and `/mcp/token` take the same proxy settings with a 16k body
cap and tighter request limits. Run rate limits in dry-run mode first: assistant
providers reach the endpoint from shared egress addresses, and a per-address
limit sized for browsers will throttle every user of the provider at once.

Run the reader as its own system user under a hardened unit: `User=wappie-mcp`,
`StateDirectory=wappie-mcp` (the reader refuses a state directory or key file
that is not 0700/0600), `EnvironmentFile` root-owned 0600, `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`,
`SystemCallFilter=@system-service`, `IPAddressDeny=any` with
`IPAddressAllow=localhost`, and a memory cap such as `MemoryMax=512M`. The
state directory holds the reader's X25519 recipient key, the key that encrypts
its state file and the state itself (consented connections with their API
keys, registered OAuth clients, pending requests and token hashes). Back it up
with the database; a restore cannot resurrect a revoked connection, because the
reader re-checks every connection against the Go registry at startup and drops
whatever is not `active`.

Self-hosters can run the reader as a container instead: `deploy/compose.yaml`
carries it as an optional service (`--profile mcp-http`) built from
`deploy/Dockerfile.mcp-http`, with a persistent volume for the state directory
and the same environment as the unit. The service joins the API container's
network namespace (`network_mode: service:api`) rather than the compose
bridge, because both relay guards accept only a loopback peer and Go accepts
only a loopback `WS_MCP_READER_URL`: the reader reaches the API at
`http://127.0.0.1:8090`, the API reaches the reader at
`WS_MCP_READER_URL=http://127.0.0.1:18093` (set in `.env`), and the `api`
service publishes `127.0.0.1:18093` on the host for the reverse proxy (the
reader listens on `0.0.0.0:18093` inside that namespace, because a published
port is delivered to the container's bridge address, not to its loopback).
One difference from the unit: host connections arrive through Docker's port
proxy, so the reader sees the bridge gateway as its peer, not loopback, and
therefore ignores `X-Forwarded-For`. Its per-address limits then count the
whole installation as one address (`/mcp/authorize` twenty a minute and ten
pending, `/mcp/authorize/complete` ten a minute); the limits keyed on
connection, client and token family are unaffected.

Rollback is not a symlink swap for this release. Migrations 0039 and 0040 add
`api_keys.expires_at` and the `mcp_connections` table, and the previous
executable refuses to start against a schema it does not know. To go back:
stop the reader, stop the API, run the down-step in one transaction
(`DROP TABLE mcp_connections; DROP INDEX api_keys_expiring; ALTER TABLE
api_keys DROP COLUMN expires_at; DELETE FROM schema_migrations WHERE version IN
(39, 40);`), then restore the previous executable and start it. Every consented
connection is lost; users approve again after a later roll-forward. Rehearse
the down-step against a copy before relying on it.

### Attested reader (Nitro Enclave)

The hosted connector at `https://mcp.wappie.thehappie.co/mcp` runs the same
reader inside an AWS Nitro Enclave: TLS ends inside it, its OAuth state and
relay secret open only inside it (KMS keys whose policy admits only released
images), and a browser checks which code it talks to before sealing anything
to it. A `metadata` connection there reads what the loopback reader above
reads. A `content` connection can also open message text, names and filenames
of its numbers, with a key that exists only in the enclave's memory; the
archive server enables it only with `WS_MCP_CONTENT_ENABLED=true` and only for
the workspaces in `WS_MCP_CONTENT_TENANTS` (both in [MCP setup](mcp.md)). The
loopback reader above never accepts a content bundle. The contract (topology,
HMAC relay, endpoints, attestation, sealed state, log schema, content) is
[mcp-enclave.md](mcp-enclave.md). Self-hosted installations do not need it;
the loopback reader above keeps working unchanged.

What is public, so anyone can check a running reader:

- `deploy/enclave/Dockerfile`: the enclave image. Base images are pinned by
  digest, npm and cargo dependencies by lockfile, and every file time is
  clamped to `SOURCE_DATE_EPOCH` in a single-layer image, so two builds of one
  commit give the same filesystem, which is what PCR0 measures. The Alpine
  packages still come from the branch's current index, which is why each
  release also publishes the exact image by digest.
- `deploy/enclave/entrypoint.sh`: brings loopback up, bridges vsock to
  loopback with `socat`, and restarts Node in a loop with its output on
  `/dev/null` (the only output channel is a schema-checked log line over vsock).
- `deploy/enclave/nsm-attest/`: the Rust helper that asks the Nitro Secure
  Module for attestation documents.
- `deploy/enclave/build.sh` (on an arm64 host with Docker and `nitro-cli`):
  builds the image with the KMS key ARNs written into `constants.mjs`, the EIF,
  the key policies rendered from `deploy/enclave/kms/` and their hashes, and
  `measurements.json` (PCR0-2, EIF and image digests, `nitro-cli` version and
  blob hashes). Each release is published as `reader-v<version>` with those
  files.
- `tools/reader-verify/`: sends a fresh nonce to the reader's public
  `/attestation`, verifies the document against a release's
  `measurements.json`, and checks that the TLS connection ended inside that
  enclave. `tools/ct-watch/` watches Certificate Transparency for certificates
  the enclave did not attest.

```
make enclave-check      # the enclave package's tests
make enclave-image      # build and check the image on arm64 (no EIF; it refuses to boot without key ARNs)
make reader-verify      # the verifier CLI's and the CT monitor's tests
```

The parent host runs only byte pipes: haproxy in TCP mode (TLS ends in the
enclave; ALPN `acme-tls/1` goes to the enclave's certificate challenge
listener, everything else arrives with a PROXY v2 header), `vsock-proxy` with
an allowlist for KMS, the archive API and Let's Encrypt, and a log receiver
that drops any line outside the schema. Its units and runbook are part of the
private hosted product.

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
hosted operations guide is in the private repository's `docs/deployment.md`;
its remote MCP runbook (reader key rotation, backup and restore, the schema
down-step and lifting the proxy's rate-limit dry run) is private as well, while
the [connector layout above](#remote-mcp-connector) is the same for both. The
attested reader's parent-host units and runbook are private too; its image,
build and verifier are the public ones described above.

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
rollout. Database migrations are forward-only, except for the documented
[remote MCP down-step](#remote-mcp-connector); verify old binary compatibility
before reverting an executable. Do not restore an older archive over newer
messages. Restore backups into separate storage when testing rollback. Never
run two runtimes against the same WhatsApp session. No archive migration or
re-pairing is necessary for frontend extraction.

# Distribution and deployment

## Public server

Go 1.26.9 and PostgreSQL 18 build and run the server, API administration and Go
CLIs. go.mod's `go 1.26.7` is only the oldest toolchain that compiles them;
build with 1.26.9 or a later patched release, since 1.26.7 has net/http
advisories that 1.26.9 fixes. Node is required only for the optional public TypeScript SDK/account CLI.
The public repository contains no app, console or billing sources. Standalone
installations require no Wappie subscription. `WS_WEB_DIR` defaults to empty.

Follow the README for database bootstrap, an owner invitation and optional S3
storage. Create the human account with the public CLI before pairing. Keep the
application database role non-superuser and without BYPASSRLS.

`WS_ENV=prod` requires verified TLS for PostgreSQL and HTTPS for configured object
storage, and `WS_LOGIN_DECOY_KEY_HEX`: 32 random bytes in hex
(`openssl rand -hex 32`), kept in the secret store and unchanged across
restarts. It keys the sign-in challenge answered for an address with no
account, so nobody can compute that answer and compare. Put the API behind an HTTPS proxy that preserves Host and WebSocket
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
archive server enables it only with `WS_MCP_CONTENT_ENABLED=true`, and then
only in the workspaces whose owner turned text on, starting from
`WS_MCP_WORKSPACE_DEFAULT` (all in [MCP setup](mcp.md)). The
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
down-steps, such as the [remote MCP one](#remote-mcp-connector) and
[0050's](#rolling-back-below-0050); verify old binary compatibility
before reverting an executable. Do not restore an older archive over newer
messages. Restore backups into separate storage when testing rollback. Never
run two runtimes against the same WhatsApp session. No archive migration or
re-pairing is necessary for frontend extraction.

## Deleted numbers and the deletion ledger

Migration 0050 keeps a deleted number 30 days, recoverable by an owner, and
then purges it ([device lifecycle](devices.md#deletion-and-recovery)). The
hourly janitor of every server process does the purge, in every workspace
whatever its status. Every deletion, recovery, purge and move to Personal
is also appended to the **deletion ledger**, a file outside the database
that a restore replays over an older snapshot, so that no number deleted,
purged or moved since the snapshot comes back as it was. The events behind
it are described in [item events](item-events.md).

**The file.** `WS_DELETION_LEDGER`, by default
`/var/lib/wappie/deletion-ledger.jsonl`. Put it on a persistent path that is
in the host's backups and off-host copies, writable by the server's user
alone, and delete its copies before they are 90 days old, as the backups'.
In `deploy/compose.yaml` it is the named volume `deletion-ledger`, mounted
on `/var/lib/wappie`, which `deploy/Dockerfile` creates 0700 for uid 10001:
back that volume up with the database. One JSON line per event:
`{v, event_id, type, workspace_id, device_id, deleted_at, purge_after,
deleted_by, to_workspace_id, occurred_at}`, every key present and null when
it does not apply, times in UTC. It holds no label, no phone number and no
content; `deleted_by` is the local id of the owner who deleted. The server
creates it with mode 0600 and appends with `O_APPEND`, syncing the file (and
its directory when it creates it) before it marks the events exported, so
the export is at least once: a line may appear twice, never zero times.
Export and compaction hold an exclusive lock on `<ledger>.lock` beside it.

- **When it is written.** After each delete, recovery and move, before the
  reply; after each purge; at every hourly pass; and by
  `whatserverd deletions export-ledger`. A failed write logs ERROR
  "deletion ledger export failed" and leaves the events for the next export.
- **At start.** In prod, serve checks the file right after its setup and
  before its "starting" line. It logs INFO "deletion ledger writable" with
  the path, creating the file when it is missing, or ERROR "deletion ledger
  not writable" with the path and the error, and starts anyway: nothing is
  lost while the file cannot be written, and only a restore reads it.
- **Compaction.** Once a day each process drops the lines of every number
  whose newest line is older than 93 days: backups are deleted before they
  are 90 days old (decision 0027), and three days of slack cover a host or
  an off-host copy whose expiry ran late. It writes the kept lines beside
  the ledger, syncs them and renames them over it.
- **The hosted unit** gets its directory from systemd: `StateDirectory=wappie`
  and `StateDirectoryMode=0700` in `wappie-api.service` (or the pilot's
  drop-in), which keeps `/var/lib/wappie` writable under
  `ProtectSystem=strict`.

**The purge**, at each hourly pass, within a 15-minute budget of its own:
at most 5 numbers per workspace, starting each pass one workspace further
on, in short transactions of at most 2000 rows per table. A number a client
or a logout still holds waits for the next pass. Rows, keys, grants and any
WhatsApp session left by an unconfirmed logout (removed by its fingerprint,
never logged out) go on schedule; an attachment object whose delete fails
stays in storage, still charged, for the orphan pass. Each object delete is
bounded at 10 seconds, and after 3 failures in a row the rest of the pass
leaves them to the orphan pass (WARN "object deletes keep failing"). A
finished purge logs INFO "number purged" with its counts. The janitor warns
of a number more than 2 hours past its date ("a deleted number is overdue
for its purge") and of a pass that ran out of its budget.

**The valve.** `WS_DELETED_NUMBER_PURGE=hold` (default `on`) stops every
purge for an incident, and each pass logs WARN "deleted-number purges are
held" with the number due. It is never a way to keep a number past its 30
days: a suspended or closed workspace's numbers are purged on their date
too.

### Operator commands

```
whatserverd devices list-deleted [-tenant ID]
whatserverd devices purge-deleted [-tenant ID] [-device ID [-now]]
whatserverd deletions export-ledger
whatserverd deletions replay -ledger FILE -snapshot-time STAMP [-dry-run] [-ledger-adds-nothing] [-leave-excluded ID]...
```

None of the four migrates. Each refuses a database whose schema is not
exactly this binary's, so a dry run over a restored snapshot changes
nothing and the export can run before a down-step. Run them as the server's
user, with its configuration, so they can write the ledger. `whatserverd`
serves only with no arguments or with `serve`: any other command, or a
`devices` or `deletions` subcommand, that it does not know prints the
command list and exits 2, so a mistyped command never starts a server whose
first janitor pass would purge.

- `devices list-deleted` lists each deleted number of every workspace (or
  one) by id: when it was deleted, when it is purged, its state
  (`recoverable`, `due`, `overdue by …`, `purging`), its status, and whether
  a WhatsApp session is left. Never a name or a phone number. It ends with
  whether this user can write the ledger.
- `devices purge-deleted` purges the due numbers of every workspace (or
  one), as the janitor does. With `-device` it purges that number if it is
  due; `-now` purges it before its date, only with its owner's agreement.
  Its record then says it was purged early.
- `deletions export-ledger` appends every workspace's unexported events.
- `deletions replay` is the restore's step below.

### Rehearsing a purge

Nothing advances a deleted number's date, so a rehearsal or a deploy's
smoke test makes its own test number due and runs the due path, exactly as
the janitor runs it. Only on a test number, with its owner's agreement: the
number is purged at once. As the server's database role, in one
transaction, with the two settings the store's own scope sets (a role that
bypasses row-level security does not need them):

```sh
psql "$WS_POSTGRES_DSN" -v ON_ERROR_STOP=1 -v tenant=WORKSPACE_ID -v device=NUMBER_ID <<'SQL'
BEGIN;
SELECT set_config('app.tenant_id', :'tenant', true), set_config('app.device_quarantine', 'on', true);
UPDATE devices SET purge_after = clock_timestamp() - interval '1 minute'
 WHERE id = :'device' AND deleted_at IS NOT NULL AND purge_started_at IS NULL;
COMMIT;
SQL
whatserverd devices purge-deleted -tenant WORKSPACE_ID
```

The update says `UPDATE 1`; `UPDATE 0` is a number that is not deleted, not
in that workspace, or already being purged. The command prints
`purged NUMBER_ID in WORKSPACE_ID: …` and logs INFO "number purged"; the
workspace's `item_events` gain a `purged` row and the ledger a `purged`
line, whose `purge_after` is the backdated one (a replay accepts that). If
the running server's hourly pass purged the number first, its "number
purged" line is in that server's log instead.

### Restoring a backup

A snapshot is older than the ledger. Restore it like this, with the server
stopped:

1. **The database and the objects**, as usual.
2. **The ledger.** Never overwrite a ledger that survived on the host: use
   it. Otherwise use the newest off-host copy. Use the copy inside the
   snapshot being restored only when nothing newer exists: it is as old as
   the database and adds nothing. Put it back owned by the server's user,
   mode 0600.
3. **Migrations.** If the snapshot's schema is older than the binary's,
   migrate first, on its own: any command other than the four above
   migrates as it starts, and `whatserverd tenants` changes nothing else.
   The replay never migrates.
4. **The replay**, before the server starts, as the server's user:
   `whatserverd deletions replay -ledger FILE -snapshot-time STAMP`, where
   `STAMP` is the snapshot's own time (`YYYYMMDDTHHMMSSZ`, a backup
   directory's name, or RFC 3339). Run it with `-dry-run` first: that runs
   every step in its real transaction and rolls it back, so it reports the
   same changes and refusals and changes nothing (sequences may advance).
   - It prints the time of the ledger's newest line beside the later of the
     snapshot's time and the restored database's newest ledgered event, and
     refuses a ledger that adds nothing (most likely the snapshot's own
     copy) unless `-ledger-adds-nothing` says that is the one to use.
   - It folds each number's lines by cause, never by time: a `purged` line
     is final; a deletion is undone exactly when a `recovered` line names
     its `deleted_at`. A torn last line (a crash) is skipped and reported; a
     damaged line before valid ones, a `deleted` line whose `purge_after` is
     not its `deleted_at` plus 30 days, or two deletions left unreversed
     stop it before anything changes.
   - It looks for each number in every workspace. A number found in another
     workspace than its ledger says (a snapshot from before a move to
     Personal) makes it refuse; `-leave-excluded ID` excludes that number
     where it is instead (with the ledger's dates, or now and 30 days on for
     a number that only moved), or the move can be redone by hand after the
     replay.
   - Then, per workspace in one transaction, every exclusion and purge
     before any recovery. A number the ledger says is deleted is excluded
     again with the ledger's dates, off every restricted key, its assistant
     connections ended. One it says was purged is excluded and left due, so
     the first janitor pass purges it. One it says was recovered is
     recovered with no window or capacity check, and a workspace left over
     its plan is reported. A recovery that cannot apply (the phone is
     linked again as another number, or its purge had started in the
     snapshot) refuses, and that workspace's transaction rolls back.
   - It sends no notice. Each change writes its event row with the ledger
     line's own `event_id`, marked ledgered and replayed, so it can run
     again.
   - Whatever stops it (a refusal, a missing or damaged ledger, one that
     adds nothing, a flag it cannot read), its error ends with `do not start
     wappie-api`, and it exits non-zero.
5. **Start the server.**

A snapshot taken while a number was deleted keeps its `purge_after`, so the
janitor still purges it on time. If the host is lost, a deletion made after
the last off-host copy of the ledger is lost with everything else made after
it, and its owner has to delete again.

### Rolling back below 0050

A binary older than 0050 refuses a database at version 50, so its
down-step comes first. No number may be left deleted through it: an older
binary would show and sync it as live. And an older binary lets
administrators delete a number at once, with no recovery. In this order:

1. `whatserverd devices list-deleted`. An owner recovers each deleted
   number in the console, or, with the owner's agreement,
   `whatserverd devices purge-deleted -device ID -now` purges it. The purge
   does not wait for object storage; objects it could not delete stay for a
   later orphan pass, and each purge prints how many `failed` and how many
   it `left for the orphan pass`. If either is not zero, let an hourly pass
   of this release run with object storage healthy, so its orphan pass
   deletes them, and record the counts and the `storage_objects` keys that
   no `media` row names (read as the tables' owner) that are still there.
   The down-step drops the indexes that let the orphan pass finish on a
   large workspace, so under the older binary such objects can stay in the
   bucket, still charged, until a release with 0050 runs again or someone
   deletes them by hand.
2. Stop the server, and every other process that runs this release's store
   code against the database (the hosted billing service is one), unless it
   already runs the release being restored.
3. `whatserverd deletions export-ledger`, as the server's user, so no event
   row is dropped before the ledger has it.
4. The down-step in the header of `0050_device_deletion.sql`, after checking
   the file's sha256 against the release's (`migration50_sha256` in a hosted
   `RELEASE.json`), as the owner of the tables, in its one transaction. Its
   guards run first: it refuses while a number is deleted, while an event
   row is not in the ledger, or while a migration after 0050 is applied, and
   a refusal changes nothing. If it refuses, start the server on this
   release again and stop the rollback: never leave it stopped on schema 50.
   It comes before 0049's down-step, which has no such guard.
5. Switch back to the older binary and start it.
6. Take a fresh backup. A snapshot older than a purge made under 0050
   still holds that number, so restoring it needs this release's binary,
   and its own way back down, in this order:
   1. migrate the restored database to 50 and run the replay, dry run
      first, as [Restoring a backup](#restoring-a-backup) says. The replay
      leaves each number the ledger says was purged excluded and due, and
      each deletion no recovery reversed excluded: the down-step would
      refuse;
   2. `whatserverd devices purge-deleted`, without `-now`: it purges the due
      numbers, which are the ones already purged before;
   3. `whatserverd devices list-deleted`, then step 1 above for each number
      still deleted: an owner recovers it, with the server running on this
      release, or, with the owner's agreement, `devices purge-deleted
      -device ID -now` purges it;
   4. steps 2 to 5 above: stop the server and the billing service, export
      the ledger, run the down-step, and switch back.

The down-step drops the notices and the event rows; the ledger file stays
as the record. The API keys 0050 revoked (those whose creator was disabled
or had left) stay revoked.

# Wappie MCP HTTP: the hosted, metadata-only connector

`@whatserver2/mcp-http` serves the same read-only tools as
[`packages/mcp`](../mcp/README.md) over **Streamable HTTP**, so claude.ai and
ChatGPT can connect to a Wappie installation as a remote MCP server. It is the
open source half of the hosted connector: one Node process on loopback behind
the reverse proxy, next to the Wappie API. Requires Node.js 22 or later.

It is **metadata-only by construction**. A connection carries a device-scoped,
read-only API key and nothing else: no archive private key, no service account,
no contact snapshot, no password. Every `list_chats` name, message body and
attachment filename stays `locked`; `search_messages` with a text query answers
`content_sealed_metadata_only`. That code, and every description and locked
reason the assistant sees on a hosted connection, is chosen from
`credential_source`: the local stdio install can be opted into plaintext and
says so, a hosted connection never can, and must not send its user after a
setting that cannot exist. The reader cannot decrypt anything even
if a bundle tried to give it the means, because the credential provider it hands
the shared reader refuses `serviceKey()` and `contactPack()` outright.

## What runs where

| Piece | Where | Role |
|---|---|---|
| Resource server (`POST /mcp`) | this process | Bearer-protected JSON-RPC over Streamable HTTP; one `McpServer` per request, built by `@whatserver2/mcp` with a provided credential |
| Authorization server (`/mcp/authorize`, `/mcp/token`, `/mcp/register`, `/mcp/revoke`) | this process | OAuth 2.1 with PKCE S256, RFC 8707 `resource`, RFC 7591 registration and Client ID Metadata Documents, rotating refresh tokens |
| Discovery (`/.well-known/oauth-protected-resource[/mcp]`, `/.well-known/oauth-authorization-server[/mcp]`) | this process | RFC 9728 and RFC 8414 documents, identical on both path forms |
| Consent | the Wappie console (`WAPPIE_MCP_CONSOLE_URL`) | the workspace owner picks the numbers, the expiry and the timezone, and seals the API key to this reader |
| Registry and relay (`/v1/mcp/*`) | the Wappie API (`WS_MCP_ENABLED=true`) | stores the connection rows, relays the sealed bundle and the consent descriptor, answers status checks, fetches client metadata documents |

Whoever can issue tokens can read, so the authorization server lives here and
not in the Go API; the API only ever sees an opaque sealed blob and a status.

The MCP SDK is imported exclusively through `@whatserver2/mcp/sdk`, so the
process holds one copy of `@modelcontextprotocol/server` and the class identity
checks inside `createMcpHandler` hold. This package deliberately declares no
`@modelcontextprotocol/*` dependency (the client SDK is a test-only dev
dependency), and the `node:http` bridge is the small `node-adapter.mjs`.

## The handshake

1. The assistant discovers the resource metadata from the `401` challenge on
   `POST /mcp`, reads the authorization server document, and either registers
   (RFC 7591) or presents an HTTPS `client_id` (CIMD). Registration accepts
   `redirect_uris` on the allowlisted hosts only (`https:`, default port, no
   userinfo or fragment) and **assigns `token_endpoint_auth_method: none`**
   whatever was requested: every client is public.
2. `GET /mcp/authorize` checks the exact `redirect_uri`, `response_type=code`,
   `code_challenge_method=S256`, `resource` byte-equal to `PUBLIC_ORIGIN/mcp`,
   `scope ⊆ wappie:read` and an optional `state`, stores a pending request for
   twenty minutes and redirects to the console with `?mcp_connect=<request_id>`.
3. The console fetches the request descriptor (`kid`, reader public key, client
   name, redirect host, `code_challenge`, `resource`) through the API, issues a
   provisional device-scoped API key, seals the bundle with HPKE to the reader
   key (`info` `wappie-mcp-connect/v1`, AAD binding request id, `kid` and
   resource) and posts it to the API, which relays it here over loopback. The
   bundle is opened, checked (`allow_plaintext:false`, no service identity, no
   contacts, `server_url` equal to the resource origin, `workspace_id` equal to
   the tenant Go names, a 43-character `link_secret`) and zeroed.
4. The browser posts `request` and `proof` (an HMAC-SHA256 under the link secret
   over the request id, client id, code challenge and the sealed bytes) to
   `POST /mcp/authorize/complete`. The `Origin` header must be the console's:
   that is the CSRF check. Three wrong proofs burn the request and revoke the
   connection in Go. A good proof activates the connection, stores the API key
   in the encrypted state and redirects back to the client with a single-use
   sixty-second code, the `state` and `iss`.
5. `POST /mcp/token` exchanges the code (all of `client_id`, `code_verifier`,
   `redirect_uri` and `resource` must match) for a fifteen-minute access token
   and a refresh token that idles out after thirty days and never outlives the
   consented connection expiry. Refresh rotates the pair; a second presentation
   within thirty seconds receives the identical successor pair (a retry whose
   answer was lost, or two clients refreshing together); anything later, or a
   grandparent token, or a replayed code, kills the whole family and revokes
   the connection.

Every `POST /mcp` re-checks the connection status in Go at most once a minute;
a connection revoked in the console stops serving within that minute and is
wiped locally. Refresh always asks Go.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `WAPPIE_MCP_LISTEN` | `127.0.0.1:18093` | bind address; keep it on loopback behind the proxy |
| `WAPPIE_MCP_PUBLIC_ORIGIN` | derived from a loopback listen address | the HTTPS origin clients see, e.g. `https://api.wappie.thehappie.co`; required for any non-loopback deployment |
| `WAPPIE_MCP_CONSOLE_URL` | required | the console page that renders consent, e.g. `https://app.wappie.thehappie.co/console`; its origin is the only accepted `Origin` on the completion post |
| `WAPPIE_MCP_STATE_DIR` | `/var/lib/wappie-mcp` | `0700` directory holding `keys/recipient.key`, `keys/recipient.previous`, `keys/state.key` and `state.json.enc` |
| `WAPPIE_MCP_RELAY_SECRET_FILE` | required | `0600` file with the secret shared with the API (`WS_MCP_RELAY_SECRET`), at least 32 characters |
| `WAPPIE_MCP_ARCHIVE_URL` | `http://127.0.0.1:18090` | the API base for both the archive REST calls and `/v1/mcp/internal/*` |
| `WAPPIE_MCP_REDIRECT_HOSTS` | `claude.ai,chatgpt.com` | hosts a `redirect_uri` or CIMD `client_id` may use; must equal the API's `WS_MCP_REDIRECT_HOSTS` |
| `WAPPIE_MCP_CIMD` | `on` | advertise and resolve Client ID Metadata Documents (fetched by the API relay, cached for a day) |
| `WAPPIE_MCP_PENDING_TTL_SECONDS` | `1200` | how long a consent may stay pending |

### The console document may not declare `no-referrer`

The consent form is a top-level cross-origin POST from the console to
`/mcp/authorize/complete`. A document served with `Referrer-Policy: no-referrer`
or `same-origin`, or carrying `<meta name="referrer" content="no-referrer">`,
makes the browser replace the `Origin` header with the literal `null` on that
post, and the reader refuses it. Serve the console with
`strict-origin-when-cross-origin`: it sends the bare origin off-site and never
the path or the query, so the consent request id still stays where it was.

`whatserverd` does this for the page it serves. A console behind some other
static server must set it there. The three refusals are told apart in the log
and on the refusal page: `origin_missing` (no header at all), `opaque_origin`
(the literal `null`, i.e. this misconfiguration) and `invalid_origin` (a real
origin that is not `WAPPIE_MCP_CONSOLE_URL`'s).

Two SDK notices are normal at startup: the reader answers JSON, not SSE, so
the SDK prints that mid-call notifications are dropped.

## State and keys

The state directory is created `0700` and every file inside it `0600`; a file
readable by other users refuses startup (`state_file_unsafe`,
`state_key_unsafe`, `state_dir_unsafe`). `state.json.enc` is AES-256-GCM under
`keys/state.key` and holds registered clients, active connections (with their
API keys) and token hashes; pending consents and authorization codes live in
memory only, so a restart during a consent simply asks for a new one. Writes go
through an exclusively created temporary file and a rename. At startup the
reader asks Go about every stored connection and drops whatever is no longer
`active`; if Go cannot be reached the state is kept and the per-request check
catches up.

To rotate the recipient key, stop the reader, move `keys/recipient.key` to
`keys/recipient.previous`, start it again: a new key is generated, the
descriptor advertises its `kid`, and bundles sealed to the previous key still
open until you delete the previous file.

## Limits and logs

In process: `/mcp` sixty requests a minute per connection; `/mcp/token` three
hundred a minute per address before the grant is known (a `client_id` is
public, so it never keys a bucket on its own), then twenty a minute per token
family and per connection; `/mcp/authorize/complete` three proof attempts per
request and ten posts a minute per address; `/mcp/authorize` twenty a minute
and ten pending requests per address, taken before anything is looked at, and
three uncached CIMD documents a minute per address (a document that failed to
resolve is not asked for again for a minute); registration five a minute per
address, five hundred live clients in total, two hundred per redirect host,
thirty days unused once a user consented to the client and an hour otherwise
(at a cap the never-consented client used longest ago makes room); two hundred
pending requests nobody consented to (the oldest makes room) and a thousand in
total. The client address is the socket peer, or the last `X-Forwarded-For`
entry when the peer is loopback; an IPv6 /64 counts as one address.
Body caps: 1 MiB on `/mcp`, 96 KiB on the internal bundle route, 16 KiB
elsewhere; headers time out after ten seconds, requests after sixty.

The log is one JSON line per request on stdout: `ts`, `route` (the route
template, never a path with ids), `status`, `ms`, `conn` and `client` as sha256
prefixes, and a short `code`. Never a query string, header, body, token or key.

## Self-hosting

The public repository ships `deploy/Dockerfile.mcp-http` (build from the
repository root) and an optional `mcp-http` service in `deploy/compose.yaml`:

```sh
docker build -f deploy/Dockerfile.mcp-http -t wappie-mcp-http:local .
docker compose -f deploy/compose.yaml --profile mcp-http up -d
```

The API must run with `WS_MCP_ENABLED=true`, `WS_MCP_READER_URL` pointing at
this process, the same relay secret and the same redirect host list, and the
reverse proxy must route `/mcp`, `/mcp/*` and both `/.well-known/oauth-*`
prefixes here while returning `404` for `/v1/mcp/internal`. Client metadata
documents are fetched by the API, so the reader itself needs no egress.

The compose service joins the API container's network namespace
(`network_mode: service:api`) instead of the bridge. Both relay guards accept
only a loopback peer and the API accepts only a loopback `WS_MCP_READER_URL`,
so the reader reaches the API at `http://127.0.0.1:8090`, is reached at
`WS_MCP_READER_URL=http://127.0.0.1:18093` (set in `.env`), and is published
on the host as `127.0.0.1:18093` by the `api` service; it listens on
`0.0.0.0:18093` there because a published port is delivered to the
container's bridge address, not to its loopback. Do not loosen the guards to
put the reader on the bridge: they are what keeps the relay secret and the
sealed bundles on one host. One consequence of the port proxy: connections
from the host reach the reader from the bridge gateway, not from loopback, so
`X-Forwarded-For` is not trusted and the per-address limits above count the
whole installation as one address; the per-connection, per-client and
per-family limits are unaffected. `deploy/smoke-mcp-http.sh <image>` checks
this layout with a stub container in place of the API.

Without a container:

```sh
npm --prefix packages/client ci && npm --prefix packages/client run build
npm --prefix packages/mcp ci
npm --prefix packages/mcp-http ci
WAPPIE_MCP_PUBLIC_ORIGIN=https://api.example.test WAPPIE_MCP_CONSOLE_URL=https://app.example.test/console \
WAPPIE_MCP_RELAY_SECRET_FILE=/etc/wappie/mcp-relay-secret node packages/mcp-http/server.mjs
```

## The attested reader (`enclave/`)

`enclave/main.mjs` runs this same reader inside an AWS Nitro Enclave at
`https://mcp.wappie.thehappie.co/mcp`, still metadata-only. The contract is
`docs/mcp-enclave.md`; what differs from the hosted reader:

- Configuration is `enclave/constants.mjs`, measured into PCR0. Nothing is
  read from the environment; the build fills only the two KMS key ARNs.
- TLS terminates inside the enclave with an ECDSA P-256 key made per enclave
  boot (in `/run/wappie`, RAM only) and a Let's Encrypt certificate ordered
  over TLS-ALPN-01 (`enclave/acme.mjs`, `enclave/tls.mjs`). The public (5443)
  and internal (5444) listeners take PROXY v2 first (`enclave/proxy.mjs`);
  5445 answers only the ACME challenge.
- The OAuth state is sealed per collection under the reader KMS key
  (`enclave/sealer.mjs`, `openSealedState` in `state.mjs`) and stored by Go
  as opaque bytes with compare-and-set generations.
- Go and the enclave sign every request with HMAC in both directions
  (`enclave/hmac.mjs`, `enclave/relay.mjs`); the relay secret arrives as KMS
  ciphertext under the boot key and rotates at runtime
  (`POST /internal/relay-secret`).
- Every consent request gets its own X25519 key, and
  `POST /internal/requests/{id}/prepare` returns the descriptor with a fresh
  attestation document binding that key, the browser's nonce, the TLS SPKI
  and the live KMS key policy hash (`attestation.mjs`, `enclave/policy.mjs`).
  `GET /attestation?nonce=` serves the same without a key, for anyone.
- Logs leave only through the vsock sink, each line checked against the
  parent's schema (`enclave/logsink.mjs`), with a health line every minute
  that includes the clock's skew against KMS's `Date` (`enclave/health.mjs`).

`server.mjs` never imports `enclave/` (a test walks its imports), and the
enclave's dependencies live in its own `enclave/package.json`.

`node enclave/policy.mjs < policy.json` prints the policy hash the console
accepts; `--canonical` prints the canonical bytes.

## Tests

```sh
npm --prefix packages/mcp-http test
node --test --experimental-test-coverage packages/mcp-http/test/*.test.mjs
```

The suite boots the synthetic archive from `@whatserver2/mcp/test/fixture`, a
fake Go implementing `/v1/mcp/internal/*` (with an injectable delay and a fake
clock) and the reader on an ephemeral port, then drives the whole handshake
with `@modelcontextprotocol/client` and a scripted console, plus the negative
matrix: redirect allowlists, CIMD refusals, PKCE and resource mismatches,
code replay, refresh grace and family death, Go revocation and expiry, Host
and Origin checks, bundle invariants, proof tampering and replay, unsafe state
files, oversize bodies, rate limits. Every response body and log line is
checked for the API key, link secrets, proofs and private keys. All test
material is minted at run time; nothing token-shaped is committed.

The enclave has its own suite (`npm --prefix packages/mcp-http/enclave ci`
first, then `npm --prefix packages/mcp-http/enclave test`): the contract's
vectors, sealed state, CMS and KMS, PROXY v2, the HMAC guard, and the whole
enclave booted against a stub `nsm-attest`, an in-memory KMS, a fake Go and a
fake ACME server that really dials the TLS-ALPN-01 listener.

## What this never has

An archive private key. A service account or its key. A contact snapshot. A
password. The plaintext of any message. The reader holds device-scoped,
read-only API keys for the connections its workspace owners consented to, and
those keys can be revoked from the console at any time.

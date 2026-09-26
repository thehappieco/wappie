# Attested MCP reader (milestone 2a): interface contract

Milestone 2a moves the hosted metadata reader into an AWS Nitro Enclave, served
at `https://mcp.wappie.thehappie.co/mcp`. TLS terminates inside the enclave,
the OAuth authorization server and the relay secret live inside it, and the
console verifies an attestation document before it seals anything to the reader.
2a is **metadata-only**: no message text, no service keys and no content bundle
(those are 2b). The hosted reader at `https://api.wappie.thehappie.co/mcp`
(`packages/mcp-http/server.mjs` on `127.0.0.1:18093`, loopback relay in
`internal/mcpauth`) keeps working unchanged.

This document is the contract between five workstreams that implement 2a in
parallel. Where it states a byte layout, a field name, a limit or a status code,
that is the value to implement. A change goes through the lead, not through a
workstream editing another's files.

**Fixed by the owner (2026-09-25):** one environment only (`mcp.`, no
`mcp-staging.`), so the Go readers are `hosted` and `enclave`. AWS account
`768406580484`, `eu-west-1`. The parent is the spike instance
`i-05cdefb4833fdf39e` (`c7g.large`, enclave CID 16, 1 vCPU, 1536 MiB). PCR3 is
SHA-384(48 zero bytes ‖ the parent's **role** ARN), so the spike role name
flows into the key policy. Ephemeral key mode is the 2b default, and attachments
come in a later stage. Neither affects 2a.

## 1. Topology

```
assistant ──TLS──▶ mcp.:443 ─ haproxy (parent, TCP mode)
                              ├─ ALPN acme-tls/1 ─▶ socat ─▶ vsock 16:5445 ─▶ enclave 127.0.0.1:5445  ACME challenge only, no PROXY
                              └─ anything else ──▶ PROXY v2 ─▶ vsock 16:5443 ─▶ enclave 127.0.0.1:5443  public HTTPS
Go (pilot) ──TLS──▶ mcp.:8443 ─ haproxy ─ PROXY v2 ─▶ vsock 16:5444 ─▶ enclave 127.0.0.1:5444  /internal/* only
enclave ─▶ 127.0.0.2:443 ─ vsock 3:8000 ─ vsock-proxy ─▶ kms.eu-west-1.amazonaws.com:443
        ─▶ 127.0.0.3:443 ─ vsock 3:8001 ─ vsock-proxy ─▶ api.wappie.thehappie.co:443   (REST reads + /v1/mcp/enclave/*)
        ─▶ 127.0.0.4:443 ─ vsock 3:8002 ─ vsock-proxy ─▶ acme-v02.api.letsencrypt.org:443
        ─▶ 127.0.0.1:7000 ─ vsock 3:7000  role credentials (IMDSv2 JSON, as in the spike)
        ─▶ 127.0.0.1:7001 ─ vsock 3:7001  boot.json
        ─▶ 127.0.0.1:7002 ─ vsock 3:7002  log sink ─▶ log-sink.py ─▶ journald
```

Every vsock hop is a byte pipe. TLS to KMS, `api.` and ACME is verified inside
the enclave. The enclave's `/etc/hosts` maps the three names to 127.0.0.2, .3
and .4. Never use vsock 9000: nitro-cli reserves it for the boot heartbeat
(spike finding). Node listens only on 127.0.0.1. `entrypoint.sh` bridges vsock
to loopback with `socat VSOCK-LISTEN:<port>,fork TCP:127.0.0.1:<port>`.

## 2. Ownership map

| Workstream | Owns (edits only these) |
|---|---|
| **ENCLAVE** | `packages/mcp-http/**`, including the new `packages/mcp-http/enclave/` with its own `package.json` and `package-lock.json` |
| **GO** | `internal/**`, `cmd/**`, `internal/migrate/sql/0041_mcp_reader.sql`, `go.mod`, `go.sum`, `.env.example`, the Go configuration section of `docs/mcp.md` |
| **VERIFIER** | `packages/client/src/crypto/attestation.ts` (+ tests, + export from `packages/client/src/index.ts`), `tools/reader-verify/**`, `tools/ct-watch/**` |
| **DEPLOY** | `deploy/enclave/**` (`Dockerfile`, `entrypoint.sh`, `nsm-attest/`, `build.sh`, `kms/`), `commercial/deploy/enclave/**`, `commercial/deploy/nginx-https.conf`, `commercial/scripts/release.py`, `commercial/docs/mcp-enclave-operations.md`, `docs/deployment.md`, `scripts/export-public.py`, `Makefile`, `.github/workflows/*` in both repositories |
| **CONSOLE** | `commercial/web/**` (`mcpConnect.ts`, `MCPPanel.vue`, locales, the generated `src/state/readerMeasurements.ts` and its generator `commercial/web/scripts/reader-measurements.mjs`), `commercial/Makefile` if needed |

This file belongs to the lead. When a workstream needs a change in a file it
does not own, it lists the change under `needs_from_others` in its result.

## 3. Reader identity and Go configuration

A **reader id** matches `^[a-z][a-z0-9]{0,15}$`. Its environment suffix is the
id in upper case. For 2a the ids are `hosted` and `enclave`.

| Variable | Reader | Rule |
|---|---|---|
| `WS_MCP_ENABLED` | all | unchanged |
| `WS_MCP_READERS` | all | comma list, default `hosted`; no duplicates, at least one id |
| `WS_MCP_READER_URL`, `WS_MCP_RELAY_SECRET`, `WS_MCP_PUBLIC_ORIGIN` | `hosted` | **today's variables, today's rules** (http loopback URL, bearer secret ≥ 32 bytes). Required only when `hosted` is listed. Any `WS_MCP_READER_HOSTED_*` variable is a config error |
| `WS_MCP_READER_<ID>_URL` | others | `https://<host>:<port>` with no path, query or userinfo; host equal to `PUBLIC_ORIGIN`'s. Enclave: `https://mcp.wappie.thehappie.co:8443` |
| `WS_MCP_READER_<ID>_PUBLIC_ORIGIN` | others | https origin with no path. Enclave: `https://mcp.wappie.thehappie.co` |
| `WS_MCP_READER_<ID>_SECRET` | others | exactly 43 base64url characters (32 random bytes). The HMAC key is the UTF-8 bytes of the string as written, not the decoded bytes |
| `WS_MCP_READER_<ID>_SECRET_NEXT` | others | optional, same shape, different from `SECRET` |
| `WS_MCP_READER_<ID>_PEER` | others | required comma list of IPs or CIDRs (the parent's EIP as `/32`). Compared with `ratelimit.ClientIP(r, TrustedProxies)` |
| `WS_MCP_READER_<ID>_TENANTS` | others | required: a comma list of workspace UUIDs, or the single value `*`. In 2a the value is the test workspace `01a08e0e-c546-7db3-9c44-e6352636d330` |

`WS_MCP_REDIRECT_HOSTS` and `WS_MCP_OPENAI_APPS_CHALLENGE` stay global. The
`hosted` reader keeps its loopback guard and bearer secret on
`/v1/mcp/internal/*`, and every tenant may use it. `String()` prints each
reader's id, URL, origin, `secret=set|unset`, `secret_next=set|unset`, and the
peer and tenant counts, never a secret. Discovery (`cmd/whatserverd/discovery.go`)
keeps `endpoints.mcp_server` for `hosted`. When `enclave` is configured it adds
`endpoints.mcp_server_attested = <enclave PUBLIC_ORIGIN>/mcp`.

## 4. HMAC request authentication (both directions, non-hosted readers)

Every request between Go and a non-hosted reader carries these headers:

| Header | Value |
|---|---|
| `X-Wappie-Reader` | reader id, e.g. `enclave` |
| `X-Wappie-Timestamp` | Unix seconds, decimal, no sign and no leading zero |
| `X-Wappie-Nonce` | 22 base64url characters (16 random bytes, fresh per request) |
| `X-Wappie-Signature` | `v1=` followed by 64 lowercase hex characters |

The canonical string is these eight fields joined by a single `\n` (0x0A), with
no trailing newline:

```
wappie-mcp-hmac/v1
<direction>        "to-reader" (Go → reader) or "to-go" (reader → Go)
<reader id>
<METHOD>           upper case
<request-target>   raw path plus query exactly as on the request line, e.g. /v1/mcp/enclave/cimd?url=https%3A%2F%2F…
<timestamp>        the header value
<nonce>            the header value
<body sha256>      lowercase hex of SHA-256 over the exact body bytes (empty body: e3b0c442…b855)
```

The signature is `HMAC-SHA256(key = UTF-8 bytes of the secret, message = UTF-8 canonical string)` in lowercase hex.
The receiver uses the raw request-target (Go: `r.RequestURI`; Node: `req.url`)
and never a re-serialized URL. nginx passes it unchanged because `proxy_pass`
carries no URI part. The direction field stops a request signed for one side
from being replayed to the other.

The receiver checks in this order:
1. Go only: the peer is in `PEER` and `X-Wappie-Reader` names a configured non-hosted reader. Otherwise **404** `{"code":"not_found"}`.
2. All four headers are present and well formed, and `|now − timestamp| ≤ 60 s`.
3. The body is read up to the route's limit (**413** `{"code":"body_too_large"}` above it) and hashed.
4. The expected signature is computed with every accepted secret and compared with a constant-time compare (`subtle.ConstantTimeCompare`, `crypto.timingSafeEqual`). Every secret is tried, with no early exit.
5. Only after a valid signature is `(direction, reader, nonce)` inserted into the replay cache. A nonce already present is a replay. Entries live until `timestamp + 61 s`. The cap is 100,000 entries after sweeping expired ones; when the cache is full the receiver answers **503** `{"code":"replay_cache_full"}` (fail closed).

A failure in steps 2, 4 or 5 answers **401** `{"code":"unauthorized"}` with no
detail. The local log carries `hmac_missing`, `hmac_stale`, `hmac_bad` or
`hmac_replay`. Responses are not signed: TLS authenticates them (WebPKI for
`api.` and for `mcp.`, and CAA restricts `mcp.` certificates to the enclave's
ACME account).

**Secrets and rotation.** Go signs with `SECRET` and accepts `SECRET` or
`SECRET_NEXT`. The enclave boots with one secret S from `boot.json`. It signs
with its *current* secret and accepts *current* and *previous*. To rotate to
S′, in this order:
1. The owner encrypts S′ under the boot key (§7), then sets `SECRET_NEXT=S′` in Go and restarts it.
2. `whatserverd mcp-relay-secret -reader enclave < ciphertext.b64` (a GO subcommand) sends `POST /internal/relay-secret`, signed with S. The enclave now has current S′ and previous S.
3. DEPLOY replaces `boot.json` on the parent with the S′ ciphertext.
4. Go is switched to `SECRET=S′` with `SECRET_NEXT` unset.

The enclave drops *previous* the first time it accepts a request signed with
*current*.

Test vectors (secret `wappie-test-relay-secret-0123456789abcdefghij`, timestamp `1790300000`):
- `to-reader`, `enclave`, `POST /internal/requests/AAAAAAAAAAAAAAAAAAAAAA/prepare`, nonce `BBBBBBBBBBBBBBBBBBBBBB`, body `{"nonce":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}`. The body hash is `5abfe6385851c7e99e840bf25362e735b4adc8b617704a5cab1c8cf3aeae5a8f` and the signature is `v1=4966d2e42ab13456589657b9df8429cd70b95f1ec2f9273e6e27b76aabe53456`.
- `to-go`, `enclave`, `GET /v1/mcp/enclave/cimd?url=https%3A%2F%2Fclaude.ai%2Foauth%2Fmcp-oauth-client-metadata`, nonce `CCCCCCCCCCCCCCCCCCCCCC`, empty body. The signature is `v1=9d67d123516b7dc431b14a28223a654d8f57299cc83022ae17cbc4554baef616`.

## 5. Endpoints

JSON bodies are UTF-8 with `Content-Type: application/json`. Errors are
`{"code": "<snake_case>"}` (Go adds `message`, as today). Every response carries
`Cache-Control: no-store`. The body limit is 64 KiB unless a route says
otherwise. Ids: a request id matches `^[A-Za-z0-9_-]{22}$`; a connection id is a
lowercase UUID.

### 5.1 Go → enclave (`https://mcp.wappie.thehappie.co:8443`, listener 5444, HMAC `to-reader`)

The Go client uses WebPKI with system roots and `ServerName` taken from the URL
host. It uses no proxy (`Proxy: nil`), follows no redirects, allows TLS 1.2 and
up, times out after 10 s, and reads at most 64 KiB of a response.

| Method and path | Request | Success | Other statuses |
|---|---|---|---|
| `GET /internal/healthz` | none | 200 health object (below) | 401 |
| `GET /internal/requests/{id}` | none | 200 descriptor (the fields `link.mjs` `descriptor()` returns today; `reader_public_key` is the request's own X25519 key, and `kid` is the first 16 hex of its SHA-256) | 404, 503 `starting` |
| `POST /internal/requests/{id}/prepare` | `{"nonce": b64url}`: 16 to 64 bytes decoded, strict keys | 200 prepared descriptor (§6.3) | 400 `bad_request`, 404, 429 `too_many_prepares` (more than 10 per request), 503 `policy_unknown`, `tls_not_ready`, `attest_failed` or `starting` |
| `POST /internal/requests/{id}/bundle` | today's `BundleRelay` (`connection_id`, `tenant_id`, `kid`, `sealed`, `expires_at`) | 204 | today's codes; `unknown_kid` if `kid` is not the request's |
| `POST /internal/connections/{id}/revoke` | none | 204 (idempotent) | 401 |
| `POST /internal/relay-secret` | `{"ciphertext": base64}`: standard base64 with padding, 1 to 6144 bytes decoded | 204 | 400 `bad_request`, 502 `kms_failed` |

Health object: `{"ok":true,"reader_id":"enclave","reader_version":"0.2.0","boot_id":<16 hex>,"state":"ready"|"loading","pcr0":<96 hex>,"tls_spki_sha256":<64 hex>|null,"cert_not_after":<RFC 3339>|null,"policy_sha256":<64 hex>|null,"acme_account_uri":<string>|null,"relay_secrets":1|2}`.
Go calls it every 60 s for each non-hosted reader, logs the `pcr0`, SPKI and
policy fingerprints and the certificate's days left, and warns after 3
consecutive failures.

On listener 5443, `/internal` and `/internal/*` always answer 404. On 5444 every
other path answers 404. The Host header is checked against
`mcp.wappie.thehappie.co` (5443) and `mcp.wappie.thehappie.co:8443` (5444).

### 5.2 Enclave → Go (`https://api.wappie.thehappie.co/v1/mcp/enclave/*`, HMAC `to-go`)

nginx serves this location only to the parent's EIP, with
`client_max_body_size 12m`. Go checks `PEER` again. A connection route acts only
on rows whose `reader` equals the caller's id; any other row is 404.

| Method and path | Request | Success | Other statuses |
|---|---|---|---|
| `GET /v1/mcp/enclave/connections/{id}` | none | 200 `{"status","expires_at"}`, as `/v1/mcp/internal/...` | 404 |
| `POST /v1/mcp/enclave/connections/{id}/activate` | none | 204 | 404, 409 `connection_state` |
| `POST /v1/mcp/enclave/connections/{id}/revoke` | none | 204 (idempotent; unknown id also 204) | none |
| `GET /v1/mcp/enclave/cimd?url=<escaped>` | none | 200 document bytes (`application/json`) | 400, 502 `cimd_unavailable` |
| `GET /v1/mcp/enclave/state/{name}` | none | 200 `application/octet-stream`, body = envelope (§8), header `X-Wappie-Generation: <n>` | 404 (never written) |
| `PUT /v1/mcp/enclave/state/{name}?if_generation=<n>` | `application/octet-stream` envelope, at most 12 MiB (12,582,912 bytes) | 200 `{"generation": n+1}` | 409 `{"code":"generation_mismatch","generation":<current or 0>}`, 413, 400 (bad name or `if_generation`) |

`name` is one of `as-clients`, `as-connections`, `as-tokens` or `infra`. The
generation travels in the query rather than in `If-Match` so that the signature
covers it. `if_generation=0` means "create; no row may exist". Go runs a single
`UPDATE … WHERE reader_id=$1 AND name=$2 AND generation=$3` (or `INSERT … ON
CONFLICT DO NOTHING` for 0) and reports 409 when no row changed. The state
handler streams the body under its own 12 MiB cap and never goes through
`decode()` (64 KiB). The enclave relay's timeout is 10 s, or 30 s for state.

### 5.3 Console → Go (`https://api.wappie.thehappie.co`)

| Method and path | Change |
|---|---|
| `GET /v1/mcp/requests/{id}` | Unchanged shape. Go resolves the reader (below) and relays that reader's descriptor verbatim |
| `POST /v1/mcp/requests/{id}/prepare` | **New, public**, rate-limited like the descriptor (`DescriptorLimits`, subject `prepare:<id>`). Body `{"nonce": b64url}` with strict keys, 16 to 64 bytes decoded. For an enclave request: 200 with the enclave's prepared descriptor verbatim, after Go checks that it is a JSON object with the same `request_id`, the reader's `resource`, and an `attestation.document` of at most 16 KiB. For a `hosted` request: 409 `attestation_unsupported`, without calling the reader. 404 and 429 as for the descriptor; 502 `reader_unavailable` |
| `POST /v1/mcp/connections` | Same body (`DisallowUnknownFields` stays). Go resolves the reader. For a non-hosted reader it answers 403 `tenant_not_allowed` if the tenant is outside `TENANTS`, and 409 `attestation_required` unless this Go process served a prepare for this id whose `kid` equals `body.kid`. `resource` is checked per reader, and `complete_url = <reader PUBLIC_ORIGIN>/mcp/authorize/complete`. The row records `reader` and `reader_measurement` |
| `DELETE /v1/mcp/connections/{id}` | Revokes in the ledger, then tells the row's own reader |

**Which reader owns a request id.** Go keeps an in-memory map from request id to
`{reader, kid, pcr0, document_sha256}`, with a 30-minute TTL and at most 10,000
entries. On a miss it sends `GET /internal/requests/{id}` to every configured
reader concurrently. The first 200 wins, is cached, and the other requests are
cancelled. If every reader answers 404, Go answers 404. Otherwise (no 200 and at
least one failure) it answers 502 `reader_unavailable`. A prepare refreshes the
`kid`, `pcr0` and `document_sha256` of the entry.
`reader_measurement = "nitro:pcr0=<96 hex>;doc=<64 hex sha256 of the document bytes>"`,
using the `pcr0` the enclave declares. The hosted reader's value is NULL. Go does
not verify attestations: the browser is the verifier (plan 2a.16).

### 5.4 Public routes on the enclave (listener 5443)

The existing public routes are unchanged: `/.well-known/*`, `/mcp`,
`/mcp/authorize`, `/mcp/authorize/complete`, `/mcp/token`, `/mcp/register` and
`/mcp/revoke`. The consent completion accepts only the console origin
`https://app.wappie.thehappie.co`. One route is new:
`GET /attestation?nonce=<b64url, 16 to 64 bytes>`. It is rate-limited to 10 per
minute per IP (`ipKey` of the PROXY v2 source). It answers 200 with
`{"attestation": <object §6.3>}`, where `request_id` is `""` and the document
has no `public_key`. It answers 400 `bad_request`, 429, or 503 as for prepare.
It has no CORS headers.

## 6. Attestation

### 6.1 Keys

- **Per-request X25519 key.** `as.mjs` `authorize()` generates it with
  `hpke.generateKeyPair()` for every pending request, imports it at once with
  `hpke.importArchiveKey()` (non-extractable `CryptoKey`), and zeroes the raw
  bytes. It is stored as `pending.recipient = {kid, publicKey, publicKeyEncoded, privateKey}`,
  which has the shape `recipientFrom()` returns today. It is memory-only and
  dies with the request. `kid` = the first 16 lowercase hex characters of
  SHA-256(raw public key). 2b replaces the import with the plan's handoff.
- **Per-boot RSA-2048 key**, used only as the KMS `Recipient` (`RSAES_OAEP_SHA_256`),
  as in `spike/enclave/app/kms.mjs`. Its documents carry `public_key` = SPKI
  DER and no `nonce` or `user_data`. They are never returned to a browser, and a
  request document is never sent to KMS.
- **Per-boot TLS key**: ECDSA P-256 (§10.3).

### 6.2 The NSM request for a request document

`nsm-attest <public_key_hex> <nonce_hex> <user_data_hex>` (the spike's
contract) is called with:
- `public_key` = the **raw 32-byte X25519 public key**, not SPKI.
- `nonce` = the browser's nonce bytes as decoded (16 to 64 bytes).
- `user_data` = 32 bytes, `SHA-256(preimage)`. `preimage` is the UTF-8
  encoding of these six fields joined by a single 0x00 byte (none may contain
  0x00):

```
"wappie-mcp-attest/v1" 0x00 request_id 0x00 resource 0x00 tls_spki_sha256 0x00 policy_sha256 0x00 reader_version
```

`request_id` is the 22-character id, or `""` for `/attestation`. `resource` is
`https://mcp.wappie.thehappie.co/mcp`. `tls_spki_sha256` is 64 lowercase hex
characters of SHA-256 over the DER SubjectPublicKeyInfo of the serving
certificate's key. `policy_sha256` is 64 lowercase hex characters (§7).
`reader_version` matches `^[0-9]+\.[0-9]+\.[0-9]+$`.
Vector: `request_id = AAAAAAAAAAAAAAAAAAAAAA`, `tls_spki_sha256 = "a"×64`, `policy_sha256 = "b"×64`, version `0.2.0` → `user_data = a63c1d0bc8fd8789d35f08c48db83edc71e71ae751d624ff9159fa5c3d50aad8`.

Every prepare and every `/attestation` call gets a fresh document. Documents are
never cached. Without a certificate (`tls_not_ready`), without a policy hash
younger than 20 minutes (`policy_unknown`), or when the NSM fails
(`attest_failed`), the answer is 503.

### 6.3 The prepared descriptor and the attestation object

```json
{ "request_id": "…", "kid": "…", "reader_public_key": "<b64url 32 B>", "client_id": "…", "client_name": "…",
  "redirect_host": "…", "redirect_local": false, "code_challenge": "…", "resource": "https://mcp.wappie.thehappie.co/mcp",
  "expires_at": "…",
  "attestation": { "format": "aws-nitro-v1", "document": "<b64url COSE_Sign1, ≤ 16 KiB decoded>",
    "request_id": "…", "resource": "https://mcp.wappie.thehappie.co/mcp", "reader_id": "enclave",
    "reader_version": "0.2.0", "tls_spki_sha256": "<64 hex>", "policy_sha256": "<64 hex>", "pcr0": "<96 hex>" } }
```

`pcr0` is informational (Go stores it). The enclave reads it from its own
document with `decodeAttestationDocument`. The verifier uses only the document.

### 6.4 Rules the console enforces (CONSOLE with VERIFIER)

The attested flow applies exactly when `descriptor.resource === READER_RESOURCE`
(the constant `https://mcp.wappie.thehappie.co/mcp`). Any other resource takes
today's hosted flow, unchanged. In the attested flow:
1. Generate 32 random bytes as the nonce and call prepare.
2. Call `verifyAttestation` with `requestId = id`, `resource = READER_RESOURCE`, `requirePublicKey: true`, the allowlist and policies from `readerMeasurements.ts`, and `maxSkewMs = 600000`.
3. Require `result.publicKey` (32 bytes) to equal the decoded `reader_public_key`, and `kid` to equal the first 16 hex of its SHA-256.
4. Seal to `result.publicKey` only, and take every other field from the prepared descriptor.

There is no fallback to the hosted flow. With no valid attestation the consent
is refused with the verifier's `attestation_*` code.

## 7. KMS keys and the policy hash

| Key (ARN by **key id**, constant in the image, never an alias) | Enclave uses | Contexts |
|---|---|---|
| `wappie-mcp-reader` | `GenerateDataKey` and `Decrypt`, always with `Recipient`, with `KeyId` pinned in every `Decrypt` | state: `{purpose:"wappie-mcp-reader-state", reader_id:"enclave", origin:"https://mcp.wappie.thehappie.co", name:<collection>}`; infra: `{purpose:"wappie-mcp-reader-infra", reader_id:"enclave", origin:"https://mcp.wappie.thehappie.co"}` |
| `wappie-mcp-boot` | `Decrypt` with `Recipient` only | `{purpose:"wappie-mcp-relay", reader_id:"enclave"}` (the owner's `aws kms encrypt` uses exactly this) |

The enclave calls `GetKeyPolicy(KeyId=<reader key>, PolicyName="default")` with
the role credentials over vsock 8000: at boot, then every 10 minutes. The
**canonical form** is RFC 8785 JSON Canonicalization (JCS) of the parsed policy
document. Object keys are sorted by UTF-16 code units, arrays keep their order,
and nothing is normalized beyond JCS (a one-element array and a bare string
hash differently). `policy_sha256` = lowercase hex SHA-256 of the canonical
UTF-8 bytes. A value older than 20 minutes counts as unknown.

KMS stores a key policy in its own normal form: every one-element array
becomes its single value (`["x"]` becomes `"x"`), and `GetKeyPolicy` returns
that form. `render.py` therefore writes policies already in that form, so the
published file, its published hash and what the enclave reads back agree.
Found with release 0.2.0: its first published hashes (`2fd7f570…`) were of the
array form, while KMS returned `c451898b…`.
Vector: `{ "Version": "2012-10-17", "Statement": [ { "Sid": "A", "Effect": "Allow" } ] }` canonicalizes to `{"Statement":[{"Effect":"Allow","Sid":"A"}],"Version":"2012-10-17"}`, whose SHA-256 is `50647085b9c42d40af6dec1918c5cb5d97788849feb2377004e08874304d3373`.
There is one implementation. ENCLAVE exports it from
`packages/mcp-http/enclave/policy.mjs` and makes that file runnable
(`node policy.mjs < policy.json` prints the hash; `--canonical` prints the
bytes). DEPLOY calls it and does not reimplement it. Only the reader key's
policy is hashed: the boot key protects a secret Go already knows.

**Owner-only administration.** Both key policies delegate administration to
the account (`arn:aws:iam::<account>:root`), which on its own would let any
IAM principal whose IAM policy allows it, such as an operator permission set,
change or delete the key. The policies therefore also carry the Deny
`OnlyOwnerAdministers` on `kms:PutKeyPolicy`, `kms:ScheduleKeyDeletion`,
`kms:CancelKeyDeletion`, `kms:DisableKey` and `kms:EnableKey` for every
principal whose `aws:PrincipalArn` is not an owner, and the boot key the Deny
`OnlyOwnerEncrypts` on `kms:Encrypt`, so only an owner can encrypt a relay
secret. `kms:CreateGrant` is denied to everyone (`DenyGrants`). The owners are
the `@OWNER_ARNS@` element, rendered from `render.py --owner-arn` (repeatable;
build.sh passes it through), by default the account root ARN, which as
`aws:PrincipalArn` matches the root user only. An owner is the root, an IAM
user or an IAM role of the parent's account (for an IAM Identity Center
permission set, the role ARN with its `aws-reserved/sso.amazonaws.com/…`
path); never an `sts` session ARN, never the parent role. The owner applies
the policy as one of the owners, so KMS's lockout safety check (the caller
must still be able to `PutKeyPolicy`) passes. Optional hardening, not in the
template: an `aws:MultiFactorAuthPresent` condition on the owner's actions. It
is left out because it would lock out an owner that signs in without MFA
(a root user with no MFA device).

## 8. Sealed state

**Envelope v1** (binary, big-endian; the exact body of GET and PUT):

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | ASCII `WMCPSEAL` |
| 8 | 1 | version `0x01` |
| 9 | 2 | `L` = length of the KMS `CiphertextBlob`, 1 to 6144 |
| 11 | L | `CiphertextBlob` of the data key |
| 11+L | 12 | AES-GCM IV (random per write) |
| 23+L | 16 | AES-GCM tag |
| 39+L | rest | ciphertext |

AES-256-GCM with AAD = UTF-8 of `JSON.stringify(["wappie-mcp-state", 1, "enclave", name, generation])`,
where `generation` is the value the blob is written as (`if_generation + 1`).
The plaintext is UTF-8 JSON. For `as-*` it is
`{"version":1,"name":<name>,"records":[…]}`, and the records are what
`state.mjs` persists today for `clients`, `connections` and `tokens`. For
`infra` it is `{"version":1,"name":"infra","acme":{"account_uri":<string>,"account_key":<EC P-256 private JWK>}}`.
The enclave refuses a plaintext above 11 MiB (event `state_too_large`) and
keeps serving from memory. Any failure to open (context, tag, AAD or shape) is
`state_auth_failed`, and the process exits.

**Keys and writes.** The first write of a collection in a boot calls
`GenerateDataKey` once, and the data key stays in memory for that boot.
`save()` keeps its API: it writes every collection whose serialized plaintext
SHA-256 changed since the last successful write, with at most one write in
flight and one queued per collection. Go assigns generations as
`if_generation + 1`, starting at 1.

**Boot, and Go unreachable.** At boot all four names are loaded (404 = empty).
Loading retries with backoff from 1 s, doubling to 60 s, and nothing is served
(`/internal/*` answers 503 `starting`) until all four are loaded. A collection
is never PUT unless it was loaded. After boot, a failed PUT leaves the
collection dirty, is retried with the same backoff, and emits `state_save_failed`;
serving continues from memory. A **409** means a second writer or tampering: the
event `state_conflict` is emitted, the process exits, and the supervisor loop
reloads. Changes made since the last successful write are lost, by design.

**Go side.** `internal/migrate/sql/0041_mcp_reader.sql`:
`ALTER TABLE mcp_connections ADD COLUMN reader text NOT NULL DEFAULT 'hosted' CHECK (reader ~ '^[a-z][a-z0-9]{0,15}$'), ADD COLUMN reader_measurement text;`
`CREATE TABLE mcp_reader_state (reader_id text NOT NULL, name text NOT NULL CHECK (name IN ('as-clients','as-connections','as-tokens','infra')), generation bigint NOT NULL CHECK (generation > 0), blob bytea NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (reader_id, name));`
The table has no RLS, as with 0040. The descent is documented by DEPLOY in
`mcp-enclave-operations.md` (plan §7: revoke non-hosted keys and rows, `COPY`
the state out, then drop).

## 9. Release measurements and the console allowlist

Each reader release publishes on the public GitHub release `reader-v<version>`
(`thehappieco/wappie`): the EIF, `measurements.json`, the canonical policies
and their hashes. The image goes to `ghcr.io/thehappieco/wappie-reader@sha256:…`.
`deploy/enclave/build.sh` (DEPLOY) writes `measurements.json`:

```json
{ "schema": "wappie-reader-measurements/v1", "reader_id": "enclave", "version": "0.2.0",
  "resource": "https://mcp.wappie.thehappie.co/mcp",
  "source": { "repository": "thehappieco/wappie", "commit": "<40 hex>" },
  "image": { "reference": "ghcr.io/thehappieco/wappie-reader@sha256:<64 hex>", "node_image": "<ref@sha256>", "rust_image": "<ref@sha256>" },
  "eif": { "file": "wappie-reader-0.2.0.eif", "sha256": "<64 hex>", "size": 0 },
  "pcrs": { "0": "<96 hex>", "1": "<96 hex>", "2": "<96 hex>" },
  "nitro_cli": { "version": "1.5.0", "blobs": { "<file name>": "<64 hex>" } },
  "kms": { "region": "eu-west-1", "reader_key_arn": "arn:aws:kms:eu-west-1:768406580484:key/<id>", "boot_key_arn": "…" },
  "policies": [ { "phase": "transition", "file": "reader-key-policy.transition.json", "sha256": "<64 hex>",
                  "pins_pcr0": ["<96 hex: previous PCR0>", "<96 hex: this PCR0>"] },
                { "phase": "steady", "file": "reader-key-policy.steady.json", "sha256": "<64 hex>",
                  "pins_pcr0": ["<96 hex: this PCR0>"] } ] }
```

`transition` pins {previous PCR0, this PCR0}, and `steady` pins this PCR0 only.
Each policy's `pins_pcr0` lists exactly the PCR0 values that policy admits,
in the policy's order: for `transition` the previous PCR0 then this one (only
this one for a first release, or when the previous equals this), for `steady`
this one. `build.sh` reads them back from the rendered file (`EnclaveUse` and
`DenyOtherImages` must name the same list) and refuses to write
`measurements.json` otherwise. Every entry carries it, and the console
generator (`reader-measurements.mjs`) will require it.
Both are rendered from `deploy/enclave/kms/reader-key-policy.template.json`
(plan §5 skeleton) and hashed with `policy.mjs`. `version` must equal
`READER_VERSION` in the image. `release.py` checks this, excludes `enclave/` from
the pilot payload (`ignore_patterns`), and adds `reader_version`, `pcr0` and
`migration41_sha256` (SHA-256 of `internal/migrate/sql/0041_mcp_reader.sql`,
checked before any 0041 down-step) to `RELEASE.json`.

`commercial/web/reader-releases.json` lists `[{ "url": "<measurements.json URL>", "sha256": "<64 hex>" }]`.
`node commercial/web/scripts/reader-measurements.mjs` downloads each file,
checks its SHA-256 and schema, and writes the committed module:

```ts
// GENERATED by scripts/reader-measurements.mjs from reader-releases.json. Do not edit.
export interface ReaderMeasurement { version: string; pcrs: { 0: string; 1: string; 2: string }; release_url: string; measurements_sha256: string }
export const READER_RESOURCE = 'https://mcp.wappie.thehappie.co/mcp'
export const READER_MEASUREMENTS: readonly ReaderMeasurement[] = [ /* … */ ]
export const READER_POLICY_SHA256: readonly string[] = [ /* union of every listed release's policy hashes */ ]
```

`--check` needs no network and validates the committed module: 96 lowercase hex
per PCR, 64 per hash, `version` shape, no duplicates. Development builds accept
empty lists, which fail closed (`attestation_measurement` for everything).
`release.py` runs `--check --require-nonempty`.

## 10. Inside the enclave

### 10.1 Image constants (`packages/mcp-http/enclave/constants.mjs`, measured in PCR0)

`READER_ID='enclave'`, `READER_VERSION`, `PUBLIC_ORIGIN='https://mcp.wappie.thehappie.co'`,
`CONSOLE_URL='https://app.wappie.thehappie.co/console'`, `ARCHIVE='https://api.wappie.thehappie.co'`,
`REDIRECT_HOSTS=['claude.ai','chatgpt.com']`, `CIMD=true`, `PENDING_TTL_MS=1_200_000`,
`REGION='eu-west-1'`, `KMS_READER_KEY_ARN`, `KMS_BOOT_KEY_ARN`,
`ACME_DIRECTORY='https://acme-v02.api.letsencrypt.org/directory'` and
`BOOT_NAME_SUFFIX='.boot.mcp.wappie.thehappie.co'`. Nothing is read from the
environment. The Dockerfile sets only `NODE_ENV=production`.

### 10.2 boot.json (vsock 7001, strict)

`{"relay_secret_ciphertext":"<standard base64, 1 to 6144 bytes decoded>"}`: at
most 16 KiB, exactly one key. An extra key, a missing key, a non-object value
or bad base64 refuses the boot (`boot_json_invalid`).

**Boot order:**
1. Read `boot.json`.
2. Read the credentials (7000) and generate the RSA key.
3. `Decrypt` the relay secret (boot key) into `{current: S}`.
4. `GetKeyPolicy`. A failure here is not fatal.
5. Load the four state collections (§8).
6. Set up the ACME account (`infra`), creating it if absent.
7. Open 5445, then get the TLS key and certificate.
8. Open 5444 and 5443.
9. Reconcile connections with Go, as `startReader` does today.

The health line runs from step 1. A fatal boot error writes
`{"event":"boot_failed","code":…}` to the sink and exits with code 78.
`entrypoint.sh` restarts Node in a loop with a 5 s to 60 s backoff (not
`exec`), with stdout and stderr sent to `/dev/null`.

### 10.3 TLS and ACME

- `boot_id` = 16 lowercase hex characters (8 random bytes). The TLS key (ECDSA P-256) and the certificate live in `/run/wappie/` (mode 0700, RAM), so they survive a Node restart but never an enclave boot.
- The certificate names `{mcp.wappie.thehappie.co, <boot_id>.boot.mcp.wappie.thehappie.co}` and is validated with **TLS-ALPN-01** only. It is renewed with the same key when fewer than 30 days remain. Failed orders are retried with backoff from 1 minute up to 30 minutes, to stay under Let's Encrypt's failed-validation limit.
- The ACME account key is EC P-256, created on the first boot with `termsOfServiceAgreed: true` and no contact, and stored in `infra`. Its URI appears in the health object and in the health line as `acme_account_id`.
- 5445 answers only ALPN `acme-tls/1`, for either name, with the RFC 8737 challenge certificate. There is no PROXY header on 5445.
- 5443 and 5444 require **PROXY v2** as the first bytes, within 5 s. Only the `PROXY` command over `AF_INET` or `AF_INET6` `STREAM` is accepted, with a header of at most 536 bytes; TLVs are ignored. A v1 header, `LOCAL`, UNIX, UNSPEC, a truncated header or garbage closes the socket. `info.remoteAddress` is the PROXY source, and `X-Forwarded-For` is never trusted (`limits.mjs` `clientIP` already trusts it only from loopback). haproxy health checks must not send PROXY to these ports.
- TLS 1.2 minimum, ALPN `http/1.1`, full chain served.

### 10.4 Log sink (vsock 7002) and health line

Only lines from `createLog` reach the sink. Each is one JSON object, UTF-8, at
most 2048 bytes, followed by `\n`. The enclave keeps at most 1000 queued lines
and drops the excess. `log-sink.py` (DEPLOY) accepts a line only if every key
is known and every value matches:

| Key | Rule |
|---|---|
| `ts` | `^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$` |
| `route` | `public`, `internal` or `unmatched`, or `^(GET|POST|PUT|DELETE|HEAD|OPTIONS) /[a-z0-9/{}._-]{0,80}$` |
| `status`, `ms` | integers, 100 to 599 and ≥ 0 |
| `event`, `code` | `^[a-z][a-z0-9_]{0,47}$` |
| `conn`, `client`, `policy`, `spki`, `pcr0` | `^[0-9a-f]{12}$` (fingerprints) |
| any other key `^[a-z][a-z0-9_]{0,31}$` | a finite number or a boolean |

A line that fails the check is dropped and counted. `createLog().event()` gains
a single exception to "numbers and booleans only": a string value is kept only
if it matches `^[0-9a-f]{12}$`.

**Health line** (`event:"health"`, every 60 s): `uptime_s`, `rss_mb`,
`heap_mb`, `clock_skew_ms`, `cert_days_left`, `connections`, `pending`,
`state_dirty`, `relay_secrets`, `acme_account_id`, `policy_ok`, `policy`,
`pcr0`, `spki`, `log_dropped` (lines the enclave's own sink writer dropped:
schema failures and queue overflow) and `proxy_rejected` (connections on 5443
and 5444 closed before a TLS session: no, late or bad PROXY v2 header, or a
TLS setup or handshake timeout). A field is omitted when unknown.
`log-sink.py` accepts both counters under the "any other key" rule; its tests
list every event the enclave writes. `clock_skew_ms` = local time
minus (the `Date` header + RTT/2) of an unauthenticated `GET https://kms.eu-west-1.amazonaws.com/`
over vsock 8000, verified TLS, once a minute. It has 1 s resolution, and the
alarm threshold is 2 s. `uncaughtException` and `unhandledRejection` write
`{"event":"fatal","code":"uncaught"}` and exit with code 70.

## 11. Signatures that cross module boundaries

**VERIFIER → CONSOLE, ENCLAVE and tools** (`packages/client`, exported as `attestation` from the index):

```ts
export interface AttestationFields { request_id: string; resource: string; reader_version: string; tls_spki_sha256: string; policy_sha256: string }
export interface AllowEntry { version: string; pcrs: { 0: string; 1: string; 2: string } } // exact keys; 96 lowercase hex each, otherwise attestation_allowlist
export interface VerifyOptions { nonce: Uint8Array; allow: readonly AllowEntry[]; policies: readonly string[]; requestId: string; resource: string;
  requirePublicKey: boolean; now?: number; maxSkewMs?: number /* 600000 */; rootDer?: Uint8Array /* pinned AWS Nitro root G1 */ }
export interface AttestationResult { publicKey: Uint8Array | null; entry: AllowEntry; pcrs: { 0: string; 1: string; 2: string };
  timestamp: number; moduleId: string; documentSha256: string; fields: AttestationFields }
export class AttestationError extends Error { readonly code: AttestationCode }
export function verifyAttestation(document: Uint8Array, fields: AttestationFields, options: VerifyOptions): Promise<AttestationResult>
export function attestationUserData(fields: AttestationFields): Promise<Uint8Array>            // §6.2, 32 bytes
export function decodeAttestationDocument(document: Uint8Array): { pcrs: Record<number, string>; publicKey: Uint8Array | null;
  nonce: Uint8Array | null; userData: Uint8Array | null; timestamp: number; moduleId: string }   // parse only, no trust
```

The pinned root has SHA-256 fingerprint `64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`.
`verifyAttestation` does everything `poc/attest-webcrypto.mjs` does, plus these checks:
- PCR0, PCR1 and PCR2 are present and not all zero.
- An entry matches on all three PCRs, and `entry.version === fields.reader_version`.
- `fields.request_id === requestId` and `fields.resource === resource`.
- `fields.policy_sha256 ∈ policies`.
- `user_data` equals `attestationUserData(fields)`.
- `public_key` is 32 bytes when `requirePublicKey` is set, and absent when it is not.

`AttestationCode` is one of: `attestation_format`, `attestation_signature`,
`attestation_chain`, `attestation_root`, `attestation_validity`,
`attestation_clock`, `attestation_debug`, `attestation_measurement`,
`attestation_allowlist`, `attestation_nonce`, `attestation_user_data`,
`attestation_policy`, `attestation_public_key`, `attestation_version`,
`attestation_request`. CONSOLE translates each one in 5 languages.

**ENCLAVE internals** (fixed here so tests and DEPLOY agree):
- `startReader(options)` keeps its current behaviour when called with `{env, now, logSink}`. New optional injections:
  - `config`, which replaces `readEnv`;
  - `secrets: {current, previous?}`;
  - `state` (an opened state);
  - `relay`;
  - `internalAuth(request, info) → Response | undefined`;
  - `servers: {public, internal?}` (created, not listening; `startReader` attaches handlers and does not call `listen`);
  - `keys: 'shared' | 'per-request'`;
  - `attest(fields) → Promise<Buffer>`.

  `info` = `{remoteAddress, listener: 'public' | 'internal'}`. The pilot path (`node server.mjs`) must not import `enclave/*`, and a test enforces this.
- `openSealedState({ store, sealer, log, now })` returns the same object as `openState` (`clients`, `pending`, `connections`, `codes`, `tokens`, `save`, `wipeConnection`, `revokeFamily` and `close`), with no `recipient` or `previous`. Its arguments:
  - `store` = `{get(name) → {generation, blob} | null, put(name, ifGeneration, blob) → generation}`, which throws `StateError('state_conflict')` on a 409;
  - `sealer` = `{seal(name, generation, plaintext) → envelope, open(name, generation, envelope) → plaintext}`.
- `createSignedRelay({ base, readerId, secrets, fetch, timeoutMs })` has the `createRelay` interface plus `stateGet` and `statePut`.
- `descriptor()` and `openBundle()` use `pending.recipient ?? state.recipient`. When `pending.recipient` is set, it is the only candidate.

**DEPLOY ↔ ENCLAVE:** the image runs `node /app/packages/mcp-http/enclave/main.mjs`,
with the enclave dependencies from `packages/mcp-http/enclave/package-lock.json`
installed `--omit=dev`. `nsm-attest` is at `/usr/local/bin/nsm-attest`, with
the spike's argument and exit-code contract.

## 12. DNS records the owner adds at GoDaddy

These are added in this order, once the values exist. The values come from the
health line and the EIP.

| Order | Name | Type | Value |
|---|---|---|---|
| 1 | `mcp.wappie.thehappie.co` | CAA | `0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/<acme_account_id>; validationmethods=tls-alpn-01"` |
| 1 | `mcp.wappie.thehappie.co` | CAA | `0 issuewild ";"` |
| 1 | `wappie.thehappie.co` | CAA | `0 issuewild ";"` (check first that nothing issues a wildcard there) |
| 2 | negative test | none | another ACME account requests `mcp.` over dns-01 and must be refused by CAA |
| 3 | `mcp.wappie.thehappie.co` | A | parent EIP |
| 3 | `*.boot.mcp.wappie.thehappie.co` | A | parent EIP |

## 13. Open points (UNCONFIRMED)

- Whether the AL2023 haproxy build supports `req.ssl_alpn`. If it does not, the enclave reads the ALPN from the ClientHello on one port (the plan's fallback).
- Whether TLS-ALPN-01 works in `pebble` for CI.
- Resolved with release 0.2.0: `GetKeyPolicy` does not return the text exactly as applied. KMS collapses one-element arrays (section 7), which `render.py` now matches; whether it also reorders arrays remains UNCONFIRMED, so the owner still applies the release's rendered file unchanged.
- The spike role name (`wappie-enclave-spike-parent`) is what PCR3 measures. Renaming the role changes PCR3 and the policy.

## 14. Deviations recorded during implementation

Where the code settled something this contract left open or said
differently. The code is right; the sections above are read with these.

- **Hosted internal routes are hosted-only.** The pilot's internal connection
  routes for the hosted reader (status, activate, revoke) act only on rows
  with `reader = 'hosted'`. A row held by an attested reader is not found
  there; that reader asks through `/v1/mcp/enclave/*` and learns about its
  own rows only.
- **`WS_MCP_READER_<ID>_URL`** must be `https://<host>:<port>` with an
  explicit port (1 to 65535), no path, query or fragment, and a lowercase
  host equal to `PUBLIC_ORIGIN`'s host. `https://mcp.wappie.thehappie.co`
  without `:8443` is refused at startup.
- **429 codes differ by layer.** The enclave's prepare answers 429
  `too_many_prepares` (more than 10 per request), and Go passes that code on
  to the console unchanged ("start again from the assistant"). Go's own rate
  limits answer 429 `rate_limited` with `Retry-After`: only that one is worth
  waiting out.
- **`SECRET_NEXT` rotation.** Go only accepts `SECRET_NEXT` (it never signs
  with it), it must differ from `SECRET`, and `whatserverd mcp-relay-secret`
  refuses to run until it is set. The enclave keeps *previous* in memory
  only: a reboot between steps 2 and 3 of §4 brings back the `boot.json`
  secret alone (start again at step 2), and a reboot between steps 3 and 4
  leaves the enclave on S′ while Go still signs with S, so its calls are
  refused until step 4: do 3 and 4 together. Rotating to the secret already
  current is a no-op, and one trailing newline in the KMS plaintext is
  forgiven.
- **Console `release_url`** is the release's tag page
  (`https://github.com/thehappieco/wappie/releases/tag/reader-v<version>`),
  not the `measurements.json` URL. `reader-measurements.mjs` has a
  `--verify` mode that downloads every listed release again and compares
  the result with the committed module, besides `--check` (offline).
- **Attestation `public_key`** is the raw 32-byte X25519 public key (§6.2),
  never SPKI, for request documents; KMS documents keep the RSA SPKI.
- **The ACME client is in-tree** (`packages/mcp-http/enclave/acme.mjs`,
  RFC 8555 with TLS-ALPN-01 only): the enclave has no `acme-client`
  dependency; its production dependencies are `@aws-sdk/client-kms` and
  `asn1js`.

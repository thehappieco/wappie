# Sealed archive REST API

Wappie exposes the same sealed archive read models used by WebSocket over HTTP.
These REST resources cover archived data only. It does not send messages,
start connections, resume capture, request missing media or run history backfill.
The server never opens archived content or receives archive private keys.

The installation advertises `archive.rest.v1` in `GET /v1/discovery` and
`GET /.well-known/wappie`. The public specification is served at
`GET /v1/openapi.json` and embedded from
[`internal/restapi/openapi.json`](../internal/restapi/openapi.json).
Contact pagination and cross-chat scans additionally advertise `archive.contacts.v1`
and `archive.scan.v1`.
It uses [OpenAPI 3.1.1](https://spec.openapis.org/oas/v3.1.1.html).

## Authentication and workspace isolation

Send a session or API key as `Authorization: Bearer <token>` over HTTPS.
Tokens are not accepted in URLs. The credential selects the workspace; there
is no workspace query parameter or tenant header override. Every successful
archive response includes a root `tenant_id`. Clients should pin the installation
origin and verify this field against their configured workspace on every call.

Session membership, workspace status, API key scope and device whitelist are
checked on every request. The credential and every returned device's permission
are checked again before serialization. A revoked grant or whitelist entry does
not remain usable until a client reconnects. As with any response, data already
returned to a client cannot be revoked retroactively.

The authorization rules are shared with `internal/access`:

- A `read` API key is sufficient. `send` and `full` include `read`.
- An API key acting as a service account also requires that account's live
  read permission and current archive grant. Its whitelist further narrows access.
- A bare operator API key can fetch ciphertext in its allowed devices. It has
  no recipient account and cannot retrieve grants through `/v1/grants`.
- A person needs read permission and a grant for archive content. An owner or
  administrator may see/manage a number in the directory without access to its
  messages. Directory presence is not proof that content can be opened.
- An empty restricted API key whitelist grants access to no devices.

Suspension of capture for storage and a paused device do not block archive reads.
A disabled account, revoked session or suspended workspace does block access.
REST reads do not modify the archive or storage suspension; authentication still
records session/key usage in the existing authentication stores.

All authenticated responses, including errors, use `Cache-Control: no-store`.
The existing explicit browser-origin configuration applies to REST as well as
the other HTTP routes. A browser must never send a central commercial session to
an external installation; authenticate separately at each origin.

## Endpoints

All IDs in paths are complete, nonzero UUIDs. Unknown and repeated query
parameters are rejected. Query strings are limited to 8192 bytes. Only GET
(and HTTP HEAD semantics) is registered for these archive resources.

| Route | Successful response and limits |
| --- | --- |
| `/v1/devices` | `{tenant_id, devices: DeviceInfo[]}`. Devices visible through the shared `ActionView` rule. This workspace directory is not paginated. |
| `/v1/devices/{device}/chats?limit=100` | `{tenant_id, device_id, chats: ChatSummary[], limit, truncated}`. Limit 1–3000, default 100. |
| `/v1/devices/{device}/messages?chat_key=...&limit=50` | `{tenant_id, chat_key, messages, receipts?, next_ts?, next_seq?, has_more}`. Limit 1–200, default 50. |
| `/v1/devices/{device}/contacts?limit=100` | `{tenant_id, device_id, contacts: ContactSummary[], has_more, next_key?}`. Limit 1–500, default 100; optional exclusive `after_key`. Stored contact metadata and sealed names only. |
| `/v1/devices/{device}/messages/scan?from=...&until=...` | `{tenant_id, device_id, from, until, messages, has_more, next_ts?, next_seq?}`. Limit 1–200, default 50. Reads across chats; every row includes `order_ts`. |
| `/v1/messages/{uid}` | `{tenant_id, ...SealedMessage}`. An individual stored row, including control rows. |
| `/v1/messages/{uid}/history` | `{tenant_id, requested_uid, device_id, chat_key, wa_id, versions, deletion?, reactions?, readers?}`. Complete existing history projection for one message thread. |
| `/v1/devices/{device}/keys?ids=1,2` | `{tenant_id, device_id, archive_tenant_id, keys: [{id, sealed}]}`. Between 1 and 500 IDs, each 1–2147483647. Missing IDs are omitted; duplicates are folded. |
| `/v1/grants` | `{tenant_id, user_id, grants: [{device_id, archive_tenant_id, label?, epoch, sealed_dsk}]}`. Current-epoch grants of the authenticated person/service account, filtered by current read access and any API key whitelist. |
| `/v1/openapi.json` | Public OpenAPI document; no credential required. |

Response fields use the existing WebSocket DTOs, documented in
[`internal/wsapi/protocol.go`](../internal/wsapi/protocol.go), plus the REST
workspace envelope and the explicit directory/history metadata above.

### Paging and completeness

Message pages contain rows oldest first. With no cursor, the newest page is
returned. While `has_more` is true, pass **both** `before_ts=next_ts` and
`before_seq=next_seq` to obtain the previous page. `before_ts` is RFC3339 and
`before_seq` is a positive 64-bit integer. The exclusive cursor orders by message
timestamp, falling back to creation time, with the sequence breaking ties.
Do not construct a cursor from the timestamp alone.

Known PN/LID aliases are included in the message query; the response `chat_key`
echoes the requested key. Rows keep their own stored chat identifiers. Concurrent
ingestion, backfill, deletion or migration can change the archive between calls;
pages are not a frozen export snapshot.

The chat directory is bounded **before** folding PN/LID aliases. It may contain
fewer than `limit` conversations. `truncated: true` explicitly means more stored
chat rows exist. This release does not provide a chat-directory cursor and this
endpoint must not be presented as a complete archive export when truncated.

History preserves the full existing WebSocket projection: revisions, reactions,
deletion and per-reader acknowledgements. It has **no row cap or pagination** in
this release. Large threads can be expensive; database work for a REST request
has a 30-second deadline, and failure returns an error rather than a partial
history. The HTTP server/proxy can impose additional response time/size limits.
When the requested UID identifies an edit or another control row, `requested_uid`
still echoes it while the history `wa_id` identifies the resolved original.

### Cross-chat reads and contact pagination

`messages/scan` requires RFC3339 `from` and `until`, covering the half-open
interval `[from, until)`. Filters are combined: `sender_keys` accepts up to three
comma-separated exact identifiers matched against the stored sender key, PN or
LID; `chat_key` includes explicit known chat aliases; `direction` is `incoming`
or `outgoing`; `type` is an archive content type; `kind` is `message`, `edit`,
`delete` or `reaction`. The server filters routing metadata only, never plaintext.

Rows are oldest first within each newest-first page. Continue using the returned
`next_ts` and `next_seq` together as `before_ts` and `before_seq`, retaining the
same bounds and filters. `order_ts` is the original message timestamp when known,
or its archive creation time otherwise; a missing `ts` remains missing. The
sequence breaks timestamp ties. Nanosecond bounds preserve half-open semantics
when compared with PostgreSQL's microsecond timestamps.

A scan returns stored events, not a projection of the latest conversation state.
Use the message history endpoint to identify superseded revisions or a later
deletion, including events outside the scanned time range. Concurrent backfills
can require a rescan. An empty interval does not prove that WhatsApp had no
messages; only the persisted archive was queried.

Contacts are ordered by their stored contact key. Pass `next_key` as `after_key`
while `has_more` is true. This read neither asks WhatsApp for contacts/avatars nor
creates missing contacts. Names stay sealed; avatar bytes are not returned.
Local personal-contact snapshots used by MCP are separate from this endpoint
and are never uploaded to the archive server.

### Opening content locally

Bodies, structured payloads, chat names, attachment secrets, content keys and
archive grants remain base64-encoded ciphertext. Routing metadata, number labels,
timestamps and receipt counts remain readable, as in WebSocket. Internal storage
object keys and raw message payloads are not included.

An authorized client unwraps its user/service private key locally, opens its
`sealed_dsk` grant, and opens the returned content keys with the archive private
key. It then uses the public cryptography library to open individual fields.
Neither account nor archive private keys should be sent to REST.

**`tenant_id` and `archive_tenant_id` serve different purposes.** The former is
the current authorization workspace. The latter, supplied on devices, grants
and key responses, is the immutable cryptographic namespace. It may refer to
the original workspace after a Team → Personal transfer. Use that archive
namespace for associated data when opening keys and message/chat fields.
`user_id` on the grants response identifies the sealed grant's recipient.

Example requests (set credentials locally; do not put them into a shared URL):

```sh
curl --fail-with-body "$WAPPIE_URL/v1/devices" \
  -H "Authorization: Bearer $WAPPIE_TOKEN"

curl --fail-with-body --get "$WAPPIE_URL/v1/devices/$DEVICE_ID/messages" \
  -H "Authorization: Bearer $WAPPIE_TOKEN" \
  --data-urlencode "chat_key=$CHAT_KEY" --data-urlencode "limit=50"
```

## Errors

Authenticated handlers return `{code, message}` with these statuses:

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `bad_request` | Invalid UUID, query, limit, key ID or incomplete cursor. |
| 401 | `unauthorized` | Missing, expired, revoked or invalid credential; unavailable workspace/account. Includes `WWW-Authenticate: Bearer realm="wappie"`. |
| 403 | `not_authorized` | Current grant/permission, API key restriction or recipient account is insufficient, or access changed while reading. |
| 404 | `not_found` | The item does not exist in this credential's workspace. Cross-workspace items are indistinguishable from missing items. |
| 500 | `internal` | Archive or authorization infrastructure could not complete the read. No partial data response is emitted. |

Unknown routes and unsupported methods use the HTTP router's 404/405 responses.
Consumers should handle these before parsing a REST JSON envelope, especially
when connecting to an older installation without `archive.rest.v1`.

## Maintaining the contract

The embedded document is validated against the Go wire DTOs by the Go tests.
When intentionally changing a DTO, regenerate and review the component schemas:

```sh
go test ./internal/restapi -run TestOpenAPIWireSchemas -args -update-openapi
go test -race ./internal/restapi ./internal/wsapi ./cmd/whatserverd
```

The REST integration tests use PostgreSQL with an ordinary, non-superuser role
and require real row-level security. They cover workspace isolation, service
whitelists, scopes, grant/key revocation, pagination, real ciphertext and
cryptographic namespace preservation through device transfer.

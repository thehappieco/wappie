# MCP for authorized archive reads

The public [`packages/mcp`](../packages/mcp/README.md) package connects an MCP
host to a Wappie installation's REST APIs. It provides number, chat, message,
revision and contact queries, bounded cross-chat lexical search and activity
counts without depending on the commercial app. The companion
[`packages/mcp-http`](../packages/mcp-http/README.md) serves the same reader
over Streamable HTTP for remote hosts: as the hosted metadata connector, which
never opens content, and as the attested reader in an AWS Nitro Enclave, which
can also open message text for a connection the user enabled it on.

## Ways to connect

| Tier | Transport | Content | Where it runs |
| --- | --- | --- | --- |
| **Local** | stdio (`packages/mcp`) | Metadata, or message text when `allow_plaintext` is enabled in the local configuration | Your computer. Archive private keys never leave it. |
| **Cloud, metadata** | Streamable HTTP, `https://api.wappie.thehappie.co/mcp` | Who, when and how much, never the content | A reader process on Wappie's API host that holds no archive private key. Sealed bodies stay sealed and are reported as `locked`. |
| **Cloud, attested reader** | Streamable HTTP, `https://mcp.wappie.thehappie.co/mcp` | Metadata; with **message text** switched on at consent, also text, chat names and previews, contact names and filenames of the chosen numbers. Never attachment contents | The same reader inside an AWS Nitro Enclave. TLS ends inside it, and the browser checks its published image before sealing anything to it ([contract](mcp-enclave.md)). Text is available only in workspaces Wappie has enabled for it. |
| **Enterprise** | Streamable HTTP (`packages/mcp-http` container) | Metadata, as the hosted metadata connector | Your infrastructure, beside your own installation, under your own OAuth server and policy. |

The hosted metadata connector, the self-hosted container and every attested
connection without text share one property: the reader is issued a read-only,
device-restricted API key with an expiry, never a service account or an archive
private key, so it cannot open message text even if its host is compromised.
Metadata still reaches the assistant's provider. A **text** connection on the
attested reader is different by design, and [who can read what](#who-can-read-what)
says exactly how.

## Who can read what

For a connection with message text, on `https://mcp.wappie.thehappie.co/mcp`:

| Who | Reads the text? | How, or why not |
| --- | --- | --- |
| The reader in the enclave (published image, verified by the browser) | Yes, in memory, per tool call | Only while the connection is live. The current grants are fetched on every call. |
| The AI provider the user connected | Yes, what the tools return | By design, limited to the chosen numbers, the expiry and each tool's size limits. |
| Wappie's staff, the archive server, its database and backups | No, short of the rows below | The key that opens the grants is generated in the enclave and never leaves it; the database holds only grants sealed to that key. |
| The host running the enclave | No | TLS ends inside the enclave, and a CAA record lets only the enclave's own ACME account obtain a certificate for the address. The host sees names, addresses, timing and sizes. |
| An operator who changes the KMS key policy | No, with the key only in memory (the only mode today) | Reading would need a new certificate for the address, which Certificate Transparency records publicly. Every attestation carries the live policy's hash, which the browser checks. |
| An operator who controls DNS | **Yes**, while it lasts | With a certificate of their own they can pose as the reader to the AI host and receive its tokens. That certificate is public in Certificate Transparency, and `tools/ct-watch` flags any certificate whose key no enclave attested. |
| An operator who serves malicious code in the console | Could divert the sealing | The same trust in delivery all of Wappie's browser cryptography relies on. |
| AWS (hypervisor, Nitro Security Module, KMS) | Trusted | Outside this model. |

The key is memory-only: a restart of the enclave (every reader release, a
reboot or a crash) clears it. The connection then answers
`reconsent_required` with a console link, and the person who consented renews
it there with their password. The assistant does not have to reconnect.
Revoking stops future reads; it cannot erase what the assistant already
received. Someone who leaves the workspace or is disabled loses their text
connections with it. Live ingestion is not blind (the server that receives
messages from WhatsApp sees them before sealing), and the archive REST API
still never opens archived content.

## Connect an assistant

The console offers an **MCP** setup for workspace owners and administrators:
choose the installation, workspace and allowed numbers; decide whether to allow
message text; confirm the timezone; then download the private setup bundle.
With text reading enabled, an additional opt-in can include an encrypted snapshot
of names and phone numbers saved in **My contacts**. The bundle contains a token
and, when text is enabled, a private service key. Import it locally with
`packages/mcp/setup.mjs` and delete the original download after import.

Use an updated checkout and rebuilt SDK before importing. Existing configurations
continue to work with the new tools when the installation supports their REST
endpoints. Personal contacts require a new, explicitly selected snapshot; they
are not copied from the browser automatically. Import a new bundle into a new
private directory and update the host's configuration path. The importer does
not overwrite existing files.

The [package quickstart](../packages/mcp/README.md#start-with-a-console-setup)
includes installation, file permissions and complete commands. It covers these
hosts in order:

1. [ChatGPT through Secure MCP Tunnel](../packages/mcp/README.md#connect-to-chatgpt),
   following the [official OpenAI tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).
   Workspace access and live tool discovery must be verified in your own account.
2. [Claude Desktop through local stdio](../packages/mcp/README.md#connect-to-claude-desktop),
   using the same MCP process and private configuration.
3. [claude.ai and ChatGPT through the remote connector](../packages/mcp-http/README.md),
   which needs no tunnel and no always-on computer. Add the installation's
   `https://<host>/mcp` URL in the assistant; the browser is sent to the console
   to approve the connection.

### Installing the hosted connector in one step

Wappie runs two addresses. `https://api.wappie.thehappie.co/mcp` is the hosted
metadata connector. `https://mcp.wappie.thehappie.co/mcp` is the attested
reader: it reads metadata the same way, and also message text in workspaces
where Wappie has enabled it and the approver switched it on. The steps below
use the first address; the second works the same way in every host.
Every host takes the address as it is — **nothing to install**:

- **Claude** (claude.ai, Desktop, mobile): the console's MCP panel and the
  Wappie page have a **Connect to Claude** button, Claude's prefilled "add
  custom connector" dialog; or paste the address in Settings → Connectors. On
  Team and Enterprise an owner adds it once for the organisation.
- **Codex** (ChatGPT desktop app or CLI): Settings → MCP servers → Add server →
  Streamable HTTP → the address, or `codex mcp add wappie --url
  https://api.wappie.thehappie.co/mcp`. Codex opens the consent page itself.
- **Claude Code**: `claude mcp add --transport http --scope user wappie
  https://api.wappie.thehappie.co/mcp`, then `/mcp` to sign in.
- **ChatGPT on the web**: turn on developer mode, then add the address as a
  plugin — that entry is all ChatGPT needs; there is no file to build.

The plugin at [thehappieco/wappie-plugins](https://github.com/thehappieco/wappie-plugins)
is optional. It adds a skill that tells Codex or Claude Code what the
connection can see, and not to read WhatsApp through the screen to get around a
locked result.

Native apps such as Codex and Claude Code identify themselves with a Client ID
Metadata Document on an allowed host and take the code on a loopback port
(RFC 8252); open registration never gets loopback redirects.

The server advertises the connector's address in `/v1/discovery` as
`endpoints.mcp_server`, because the console runs on another origin than the
connector and cannot work it out. `WS_MCP_OPENAI_APPS_CHALLENGE` serves the
token OpenAI's plugin portal issues for domain verification at
`/.well-known/openai-apps-challenge`; unset, the path is a 404 like every other
unknown `/.well-known` path.

A Wappie REST address is still not an MCP endpoint: the REST API and the MCP
endpoint are different services on different paths. Two transports are
supported. **Local stdio** (`packages/mcp`) keeps decryption keys on your
computer and requires that computer to stay awake and connected. **Remote
HTTP** (`packages/mcp-http`, served at `/mcp` behind OAuth 2.1) runs the same
reader over Streamable HTTP. On `api.` and in a self-hosted container no
archive decryption key ever reaches it; on the attested reader a text
connection's key exists only inside the enclave. A [manual setup](../packages/mcp/README.md#manual-configuration)
also works with public API/CLI credentials, without the commercial console.

### Approving a remote connection

The assistant redirects the browser to the console with a one-time request id.
An owner or administrator chooses the numbers, the timezone and an expiry of
30, 90 or 365 days, and sees the sentence the connection is held to: the
assistant will see who, when and how much, never the content. On approval the
console issues a read-only API key restricted to those numbers, seals it to
the reader's public key in the browser, and hands the reader a proof that the
same browser approved that same request. The archive server relays the sealed
bundle as an opaque blob and records the connection; it never sees the key
inside. A workspace can hold five live connections; each is listed in the
console's MCP panel and can be revoked there, which revokes its API key in the
same transaction. Revocation stops future reads; it cannot retract metadata
already returned. An approval that is not completed within twenty minutes
expires with its provisional key.

On the attested reader the console first asks it for a fresh attestation
document and verifies it in the browser: the image must be one of the
published releases, the key policy one of the published hashes, and the key the
bundle is sealed to the one the enclave attested. Only then, and only in a
workspace enabled for text, does the card offer **Also read message text**.
With it on, the approver chooses 1, 30 or 90 days (30 by default), reads the
sentence the connection is held to (the reader will be able to open all
messages, chat names, contacts and files of those numbers, past and future,
until the date shown; Wappie does not receive the key; revoking does not erase
what the assistant already read), and enters their password once for all the
chosen numbers. The browser then creates a service account for this connection
alone, gives it read-only access to those numbers, seals each number's key to
the enclave's attested key, and issues an API key that acts as that account.
Nothing sealed leaves the browser before the attestation passes. The console
lists the connection as text, and its refresh token lapses after seven days
unused (thirty for metadata).

When the enclave restarts the connection shows **reseal** in the console and
its tools answer `reconsent_required` with a link to
`/console?mcp_renew=<connection id>`. The person who consented opens it, the
console verifies a new attestation, and their password seals the grants to a
new enclave key and a new service account on the same connection, with the
same expiry. The assistant keeps its tokens.

### Server configuration for the readers

The archive server fronts one or more readers, listed in `WS_MCP_READERS`
(default `hosted`). The **hosted** reader is the process on the same host and
keeps its original variables: `WS_MCP_READER_URL` (loopback http),
`WS_MCP_RELAY_SECRET` (at least 32 bytes) and `WS_MCP_PUBLIC_ORIGIN`; they are
required only when `hosted` is listed. Any other id is an **attested** reader
running in a Nitro Enclave (`enclave` for `https://mcp.wappie.thehappie.co/mcp`),
configured under `WS_MCP_READER_<ID>_*`:

| Variable | Rule |
|---|---|
| `_URL` | `https://<host>:<port>` with no path, on the public origin's host (`https://mcp.wappie.thehappie.co:8443`) |
| `_PUBLIC_ORIGIN` | https origin with no path (`https://mcp.wappie.thehappie.co`) |
| `_SECRET` | exactly 43 base64url characters; the HMAC key is the string as written |
| `_SECRET_NEXT` | optional, same shape, different from `_SECRET`; set only during a rotation |
| `_PEER` | the addresses the enclave calls from (the parent's Elastic IP as `/32`) |
| `_TENANTS` | workspace UUIDs that may consent to this reader, or `*` |

`WS_MCP_READER_HOSTED_*` is a configuration error, and nothing is relaxed
outside production for an attested reader. The startup line prints each
reader's id, URL, origin, whether each secret is set, and its peer and tenant
counts, never a secret.

Requests between the server and an attested reader are signed in both
directions (HMAC-SHA256 over method, raw target, timestamp, nonce and body
hash, with a direction), checked within 60 seconds and against a replay cache.
The server reaches the reader over HTTPS verified with the system roots, with
no proxy, no redirects and a 10 second timeout. The reader calls back on
`/v1/mcp/enclave/*` only from a `_PEER` address, and each call acts only on
that reader's own connections. The console prepares an attested consent with
`POST /v1/mcp/requests/{id}/prepare` and verifies the attestation in the
browser; the server refuses a consent for an attested reader that was not
prepared with the same key, records the PCR0 and the document's SHA-256 the
reader declared, and never verifies attestations itself. The enclave's sealed
state lives in `mcp_reader_state` as opaque blobs, written with a generation
compare-and-swap and at most 12 MiB each. When `enclave` is configured,
discovery adds `endpoints.mcp_server_attested`.

Message text is a separate switch, with two variables:

| Variable | Rule |
|---|---|
| `WS_MCP_CONTENT_ENABLED` | boolean, default `false`; lets the `enclave` reader hold **content** connections. On without an `enclave` reader in `WS_MCP_READERS` is a configuration error |
| `WS_MCP_CONTENT_TENANTS` | workspace UUIDs, comma separated, that may consent to content; required and non-empty when the switch is on; `*` is refused, and each listed workspace must also be in `WS_MCP_READER_ENCLAVE_TENANTS` |

The server allows a content consent only for a request the enclave holds,
prepared by this process, with the switch on and the workspace listed;
anything else is `403 content_not_allowed`. Turning the switch off (or
removing a workspace from the list) is the kill switch: the enclave's status
checks answer `reseal` for that workspace's live content connections, so
every key is dropped within a minute while the consents and the assistants'
token families survive, and renewal is refused until content is allowed
again. Discovery adds the capability `mcp.remote.content.v1` when
`enclave` is configured and the switch is on; the console asks
`GET /v1/mcp/content` whether its own workspace may use it. The startup line
prints `content=on|off` and the number of listed workspaces.

A content connection reads as a service account created for it alone, with a
thirty-minute membership until the consent is recorded and the connection's
lifetime after. Ending the connection in any way (the console, the reader, a
failed hand-off, expiry, or removing or disabling the service account or the
person who consented) revokes its key and removes that account's grants,
permissions and membership in the same transaction. The janitor also removes
provisional accounts whose consent was abandoned, and revocations the enclave
has not confirmed are sent again every 30 seconds for a day.

To rotate an attested reader's secret: encrypt the new secret under the
reader's boot key, set it as `_SECRET_NEXT` and restart the server, then run
`whatserverd mcp-relay-secret -reader enclave < ciphertext.b64` (signed with
the current secret), replace `boot.json` on the parent, and finally make the
new secret `_SECRET` and unset `_SECRET_NEXT`. The full contract is
[mcp-enclave.md](mcp-enclave.md).

## Configuration and identity

- The installation and workspace are fixed in a private local configuration file.
- Use an existing CLI session for a person or an API key for automation.
- The default mode reads metadata and presents sealed content as `locked`.
- To open text, enable `allow_plaintext` and supply a private password file for
  the session, or a service account's private key for the API key.
- The service key uses the exact base64url format produced by `wsctl service-key`.
- The optional number list narrows the scope beyond the server's permissions.
- `timezone` defaults to `UTC`; the console exports the user's selected timezone.
- `max_scan_messages` defaults to 500 and can be set from 1 to 2000 rows per
  search/activity call.
- Optional `contacts_file` requires service-account mode, plaintext opt-in and
  an explicit number list. The encrypted snapshot must match the exact server,
  workspace, service account and configured number set.
- The model cannot choose another installation, workspace, credential or path.

Opened text is sent to the MCP host and model chosen by the user. Keys stay in
the local process, without a persistent cache, and current grants remain
required. A key stored on the computer does not bypass revocation or a workspace
change. Private credential files and TLS remain necessary. Contact snapshots
remain local encrypted files with no browser synchronization or Apple/Google
connection. Matching names and phone numbers returned by tools can reach the
model. Revoking a token cannot retract a copied snapshot or its decryption key.

Older version-1 setup bundles remain supported. Without their optional new
fields, the timezone is UTC and there is no personal snapshot.

## Read-only contract

`list_numbers`, `list_chats`, `list_messages`, `get_message` and `list_revisions`
only read the persisted archive. They do not send messages, make calls, mark
messages as read, download media or sync history. Message listing preserves the
timestamp/sequence cursor provided by the server. Chats and revisions can report
explicit truncation; these directories do not yet have continuation cursors.
This release does not open structured payloads or download attachment contents.
It can open encrypted attachment filenames when plaintext reading is enabled.

Three additional tools build on that archive:

| Tool | Contract |
| --- | --- |
| `resolve_contact` | Matches archived names/phones and an optional personal snapshot. Returns candidate identities and explicit ambiguity; follows archive contact pages through `next`. |
| `search_messages` | Searches all chats of one authorized number using optional lexical body/filename matching, time bounds and metadata filters. Returns sources and historical revision/deletion status. |
| `activity_summary` | Counts a bounded page of archived original messages by chat, sender and direction. Original events can remain counted after a later edit or deletion. |

`search_messages` does not require selecting a person or conversation first.
It matches all case-insensitive, accent-insensitive query terms; it has no
semantic/vector index and does not search attachment contents. Without a text
query, metadata filters also work with locked content. A separate call is needed
for each authorized number. The [package guide](../packages/mcp/README.md#search-across-conversations)
documents filters, result limits and source references.

## Dates, continuation and coverage

Search and activity accept `today`, `yesterday`, `yesterday_evening`,
`last_7_days` or `all`, or explicit RFC3339 `from` and `until` bounds.
`yesterday_evening` means 18:00 until the next local day starts; `last_7_days`
starts at the beginning of the local date six dates ago. Relative dates use the
configured timezone. Intervals include `from` and exclude `until`. Missing
message timestamps use archive arrival time for ordering/filtering and are
reported as such, rather than invented message times.

For `search_messages`, `activity_summary` and paginated `resolve_contact`, send
the **whole returned `next` object** as arguments to the same tool. Search and
activity continuation freezes explicit bounds so the period does not shift
between calls. Check `coverage` and follow `has_more`; zero matches on an
incomplete scan does not prove absence. Activity counts belong to each page and
must be summed by group across completed pages. Concurrent backfill and other
archive changes can still require a rescan.

Search can find superseded or deleted historical content. Check `archive_status`
and use `list_revisions` before describing a match as current. On a text
connection of the attested reader, a text query always scans the whole scan
budget and reports `archive_status: {"state": "not_checked"}`, so the archive
server cannot tell from the requests which messages matched; follow `next`,
narrow the period when `omitted_hits` is above zero, and use `list_revisions`
to check that a match is current. Exhausting an archive interval does not
establish that every original WhatsApp message was captured. See [period semantics and continuation](../packages/mcp/README.md#calendar-periods-and-continuation)
and [activity counting](../packages/mcp/README.md#summarize-activity-accurately).

For limits, complete examples, identity setup and host configuration, see the
[MCP package guide](../packages/mcp/README.md).

The SDK's [`ArchiveClient`](../packages/client/README.md#read-only-rest-client)
also supports custom HTTP clients with fixed origins/workspaces, the same
sealed envelopes and local decryption through the public `Opener`.

## Future contextual retrieval

[Encrypted contextual search](encrypted-context-search.md) proposes a persistent
local encrypted index, local embeddings and semantic retrieval across authorized
conversations. It includes key management, live permissions, retention/removal,
source coverage and the disclosure boundary for model-visible excerpts. It is a
future architecture, separate from the lexical search available through MCP.

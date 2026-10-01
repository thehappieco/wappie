# MCP for authorized archive reads

The public [`packages/mcp`](../packages/mcp/README.md) package connects an MCP
host to a Wappie installation's REST APIs. It provides number, chat, message,
revision and contact queries, bounded cross-chat lexical search and activity
counts without depending on the commercial app. The companion
[`packages/mcp-http`](../packages/mcp-http/README.md) serves the same reader
over Streamable HTTP for remote hosts: as the hosted metadata connector, which
never opens content, and as the attested reader in an AWS Nitro Enclave, which
can also open message text for a connection the user enabled it on, and
attachments for one whose consent includes them.

## Ways to connect

| Tier | Transport | Content | Where it runs |
| --- | --- | --- | --- |
| **Local** | stdio (`packages/mcp`) | Metadata, or message text when `allow_plaintext` is enabled in the local configuration | Your computer. Archive private keys never leave it. |
| **Cloud, metadata** | Streamable HTTP, `https://api.wappie.thehappie.co/mcp` | Who, when and how much, never the content | A reader process on Wappie's API host that holds no archive private key. Sealed bodies stay sealed and are reported as `locked`. |
| **Cloud, attested reader** | Streamable HTTP, `https://mcp.wappie.thehappie.co/mcp` | Metadata; with **message text** switched on at consent, also text, chat names and previews, contact names and filenames of the chosen numbers; with **attachments** switched on as well, also photos, stickers, PDFs, office and text files and a video's preview image, opened inside the enclave ([what they send](#attachments)) | The same reader inside an AWS Nitro Enclave. TLS ends inside it, and the browser checks its published image before sealing anything to it ([contract](mcp-enclave.md)). Text, and attachments on top of it, are available only in workspaces Wappie has enabled for them. |
| **Enterprise** | Streamable HTTP (`packages/mcp-http` container) | Metadata, as the hosted metadata connector | Your infrastructure, beside your own installation, under your own OAuth server and policy. |

The hosted metadata connector, the self-hosted container and every attested
connection without text share one property: the reader is issued a read-only,
device-restricted API key with an expiry, never a service account or an archive
private key, so it cannot open message text even if its host is compromised.
Metadata still reaches the assistant's provider. A **text** connection on the
attested reader is different by design, and [who can read what](#who-can-read-what)
says exactly how. A text connection never opens attachment contents; only a
**media** connection, whose consent also includes attachments, does.

## Who can read what

For a connection with message text, on `https://mcp.wappie.thehappie.co/mcp`
(and its attachments, for a media connection):

| Who | Reads the text? | How, or why not |
| --- | --- | --- |
| The reader in the enclave (published image, verified by the browser) | Yes, in memory, per tool call | Only while the connection is live. The current grants are fetched on every call. |
| The AI provider the user connected | Yes, what the tools return | By design, limited to the chosen numbers, the expiry and each tool's size limits. Attachments reach it as text and re-encoded images; on claude.ai, large results and images may be copied into Anthropic's code-execution storage and kept there. |
| Wappie's staff, the archive server, its database and backups | No, short of the rows below | The key that opens the grants is generated in the enclave and never leaves it; the database holds only grants sealed to that key. For an attachment, the archive server serves only its ciphertext, so it learns which one was opened, when and how large it is, never its content. |
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

From reader 0.6.0 ([contract §19](mcp-enclave.md#19-any-mcp-client-060)) the
attested reader admits any assistant that identifies itself with a client
document on its own https domain, and a connection token made in the
console. These rows add to the table above, for every connection on that
reader, with or without text:

| Who | Reads? | How, or why not |
| --- | --- | --- |
| An assistant you approved that Wappie has not tested | Yes, what you allowed | Metadata once you tick "I started this"; text and attachments only after a second, deliberate tick, with your password and a confirmed e-mail address. Never drafts, notes or sending. At most the last 7, 30 or 90 days (30 by default), 2,000 messages and 50 attachments a day (300 and 10 in the first hour), 20 calls a minute, text for 30 days at most, and its access lapses after 3 days unused (7 for metadata). |
| Someone who tricked you into approving their assistant | Yes, what was approved, within those limits, until you revoke it or it expires | The consent card leads with the verified domain and its main domain, shows the full identity and return addresses, warns about look-alike names and shared hosting, and refuses public suffixes, hosts shared by path and Wappie's own domain. Every new connection raises a banner in the console and an e-mail with a link that can only revoke it. |
| Someone who started a connection in their own Claude or ChatGPT and got you to approve it | Only if that assistant accepts a sign-in it did not start | Each release tests this for every web assistant it lists, and an assistant that fails is not listed. You tick "I started this" on every consent, and the reader refuses an approval completed from a different network than the one that started the connection. The banner, the e-mail and revocation. |
| A program on your computer posing as an app such as Claude Code or Codex (an installer script is enough) | Yes, what you approved for that app | Nothing can confirm which program on your computer receives the access, and the card says so. You tick "I started this"; such apps get shorter lifetimes (text 30 days at most, refresh lapsing after 7 days unused) and never drafts, notes or sending. |
| Whoever holds a connection token | Yes, within its numbers, scope, networks, history window, limits and validity | The token is shown once and Wappie keeps only its hash, inside the reader's sealed state. A text token lasts 1 day by default and 30 at most. Revocation takes effect within a minute. |
| Wappie's staff forging an assistant's identity document | No | The verified reader fetches the document itself over a connection it checks; the assistants Wappie tested are pinned in its published image and never fetched. Staff can only block a document. |
| Wappie's staff hiding a connection from the list | Detected | The console compares the list with the one the verified reader signs, and shows a red warning when a connection is missing. |

## Connect an assistant

The console's **MCP** panel shows workspace owners and administrators one
connector address and how to add it in Claude or ChatGPT (from reader 0.6.0,
in any MCP client: [below](#any-mcp-client-reader-060)). The assistant then
sends the browser back to the console to choose the numbers and approve the
connection; nothing runs on the person's computer. See the
[remote connector](../packages/mcp-http/README.md) and the steps below.

The console no longer creates local setup bundles. A bundle created earlier
still imports with `packages/mcp/setup.mjs`, and the console lists the tokens
of those setups under **Old local MCP tokens** so they can be revoked.
The [package quickstart](../packages/mcp/README.md#start-with-a-console-setup)
covers importing such a bundle, [ChatGPT through Secure MCP Tunnel](../packages/mcp/README.md#connect-to-chatgpt)
and [Claude Desktop through local stdio](../packages/mcp/README.md#connect-to-claude-desktop);
a new local connection uses its [manual configuration](../packages/mcp/README.md#manual-configuration).

### Installing the hosted connector in one step

Wappie runs two addresses. `https://api.wappie.thehappie.co/mcp` is the hosted
metadata connector. `https://mcp.wappie.thehappie.co/mcp` is the attested
reader: it reads metadata the same way, and also message text in workspaces
where Wappie has enabled it and the approver switched it on, and attachments
where Wappie has enabled those too and the approver switched them on as well.
The console's MCP panel shows the second address to workspaces the attested
reader allows and the first to every other. The steps below use the first
address; the second works the same way in every host.
Every host takes the address as it is — **nothing to install**:

- **Claude** (claude.ai, Desktop, mobile): the console's MCP panel and the
  Wappie page have a **Connect to Claude** button, Claude's prefilled "add
  custom connector" dialog; or paste the address in Customize → Connectors →
  + → Add custom connector. On Team and Enterprise an owner adds it once for
  the organisation, in Organization settings → Connectors → Add → Custom → Web
  (the panel also links the same prefilled dialog on that admin path), and
  members then click Connect on it.
- **Codex** (ChatGPT desktop app or CLI): Settings → MCP servers → Add server →
  Streamable HTTP → the address, or `codex mcp add wappie --url
  https://api.wappie.thehappie.co/mcp`. Codex opens the consent page itself.
  Codex has been seen to list the tools without being able to call them; if
  that happens, add Wappie as a ChatGPT app instead (below).
- **Claude Code**: `claude mcp add --transport http --scope user wappie
  https://api.wappie.thehappie.co/mcp`, then `/mcp` to sign in.
- **ChatGPT** (desktop app or web): Settings → Apps (Apps & Connectors) →
  Advanced settings → turn on Developer mode. Then in Apps click Create: name
  "Wappie", MCP server URL the address, Authentication OAuth, tick "I trust
  this application", Create. In a chat, "+" → Developer mode → turn on
  Wappie. That entry is all ChatGPT needs; there is no file to build. Added
  another way, for example as a plain connector or in Codex, ChatGPT may list
  the tools without being able to use them. For attachments, pick a model
  with reasoning (Thinking or Pro): Instant does not see images.

The plugin at [thehappieco/wappie-plugins](https://github.com/thehappieco/wappie-plugins)
is optional. It adds a skill that tells Codex or Claude Code what the
connection can see, and not to read WhatsApp through the screen to get around a
locked result.

Native apps such as Codex and Claude Code identify themselves with a Client ID
Metadata Document and take the code on a loopback port (RFC 8252); open
registration never gets loopback redirects. Up to reader 0.5.0 the document
must sit on an allowed host (`claude.ai` or `chatgpt.com`); from reader 0.6.0
any https host that passes the reader's checks qualifies, as below.

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

### Any MCP client (reader 0.6.0)

From reader 0.6.0 ([contract §19](mcp-enclave.md#19-any-mcp-client-060)) the
attested reader's address works in any MCP client that identifies itself
with a Client ID Metadata Document on its own https domain (VS Code, Zed,
goose, an in-house agent), as well as in Claude, ChatGPT, Codex and Claude
Code. The consent card always leads with the client's verified domain.

- **Tested by Wappie.** The clients Wappie has tested are pinned, with their
  exact return addresses, in the reader's published image. The first list
  (Claude, ChatGPT, Codex and Claude Code) is final only after a live
  baseline on reader 0.5.0, and only the clients that pass it are listed.
  Claude and ChatGPT show "Tested by Wappie". Codex and Claude Code show
  "App on this computer": an app on your computer cannot be identified
  there, so they get shorter lifetimes and no drafts or notes.
- **Not tested by Wappie.** Any other client connects with an amber card:
  its domain and main domain, the full addresses it identifies itself with
  and returns to, the name it gives in quotes, and warnings for look-alike
  names and shared hosting. Text and attachments stay locked until a second,
  deliberate tick and a confirmed e-mail address, sending is never offered,
  and the reading limits in [who can read what](#who-can-read-what) apply.
- **Connection token**, for tools that cannot sign in with OAuth but can
  send a fixed header (Cursor, Windsurf, Gemini CLI, n8n, OpenCode,
  mcp-remote, scripts): in the console's MCP tab, an owner or administrator
  creates a token, chooses its numbers, what it may read, its validity (text
  1 day by default), its history window and, optionally, the networks it may
  be used from, and copies it once into the computer's keychain. The tool
  sends it only as `Authorization: Bearer`, never in a URL. A token is
  always "not tested".
- **Not supported:** clients that run inside a web page (the reader refuses
  any `Origin` on `/mcp`), and clients that can only register dynamically
  and cannot send a header (the Gemini app; Perplexity, unconfirmed).
- Every consent asks you to tick "I started this", and every new connection
  raises a banner in the console and an e-mail whose only link revokes that
  connection. Wappie never asks for your password from an e-mail.
- A workspace holds at most ten live connections, of which at most three
  are untested assistants or tokens.

### Approving a remote connection

The assistant redirects the browser to the console with a one-time request id.
An owner or administrator chooses the numbers, the timezone and an expiry of
30, 90 or 365 days, and sees the sentence the connection is held to: the
assistant will see who, when and how much, never the content. On approval the
console issues a read-only API key restricted to those numbers, seals it to
the reader's public key in the browser, and hands the reader a proof that the
same browser approved that same request. The archive server relays the sealed
bundle as an opaque blob and records the connection; it never sees the key
inside. A workspace can hold five live connections (ten from the server
release that prepares reader 0.6.0, of which at most three untested
assistants or tokens); each is listed in the console's MCP panel and can be
revoked there, which revokes its API key in the same transaction. Revocation stops future reads; it cannot retract metadata
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

### Attachments

Attachments ride on text. Where the attested release declares them, discovery
lists `mcp.remote.media.v1` and the workspace may use them, the card also
offers **Also read attachments** ("Photos, PDFs and documents, opened only
inside the verified reader. Requires your password."), which turns text on
too. The approver then reads a second paragraph the connection is held to:
photos, stickers, PDFs and documents of those numbers are opened inside the
verified reader and sent to the assistant as text and images; photos are
re-encoded, which removes location and camera data; voice notes, audio and
video are not transcribed yet, and a video sends only its preview image;
view-once media are never opened; apart from a video's preview image stored
in the archive, only attachments the archive has downloaded and can verify
are read; the archive
server can see which attachments are opened and when, never their content;
on claude.ai, large results and images may be copied into Anthropic's
code-execution storage and kept there; revoking stops future reads and does
not erase what the assistant already received. The console seals that
consent as version 2 of the card and lists the connection as **Text +
attachments**.

A media connection gets a ninth tool, `open_attachment`
([package guide](../packages/mcp/README.md#open-attachments-on-a-media-connection)).
Inside the enclave it fetches the attachment's ciphertext from the archive,
checks its SHA-256 and MAC, decrypts it and parses it in a jailed process
with no network (a plain-text file is only decoded, in the reader itself,
with no parser). The AI provider receives photos and stickers as re-encoded
images, PDFs as text by page with scanned pages as images, docx, odt, xlsx,
xls, ods, pptx and plain-text files as text, other zip archives as their
entry names, and a video, a round video note or a GIF as its preview image
and the length its sender's app reported. It refuses, with a code and a
sentence telling the assistant what to tell the user: view-once media; audio
and voice notes, until transcription exists; attachments the archive never
downloaded and WhatsApp no longer keeps (`gone`), never recovered because a
recovery would hand the media key to the archive server; keyless or unhashed
media, which the reader cannot verify; other types (HEIC, legacy doc and ppt
among them); and files over 16 MB for photos or 32 MB for documents. A
video's preview image is the exception: it is sealed in the message itself,
so it is sent whatever the video's key, hash or download status, and the
video itself is never fetched. Since reader 0.4.1 every answer about a
message, and `get_message`'s attachment, also carries `open_url`: a link that
opens the message in the console, where the user's own browser decrypts the
original. The assistant gives the user that link when they ask to see, hear
or download an attachment; the file itself never leaves the enclave.

Nothing changes for anyone else. The hosted metadata connector, every
metadata connection and every text connection, whatever its consent version,
never open attachment contents. A text connection never gains attachments,
by renewal or otherwise: connect again with attachments switched on and
revoke the old connection. Renewing a media connection renews its key, never
its consent.

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
`GET /v1/mcp/content` whether its own workspace may use it (`enabled`) and
whether the `enclave` reader allows that workspace at all (`attested`), which
picks the one connector address the console shows. The startup line
prints `content=on|off` and the number of listed workspaces.

Attachments are a third switch on top of content, with three variables
([contract](mcp-enclave.md#16-stage-a-attachments)). Reader 0.4.0 and later
open attachments for media connections; with the switch off, the default, no
connection can.

| Variable | Rule |
|---|---|
| `WS_MCP_MEDIA_ENABLED` | boolean, default `false`; lets content connections whose consent includes attachments (`media`) open them inside the `enclave` reader. With `WS_MCP_CONTENT_ENABLED` off it is off too, and the other two are not inspected |
| `WS_MCP_MEDIA_TENANTS` | workspace UUIDs, comma separated, whose content connections may open attachments; required and non-empty when the switch is on; `*` is refused, and each listed workspace must also be in `WS_MCP_CONTENT_TENANTS` |
| `WS_MCP_MEDIA_OFF_KINDS` | attachment kinds the reader refuses to open, any of `image`, `pdf`, `office`, `text`, `zip`, `audio`, `video`, comma separated; empty by default; an unknown word is a configuration error. Only the reader enforces it: `/v1/media` does not look at kinds and keeps serving their ciphertext to a media connection's key |

A consent asks for attachments with `"media": true`, which needs
`consent_version: 2`, and is refused with `400 media_not_allowed` unless both
switches are on and the workspace is in both lists. The flag is recorded on
the connection and never changes, a renewal included; attachments for an
existing text connection take a new consent. The enclave's status checks
answer `media` (whether that connection may open attachments right now) and
`media_off` (the kinds switched off), so turning the switch off, removing a
workspace or switching a kind off reaches every reader within a minute while
text keeps working. `/v1/media` refuses a content connection's key, with the
same 404 as an attachment that is not the caller's, unless its consent
includes attachments and the switch allows them now; it refuses any other key
acting as a connection's service account (a renewal's new key before the
connection points at it) the same way. The switch and the list reach
`/v1/media` when the server restarts; the kinds reach only the reader.
Discovery adds `mcp.remote.media.v1` when content is advertised and the switch
is on, and `GET /v1/mcp/content` adds `media` for the session's workspace. The
startup line prints `media=on|off`, the number of listed workspaces and, when
any are off, `media_off=`.

Sending is a fourth switch on top of content
([contract](mcp-enclave.md#17-sending-drafts-050-and-direct-send-planned)).
The server carries it from before reader 0.5.0, every switch off: no reader
before 0.5.0 drafts or sends, and a consent with sending fails closed on them.

| Variable | Rule |
|---|---|
| `WS_MCP_SEND_ENABLED` | boolean, default `false`; lets content connections whose consent includes sending (`send`, consent version 3) draft messages for the person who consented to confirm in the console. On while `WS_MCP_CONTENT_ENABLED` is off is a configuration error; off, nothing below is inspected |
| `WS_MCP_SEND_TENANTS` | workspace UUIDs, comma separated, whose content connections may send; required and non-empty when the switch is on; `*` is refused, and each listed workspace must also be in `WS_MCP_CONTENT_TENANTS` |
| `WS_MCP_SEND_SELF_ENABLED` | boolean, default `false`; also lets them send notes to the number's own chat, without the console, where their consent says so |
| `WS_MCP_SEND_DIRECT_ENABLED` | boolean, default `false`; direct send to chats the person chose (S3). Until its server ships, `true` is a configuration error |
| `WS_MCP_SEND_DRAFTS_PER_HOUR` | 1 to 30, default 30: drafts per connection in a rolling hour |
| `WS_MCP_SEND_DRAFTS_PENDING` | 1 to 20, default 20: drafts a connection may have waiting at once |
| `WS_MCP_SEND_PER_DAY` | 1 to 20, default 20: own-chat and direct sends per connection in a rolling day |
| `WS_MCP_SEND_PER_CHAT_PER_DAY` | 1 to 5, default 5: direct sends per connection and chat in a rolling day (S3) |
| `WS_MCP_SEND_MIN_INTERVAL` | a Go duration from `30s` to `1h`, default `30s`: the least time between two sends of a connection |
| `WS_MCP_SEND_TENANT_PER_DAY` | 1 to 1000, default 100: own-chat and direct sends of a whole workspace in a rolling day |

The ceilings are the reader image's own limits: an operator can lower a
limit but never raise one, and a value above its ceiling is a configuration
error. A consent asks for sending with `"send": "draft"` (and `"send_self"`,
`"send_groups"`), which needs `consent_version: 3`, and is refused with
`403 send_not_allowed` unless the switches allow it for the workspace. The
fields are recorded on the connection and never change, a renewal included;
sending for an existing connection takes a new consent. The enclave's status
checks answer `send` and `send_self`, so turning a switch off, removing a
workspace or pausing a connection reaches every reader within a minute while
reading keeps working; the draft and send routes and the console's
confirmation check the switches, the connection and the consenting person's
send permission on every request. A connection's own key, and any key a
connection holds, is refused every WebSocket frame that sends or manages.
Discovery adds `mcp.remote.send.v1` when content is advertised and the switch
is on, and `GET /v1/mcp/content` adds `send`, `send_self` and `send_direct`
for the session's workspace. The startup line prints `send=on|off`, the
number of listed workspaces, `send_self=on|off`, `send_direct=on|off` and
the limits in force. Pending drafts expire after 24 hours, and the ledger of
drafts, sends and refusals keeps no message text and is deleted after 365
days.

AI integrations are a switch on top of attachments
([contract](mcp-enclave.md#18-ai-integrations-on-request-050)): the enclave
sends a number's audio, video, images and documents to the AI provider a
person chose for each function, with that person's own API key, and stores
the transcripts, descriptions and summaries sealed with the number's keys.
The server carries it from before reader 0.5.0, every switch off; it never
sees a key or a word of the content.

| Variable | Rule |
|---|---|
| `WS_AI_ENABLED` | boolean, default `false`; lets the workspaces listed below have AI authorizations. On while `WS_MCP_MEDIA_ENABLED` is off (with content on) is a configuration error; while content or this switch is off, nothing below is inspected |
| `WS_AI_TENANTS` | workspace UUIDs, comma separated; required and non-empty when the switch is on; `*` is refused, and each listed workspace must also be in `WS_MCP_MEDIA_TENANTS` |
| `WS_AI_OFF_PROVIDERS` | a subset of `anthropic,openai,google`, any case and order, switched off for every workspace; an unknown word is a configuration error. Empty by default |
| `WS_AI_OFF_FEATURES` | a subset of `audio,video,image,document`, likewise |

`AIAllowed(workspace)` is attachments allowed for the workspace, the switch
on and the workspace listed. An AI authorization is an `ai` row of the
connections ledger with its own service account, created by an owner or an
admin in the console; it is left out of the cap of ten live connections and
out of `GET /v1/mcp/connections`, and is listed by `GET /v1/ai/authorizations`.
While `AIAllowed` is false its status reads `reseal` (computed, never
written) and the enclave wipes its API keys within a minute; every status
answer of an `ai` row carries `ai_off`: the functions switched off (by
`WS_AI_OFF_FEATURES`, by the row's own narrowing, or because their provider
is in `WS_AI_OFF_PROVIDERS`), the providers switched off, whether the row is
paused, and its lower monthly cap in tokens. `/v1/media` lets an `ai` row's
key through only while the row is active, not paused and `AIAllowed`.
Discovery adds `mcp.remote.ai.v1` when content is advertised and the switch
is on, and `GET /v1/mcp/content` adds `ai` for the session's workspace. The
`/v1/ai/*` routes answer 404 while the switch is off, except the keychain,
the listing of authorizations, their revocation and the deletion of results.
The startup line prints `ai=on|off`, the number of listed workspaces and,
when any is off, `ai_off_providers=` and `ai_off_features=`. Stored results
go with their message and count toward the storage quota; the daily usage
counters are deleted 400 days after their day, and deleted keychain items 30
days after their deletion.

Any MCP client ([contract](mcp-enclave.md#19-any-mcp-client-060)): reader
0.6.0 admits any client that identifies itself with a client metadata
document on an https host of its own, in two tiers (tested and not tested by
Wappie), and a console connection token for tools without OAuth. It
describes each request in a version-2 descriptor and attests all of it; the
server keys its checks on the descriptor's version, never on what a reader
declares. A version-1 descriptor (a reader before 0.6.0) is checked against
`WS_MCP_REDIRECT_HOSTS`, as before. A version-2 one is held to the host
predicate and the Public Suffix List snapshot the reader uses
(`internal/netguard`), to what each kind of client carries, and to these
switches, every one of which can only refuse:

| Variable | Rule |
|---|---|
| `WS_MCP_CIMD_MODE` | `allowlist` (default) or `any`. In `allowlist` mode every consent, renewal and token request for a client Wappie has not tested, and every console token, is refused with `403 client_not_allowed`. Set `any` once a 0.6.0 reader serves; back to `allowlist` turns them off without a release (live ones are revoked from the console) |
| `WS_MCP_BLOCKED_CLIENTS` | tested clients' ids from the image's `TESTED_CLIENTS` (`^[a-z][a-z0-9_]{0,31}$`), comma separated, refused the same way whatever the mode; empty by default |
| `WS_MCP_DCR_HOSTS` | the hosts a dynamically registered client may be identified by, each one a client's host by the predicate; default `claude.ai,claude.com,chatgpt.com` |
| `WS_MCP_NOTICE_ORIGIN` | this server's public https origin (`https://api.wappie.thehappie.co`), where the new-assistant e-mail's revoke-only link points. Optional; without it, or without `WS_SMTP_ADDR` and `WS_MAIL_FROM`, no notice e-mail goes |

The console's consent to a version-2 descriptor carries `trust`,
`client_host`, `client_local` and `claimed_name`, which must equal the
descriptor's, and `history_days` (7, 30 or 90 for an untested client, `null`
for a tested one); text is `consent_version: 4`, drafting is a tested web
client's only, and the ceilings follow the tier: ninety days for metadata
and thirty for text, with an hour's margin, for every tier but a tested web
client's. Text for an untested client or a token is refused with `403
email_unverified` unless the notice e-mail can go and the consenting person
confirmed their address at sign-up. A workspace has at most ten live
assistant connections, of which at most three untested ones and tokens
(`409 too_many_unknown`). Every activation, and every reading limit the
reader reports (`POST /v1/mcp/enclave/connections/{id}/budget-hit`), raises
the new-assistant notice: the console's banner shows the connection again,
and an e-mail goes once per connection and event, at most twenty a day per
workspace, to the person who consented and the owners with a confirmed
address. It names the client's verified domain and tier, never the name the
client gave itself, and its only link is a revoke-only link
(`GET`/`POST /v1/mcp/revoke-link/{token}`) that needs no session, ends that
one connection once, and is replaced by the next notice. The list adds the
client, who consented, the viewer's seen mark (`POST
/v1/mcp/connections/{id}/seen`), the first use and the limits reached. The
console token's routes are `POST /v1/mcp/token-requests` and `POST
/v1/mcp/token-requests/{id}/bundle`, and the attested list of live
connections is relayed by `POST /v1/mcp/workspaces/{id}/live-list`, ten a
minute per workspace. The startup line prints `cimd_mode`,
`blocked_clients`, `dcr_hosts` and `notice_origin`.

A 0.6.0 reader fetches documents itself, over TLS it verifies, through the
document egress proxy on the enclave's parent instance, `cmd/cimd-egress`: a
process of its own, listening on vsock 8007 for the enclave (CID 16) only,
reading `WS_CIMD_EGRESS_OWN_ADDRESSES` (the deployment's own addresses, never
dialed; required) and nothing else. It tunnels `CONNECT <host>:443` to hosts
that pass the same predicate, resolved once to public addresses only, with
budgets overall and per registrable domain, and 16 KiB and 6 seconds per
tunnel. The server's own metadata relay (`/v1/mcp/enclave/cimd`) serves
readers before 0.6.0 only and goes with them.

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
messages as read, fetch attachments or sync history. Message listing preserves the
timestamp/sequence cursor provided by the server. Chats and revisions can report
explicit truncation; these directories do not yet have continuation cursors.
They do not open structured payloads or attachments. They can open encrypted
attachment filenames when plaintext reading is enabled; on a media connection
a message's attachment also says whether `open_attachment` would open it
(`openable`, and `why` when it would not).

Three additional tools build on that archive:

| Tool | Contract |
| --- | --- |
| `resolve_contact` | Matches archived names/phones and an optional personal snapshot. Returns candidate identities and explicit ambiguity; follows archive contact pages through `next`. |
| `search_messages` | Searches all chats of one authorized number using optional lexical body/filename matching, time bounds and metadata filters. Returns sources and historical revision/deletion status. |
| `activity_summary` | Counts a bounded page of archived original messages by chat, sender and direction. Original events can remain counted after a later edit or deletion. |

On a media connection of the attested reader, and there only, `open_attachment`
opens one message's attachment inside the enclave, as [above](#attachments).

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

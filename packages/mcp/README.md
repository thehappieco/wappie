# Wappie MCP: authorized archive reads

An open source MCP server for querying a fixed Wappie installation and
workspace. It runs over **stdio** locally, and the companion
[`packages/mcp-http`](../mcp-http/README.md) serves the same reader over
**Streamable HTTP** in metadata-only mode. It uses the public REST APIs and
public SDK cryptography, without depending on the private app. Requires
Node.js 22 or later.

## Install from the repository

```sh
npm --prefix packages/client ci
npm --prefix packages/client run build
npm --prefix packages/mcp ci
npm --prefix packages/mcp test
```

The MCP package runs ESM files directly, with no separate build step. Official MCP
dependencies are pinned to `2.0.0`; `package-lock.json` records the installed graph.

## Start with a console setup

The private Wappie console can prepare a connection for a workspace owner or
administrator. The public MCP package also supports [manual configuration](#manual-configuration)
without the console.

1. Select the installation and workspace you intend to share. Open **MCP** in
   the console, name the connection and select its numbers.
2. Leave message text disabled for metadata only. To allow text, enable
   **Allow the assistant to read message text** and enter your Wappie password
   for that installation. Your account must have archive access to every
   selected number. The browser uses the password locally; it is not exported.
   Confirm **Timezone for dates in MCP searches**, for example
   `America/Sao_Paulo`. With text reading enabled, you can separately choose
   **Include a snapshot of my personal contacts**. This copies the names and
   phone numbers currently saved in **My contacts**, encrypted for this
   connection. Matching contact results may be sent to the AI provider.
3. Create the connection and download `wappie-mcp-setup.json` before closing
   the setup view. This file contains an API token and, when text is enabled,
   a service account's private key. It can also contain the optional encrypted
   contact snapshot. Keep it out of shared folders and chats.
4. On macOS or Linux with Node.js 22 or later, install the public package and
   import the download into a **new** private directory:

```sh
git clone https://github.com/thehappieco/wappie.git
cd wappie
npm --prefix packages/client ci
npm --prefix packages/client run build
npm --prefix packages/mcp ci
node packages/mcp/setup.mjs \
  --bundle "$HOME/Downloads/wappie-mcp-setup.json" \
  --output "$HOME/.wappie-mcp"
```

If you already have a checkout, update its code and rebuild the SDK before
importing a new bundle or using the new tools:

```sh
git pull --ff-only
npm --prefix packages/client ci
npm --prefix packages/client run build
npm --prefix packages/mcp ci
```

Restart the MCP connection after updating. Existing configurations work with the
expanded eight-tool catalog; the connected installation also needs the new
contact and archive-scan REST endpoints. An old configuration does not gain a
personal contact snapshot automatically. To include one, create and download a
new console setup, import it into a new directory such as
`"$HOME/.wappie-mcp-next"`, and point the host at that directory's `config.json`.
Do not overwrite an existing profile's files.

Adjust the download path if your browser saved a different filename. The output
must be an absolute path in an existing directory you own; it must not already
exist. The importer accepts an ordinary browser download, then creates a `700`
directory with `600` files: `config.json`, `token.txt` and, when needed,
`service-key.txt` and `contacts.enc.json`. It authenticates an included contact
snapshot before writing output, makes no network requests and never replaces
existing files. The contact file remains encrypted on disk.

Earlier version-1 bundles remain compatible with this importer. A bundle without
`timezone` uses `UTC`; one without `contacts` creates no contact snapshot. The
browser's contacts are never imported automatically. A snapshot does not update
when the browser address book changes.

After a successful import, **delete the original download and remove it from the
trash**. The importer leaves it in place. Keep the generated files private; host
configuration below needs only the path to `config.json`, never its credentials.

## Connect to ChatGPT

This package speaks **stdio**. Connect it through OpenAI's Secure MCP Tunnel;
the Wappie server's REST address is not an MCP endpoint. For a connector that
needs no tunnel and no always-on computer, use the installation's hosted
metadata-only endpoint instead; see [remote HTTP MCP](../mcp-http/README.md).

1. Follow the [official Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
   to install `tunnel-client`, create a tunnel in the correct organization and
   associate it with your ChatGPT workspace. Configure its runtime
   `CONTROL_PLANE_API_KEY` as directed there. This is an OpenAI key, separate from
   the Wappie token; do not put it in the Wappie setup.
2. Replace the tunnel ID and every absolute path below, then initialize and
   check the tunnel. Use paths without spaces for this command example:

```sh
tunnel-client init \
  --sample sample_mcp_stdio_local \
  --profile wappie \
  --tunnel-id tunnel_REPLACE_ME \
  --mcp-command "/ABSOLUTE/PATH/node /ABSOLUTE/PATH/wappie/packages/mcp/cli.mjs --config /ABSOLUTE/PATH/.wappie-mcp/config.json"
tunnel-client doctor --profile wappie --explain
tunnel-client run --profile wappie
```

3. Keep the tunnel running and the computer awake. If your account and workspace
   allow it, enable developer mode in ChatGPT settings. In **Plugins**, add a
   developer connection, choose **Tunnel**, select your tunnel and review its
   tools. Enable the connection in a conversation, following the
   [official ChatGPT connection guide](https://developers.openai.com/plugins/deploy/connect-chatgpt).

If the tunnel is missing, check its workspace association and your **Tunnels
Read + Use** permissions. Local installation does not establish ChatGPT access
by itself; discovery and tool calls must still be verified in your workspace.

## Connect to Claude Desktop

This section covers the desktop app. For claude.ai, add the hosted connector
described in [remote HTTP MCP](../mcp-http/README.md) instead.

The same local stdio server works with Claude Desktop. In the desktop app's
settings, open **Developer → Edit Config** and merge this entry into
`claude_desktop_config.json`. Replace all absolute paths, including the Node.js
executable. The [official MCP local-server guide](https://modelcontextprotocol.io/docs/develop/connect-local-servers)
describes this configuration flow.

```json
{
  "mcpServers": {
    "wappie": {
      "command": "/ABSOLUTE/PATH/node",
      "args": [
        "/ABSOLUTE/PATH/wappie/packages/mcp/cli.mjs",
        "--config",
        "/ABSOLUTE/PATH/.wappie-mcp/config.json"
      ]
    }
  }
}
```

Fully quit and restart Claude Desktop, then review and enable Wappie's tools in
the conversation's connectors menu. This config is for the local desktop app.
A Wappie REST address is still not an MCP URL; for claude.ai, add the hosted
connector URL published by your installation (`https://<host>/mcp`), which is
metadata-only and discovered through `/.well-known/oauth-protected-resource`.
See also
[Claude's local MCP support guide](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop).

## First check

Ask the connected assistant:

> Use Wappie to list my authorized numbers. Then list the five most recent chats
> for the number I choose. Do not send messages.

Confirm that only the selected numbers appear. Without text access, encrypted
content remains `locked`. When enabled, opened text is sent to your chosen AI
provider on tool calls. Test a recent message from a selected number to check
that its archive grant is available.

To stop access, revoke the connection's token in the console. That blocks future
Wappie requests; it cannot remove content already shared with an AI provider.
It also does not delete or invalidate a contact snapshot already copied locally.
Create another connection for another installation or workspace. After archive
key changes, a new connection may be needed to grant current keys.

## Manual configuration

The host starts `node /path/to/whatserver2/packages/mcp/cli.mjs --config
/private/path/mcp.json`. The JSON file and all credential files must belong to
the user running the process, with permissions `600` or `400`. Symlinks at the
final path component are rejected. Relative paths resolve from the configuration
file's directory.

### Default: metadata with locked content

```json
{
  "server": "https://your-server.example",
  "workspace": "11111111-1111-4111-8111-111111111111",
  "token_file": "./api-token.txt",
  "device_ids": ["22222222-2222-4222-8222-222222222222"]
}
```

`api-token.txt` contains only an API key, with an optional trailing newline.
It must belong to the configured workspace and have read access to the desired
numbers. The `device_ids` list further restricts the MCP server; when omitted,
it accepts all numbers the credential can read in that workspace. Registered
names, numbers, identifiers, timestamps and states are metadata. Encrypted text
is returned as `body.state: "locked"`; the MCP server does not forward encrypted
blobs or infer their contents.

### Automation: API key acting as a service account

```json
{
  "server": "https://your-server.example",
  "workspace": "11111111-1111-4111-8111-111111111111",
  "token_file": "./api-token.txt",
  "service_user_id": "33333333-3333-4333-8333-333333333333",
  "service_key_file": "./service-private.key",
  "allow_plaintext": true,
  "device_ids": ["22222222-2222-4222-8222-222222222222"]
}
```

1. Generate the key pair with the Go command `wsctl service-key`, keeping its
   output in a private location outside shared logs. Register only the public
   half with a service account.
2. An owner grants the service account the key and read access for each number.
   Create an API key with that account's `acts_as` and the allowed number list.
3. `service-private.key` contains **only the value from the `private` line**
   produced by `wsctl service-key`: 32 bytes in unpadded base64url, 43 characters.
   Do not use the complete output file, the public half or a number's archive key.
4. Set `service_user_id` to the account's UUID. On each operation, the MCP server
   compares it with `/v1/grants`'s `user_id` and opens only authorized grants.

Example setup without putting secret values in command arguments:

```sh
umask 077
mkdir -p "$HOME/.config/wappie-mcp"
./bin/wsctl service-key > "$HOME/.config/wappie-mcp/keypair.private.txt"
awk '$1 == "private" {print $2}' "$HOME/.config/wappie-mcp/keypair.private.txt" > "$HOME/.config/wappie-mcp/service-private.key"
```

The API key and private key are separate files. An API key without `acts_as` can
query permitted metadata, but cannot retrieve service account grants. Do not put
secrets in the MCP host's JSON configuration or in tool arguments.

### Optional encrypted personal contacts

An imported setup with a contact snapshot adds
`"contacts_file": "./contacts.enc.json"` to its configuration. This requires
API-key/service-account mode, `allow_plaintext: true`, `service_user_id`,
`service_key_file` and an explicit `device_ids` list. Session/password mode does
not accept a contact snapshot.

The snapshot is encrypted to that service account and bound to the server origin,
workspace, service user and the **exact configured set of numbers**. Changing
that set, copying the file to another connection or using a different service
key fails validation. Do not point `contacts_file` at a vCard or a plaintext JSON
address book. Use a snapshot prepared for this connection.

Only names and normalized phone numbers are included. Resolution combines them
with archived contact information using exact phone matches and explicit server
aliases; it does not guess phone numbers from numeric LIDs. No Apple, Google or
other contact service is contacted. There is no synchronization with the browser.
To stop using a snapshot, remove `contacts_file` from the private configuration
and remove the local file. Token revocation cannot retract a copied snapshot or
its decryption key.

### Person: existing CLI session and private password file

Sign in with the public CLI, which prompts for the password without displaying it:

```sh
node packages/cli/cli.mjs login --server https://your-server.example --email you@example.test --workspace 11111111-1111-4111-8111-111111111111
```

The CLI writes a private JSON file in `~/.config/whatserver2/`, named from the
server origin's SHA-256 hash. It stores the session, not passwords or private
keys. Set `session_file` to its path; origin, workspace, user and expiration are
checked again.

```json
{
  "server": "https://your-server.example",
  "workspace": "11111111-1111-4111-8111-111111111111",
  "session_file": "./cli-session.json",
  "password_file": "./password.txt",
  "allow_plaintext": true,
  "device_ids": ["22222222-2222-4222-8222-222222222222"]
}
```

The password file contains only the password, with an optional trailing newline.
The MCP server fetches the challenge and current grants to open the key locally;
it does not sign in, create a session or change the account. Renew expired
sessions through the CLI. For metadata only, remove `password_file` and
`allow_plaintext`. Do not mix session/password credentials with API key/service
key credentials.

Password unlocking accepts Argon2id challenges up to **128 MiB**, **5 passes** and
**4 parallel lanes**. Invalid or higher costs are rejected before derivation,
without lowering the protection requested by the server. Wappie's defaults of
64 MiB/3/1 fit within these limits. Authentication responses are limited to 4 MiB,
and unlocking HTTP requests have a 30-second deadline. Service account mode does
not derive passwords and is not subject to these Argon2 limits.

You choose the configuration outside the arguments sent by the model. Configure
another MCP instance to connect to a different server/workspace. Use HTTPS;
HTTP is accepted only for `localhost`, `127.0.0.1` or `::1`.

## Search configuration

These optional properties belong in the private configuration, outside tool
arguments:

| Property | Default | Meaning |
| --- | --- | --- |
| `timezone` | `"UTC"` | An Intl-supported timezone, such as `"America/Sao_Paulo"`, for relative calendar periods. |
| `max_scan_messages` | `500` | Maximum archive rows examined by one search/activity call; integer from 1 to 2000. |
| `max_text_chars` | `4096` | Maximum characters returned per opened text field; integer from 128 to 8192. |
| `contacts_file` | Omitted | Private encrypted personal snapshot, subject to the service-account and exact-scope requirements above. |

For example, add `"timezone": "America/Sao_Paulo"` and
`"max_scan_messages": 1000` to an existing valid configuration. The console
bundle includes its selected timezone; manual configurations and older bundles
default to UTC.

## Tools and limits

| Tool | Purpose |
|---|---|
| `list_numbers` | Authorized numbers in the configured workspace. |
| `list_chats` | A number's chats, with names and previews when unlocked. |
| `list_messages` | A page of messages, with a cursor for older messages. |
| `get_message` | One message by UUID and number. |
| `list_revisions` | Archived message versions, with truncation reported. |
| `resolve_contact` | Candidate identities from archived contacts and an explicitly included personal snapshot. |
| `search_messages` | Bounded lexical search and metadata filtering across a number's archived chats. |
| `activity_summary` | Page-level counts of archived original message events by chat, sender and direction. |

The remote HTTP transport exposes the same eight tools; sealed content is
always reported as `locked` there, because that reader is never given a key.

`list_chats`, `list_messages` and `list_revisions` accept up to 100 items,
defaulting to 50. For `list_messages`, pass
`next` as `before` in the next request, preserving `ts` and `seq`. Chat listing
has no cursor in this version; `truncated: true` means the list is incomplete.
Truncated revisions also have no continuation.
`max_text_chars` limits each opened text (128–8192, default 4096); each text
reports `truncated`. Responses larger than 1 MiB are rejected with
`result_too_large`; reduce `limit`, `max_text_chars` or the configured number list.

### Resolve a contact without guessing

`resolve_contact` requires `device_id` and a `query` of 2–256 characters. It
returns up to 20 candidates by default, with a maximum `limit` of 50. Each call
examines up to 500 archived contacts and the optional personal snapshot. Names
identify their source; results include explicit phone/JID aliases and
`ambiguous` when several candidates match. Ask the user which candidate they
mean before choosing an identity.

Follow the complete returned `next` object as the next call's arguments to scan
more archived contacts. If `omitted_candidates` is positive, narrow the query;
there is no separate cursor for omitted matches from the current page or personal
snapshot. Check `coverage`, including unavailable encrypted names and remaining
archive pages, before concluding that a contact is absent. A personal-only phone
candidate does not prove that the archive contains a conversation with it.

### Search across conversations

`search_messages` requires one authorized `device_id`. It searches that number's
chats together; selecting a contact or listing chats first is unnecessary. For
several authorized numbers, make a call for each number and keep source labels.

With a `query`, all whitespace-separated terms must occur as case-insensitive,
accent-insensitive substrings in the locally opened body or attachment filename.
This is lexical matching: it does not translate queries, infer synonyms, search
file contents or use a semantic/vector index. Text queries require
`allow_plaintext: true`; without a query, metadata filters also work with locked
content. The body is searched before the returned excerpt is shortened.

Optional filters combine with the time interval:

- `chat_key`: restrict to one conversation, including known archive aliases.
- `sender_keys`: one to three explicit identities, such as aliases returned by
  `resolve_contact`; no inferred LID or name is accepted as an identity.
- `direction`: `incoming` or `outgoing`.
- `type`: an archive message type.
- `kind`: `message`, `edit`, `delete` or `reaction`; omitted means all kinds.
- `has_attachment`: presence or absence of archived attachment metadata.

Results arrive newest first, up to `limit` matches (default 20, maximum 50),
within `max_scan_messages` examined rows. A call can return no matches and still
have more rows to search. Follow the complete `next` object unchanged while
`has_more` is true. This is different from `list_messages`, where only the cursor
is passed as `before`.

Each result includes an authenticated REST source reference and an
`archive_status`: `latest_archived`, `superseded`, `deleted`, `control_event` or
`unavailable`. A search can match an old revision or a subsequently deleted
message. Check this state and use `list_revisions` before presenting a historical
statement as current. The source URL contains no credential and still requires
authorized access. To expand context, search the returned `chat_key` with a
bounded explicit time interval and no text query.

### Calendar periods and continuation

Both `search_messages` and `activity_summary` accept either `period` or the pair
`from`/`until`, never both forms. Explicit bounds require RFC3339 timestamps with
an offset; supported fractional seconds, including nanoseconds, are preserved.
The interval includes `from` and excludes `until`.

| `period` | Interval in the configured timezone |
| --- | --- |
| `today` | Start of the current local date until now. |
| `yesterday` | Start of the preceding local date until the start of today. |
| `yesterday_evening` | 18:00 on the preceding local date until the start of today. |
| `last_7_days` | Start of the local date six dates ago until now. |
| `all` or omitted | Unix epoch until now. |

Calendar boundaries account for timezone changes; a local day need not contain
24 hours. `range` reports the resolved bounds, timezone and current clock. Inspect
it when interpreting relative dates. If a row has no original message timestamp,
filtering and ordering use archive arrival time (`order_ts`); `ts` remains absent,
and `coverage.missing_sent_time` reports these cases.

A returned `next` contains fixed `from`/`until`, the `before` cursor and the
original filters. Use it as the full argument object for the same tool. Do not
recompute “yesterday” on each page: a continuation with `before` requires explicit
bounds and no `period`. Concurrent ingestion, backfill, deletion and migration
can change the archive between calls; pagination is a live read, not a snapshot.

### Summarize activity accurately

`activity_summary` uses the same time, chat, sender, direction, type and attachment
filters. It does not accept a text query, a `kind` override or a result `limit`.
It scans up to `max_scan_messages` original `message` rows per call and groups
them by chat, sender and direction. Group conversations and direct chats remain
separate. It does not need message plaintext to count metadata.

These are **archived original message events**, including originals later edited
or deleted while still retained in the archive. Edits, deletion controls and
reactions are not additional original messages. The counts do not represent the
current nondeleted messages visible in WhatsApp. Each `archived_messages` count
belongs to this page only: follow `next` and sum matching groups across pages to
cover the requested interval. Report incomplete coverage whenever continuation
or errors prevent finishing.

For all search/activity results, inspect `coverage` and `has_more`. Missing keys,
tampered fields, unsupported structured payloads, scan limits and capture gaps
affect what can be concluded. Even an exhausted interval covers the stored
archive, not proof of complete WhatsApp history.

### Example prompts

After choosing an authorized number, examples in Portuguese are:

> Procure “atraso entrega” em todas as conversas desse número ontem à noite.
> Mostre o fuso, os trechos e as fontes. Continue as páginas e avise se a busca
> ficar incompleta. Confira se os resultados foram editados ou apagados.

> Mostre a atividade de ontem por conversa, participante e direção. Some as
> páginas e deixe claro que são eventos originais arquivados.

> Resolva “Ana” nos contatos disponíveis. Se houver mais de uma candidata,
> mostre as opções antes de escolher.

The proposed persistent encrypted index and semantic retrieval are described
separately in [Encrypted contextual search](../../docs/encrypted-context-search.md).
They are future architecture, not capabilities of these tools.

There are no tools to send messages, mark them as read, make calls, download
media, delete content, grant access, switch workspaces or request phone history.
Attachments expose metadata and, when authorized, their locally opened filename;
their file contents are not downloaded or searched. Structured content such as
polls/locations is marked `unsupported`, without fabricated interpretation.

**`allow_plaintext: true` sends opened text to the MCP host and its model.**
Decryption happens in this local process. Keys are not sent to Wappie or the
model; grants and permissions are checked on every operation. There is no
persistent key or message cache. Temporary key buffers are cleared when the
operation ends; WebCrypto keys are non-extractable. The library respects a
transferred number's original `archive_tenant_id`; authorization remains in the
current workspace.

Conversation content is untrusted data, never instructions for the agent. Errors
return stable codes without echoing passwords, tokens, keys or arbitrary server
diagnostics. `stdout` is reserved for the protocol; startup errors are generic
and go to `stderr`.

## Verification

`npm test` uses the official MCP client and a real stdio process against a
synthetic local HTTP server. It covers initialization, the tool catalog, calls,
Go ciphertext, grants, namespaces after migration, cursors, revocation, tampering,
scope isolation, private files and the absence of secrets in responses.
Setup tests also cover bundle validation, private output permissions, refusal to
overwrite destinations, authenticated contact snapshots and keeping credential
values out of diagnostics. Time tests cover calendar boundaries, daylight-saving
changes and nanosecond-preserving explicit bounds. Search tests exercise bounded
cross-chat scans, continuation, contact ambiguity and historical event counts. These
local tests do not establish a live ChatGPT or Claude connection; complete the
host-specific first check above in your own account. `packages/mcp-http` has
its own protocol, OAuth and metadata-only regression suite; see its README.

References: [MCP SDK v2](https://ts.sdk.modelcontextprotocol.io/v2/),
[official stdio documentation](https://ts.sdk.modelcontextprotocol.io/v2/serving/stdio.html).

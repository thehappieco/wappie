# Wappie MCP: authorized archive reads

An open source MCP server for querying a fixed Wappie installation and
workspace. It runs over **stdio** locally, and the companion
[`packages/mcp-http`](../mcp-http/README.md) serves the same reader over
**Streamable HTTP**: as the hosted metadata connector, which never opens
content, and inside an attested enclave, which can open message text for a
connection the user enabled it on, and attachments too when that consent
includes them. It uses the public REST APIs and
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

The private Wappie console no longer creates new setups: its **MCP** panel now
offers the [hosted connector](../mcp-http/README.md) instead. The steps below
describe how a setup was created and still apply to importing a
`wappie-mcp-setup.json` made earlier; the console lists those setups' tokens
under **Old local MCP tokens** to revoke them. For a new local
connection, use [manual configuration](#manual-configuration).

1. Select the installation and workspace you intend to share. Open **MCP** in
   the console, name the connection and select its numbers.
2. Leave message text disabled to share metadata alone. To allow text, enable
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
needs no tunnel and no always-on computer, use one of the installation's
hosted endpoints instead; see [remote HTTP MCP](../mcp-http/README.md) and
[MCP setup](../../docs/mcp.md#ways-to-connect) for what each can read.

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
connector URL published by your installation (`https://<host>/mcp`),
discovered through `/.well-known/oauth-protected-resource`. Wappie publishes
two: a metadata connector and an attested reader that can also open text and,
where the consent includes them, attachments; see
[MCP setup](../../docs/mcp.md#ways-to-connect).
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
sessions through the CLI. To read metadata alone, remove `password_file` and
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

### Hosted modes: `credential_source`

The configurations above use the default `credential_source: "files"`. The two
hosted readers in [`packages/mcp-http`](../mcp-http/README.md) build their
configuration in process, one per connection; nobody writes these by hand.
`readerMode(config)` names the mode, and every model-facing string (tool
descriptions, instructions, locked reasons, guidance) picks its wording by it.
Source URLs are left out of results in both hosted modes, because the archive
address a hosted reader uses is internal.

| `credential_source` | Mode | What it opens |
| --- | --- | --- |
| `"files"` (default) | `local` | What the local configuration above allows. |
| `"provided"` | `hosted-metadata` | Nothing. The pilot's hosted connector (`wappie-mcp`) and every connection of kind `metadata`. |
| `"enclave"` | `hosted-content` | Message text, chat names and previews, contact names and filenames, inside the attested reader; with `media: true`, attachment contents too, through [`open_attachment`](#open-attachments-on-a-media-connection). |

**`"provided"` is unchanged by the content milestone and still never opens
content.** The provider hands over only a token; any credential file or
`allow_plaintext` is refused with `provided_credentials_metadata_only`, and no
code reachable from the pilot's server can select `"enclave"`. Text queries
answer `content_sealed_metadata_only`.

**`"enclave"`** is the attested reader's content connection. It requires
`service_user_id`, `device_ids` and `allow_plaintext: true`, and refuses every
file field (`token_file`, `service_key_file`, `session_file`, `password_file`,
`contacts_file`) with `enclave_credentials_invalid`. The provider supplies
`token()`, `serviceKey()` (a non-extractable X25519 key handle with its 32-byte
public half, never key bytes; anything else is `invalid_service_key`),
`expectedEpoch(device)` (the grant epoch consented for that number) and,
optionally, `renewalURL()` and `onStaleGrant({device_id})`. The reader still
fetches the grants on every operation; a grant whose epoch differs from the
consented one, or that the held key cannot open, is refused with `stale_grant`,
after `onStaleGrant` is told (best effort: it is not awaited and cannot fail the
tool) so the enclave can log the event. There is no personal contacts snapshot
in this mode; the provider is never asked for one. The key lives only in the
enclave's memory: when the reader restarts it is gone. From reader 0.6.0 the
provider's optional `keyHeld()` says so, and until the user renews, the
connection keeps reading metadata with its own read-only key: every value that
needs the key is `locked` with the reason "Locked: the Wappie reader holds no
key for this connection right now; the result's renewal says how text comes
back.", every result carries a `renewal` object (`needed`, `renew_url`, `note`),
and a text query, `open_attachment` and the sending tools answer
`reconsent_required` with the renewal link. The words name no cause: the
reader holds no key after a restart or an update, when a renewal works at
once, and also while message text is switched off for the workspace, when
Wappie refuses the renewal until it is allowed again. Before 0.6.0 every tool
answered `reconsent_required`, `list_numbers` included.

**`media: true`** marks a media connection: a content connection whose sealed
consent (version 2) includes attachments. It is accepted only with
`credential_source: "enclave"` (anything else is `enclave_credentials_invalid`)
and defaults to `false`, so every text connection, whatever its consent
version, is unchanged. With it, the provider also supplies `media`, the
enclave's `{host, why(row), openURL(row), consoleURL, open(request, archive), resultMaxBytes}`
(`resultMaxBytes` caps a serialized result: images that would pass it are
withheld; `openURL` is the console link `get_message` adds, and `consoleURL`
the address every such link must begin with), and the reader
then registers a ninth tool, `open_attachment`.
Without `media` in both places the tool does not exist, and the instructions
keep saying that attachment contents are unavailable.

Two guidance codes exist only in this mode. The tool result names the code and
tells the assistant what to say:

| Code | Meaning | Guidance to the assistant |
| --- | --- | --- |
| `reconsent_required` | The reader holds no key for this connection right now (after a restart or an update, or while message text is switched off for the workspace), and the call needs it (a text query, an attachment, a draft or a note). | Give the user the renewal link (or point to the Wappie console) to renew with their password; if Wappie says message text is not available for the workspace, the renewal waits until it is allowed again. The assistant does not reconnect and does not retry until they have renewed. Metadata keeps working meanwhile. |
| `stale_grant` | The number's access changed after consent (new grant epoch, or a grant the held key cannot open). | Ask the user to renew the connection, with the renewal link when there is one. |

A renewal link is included only when it is an `https` address; otherwise the
guidance points to the Wappie console.

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
| `list_numbers` | Start here: the authorized numbers (each `id` is the `device_id` the other tools take), the time zone and current time, and the [`connection` block](#what-a-connection-says-about-itself). |
| `list_chats` | A number's chats, with names and previews when unlocked. |
| `list_messages` | A page of messages, with a cursor for older messages. |
| `get_message` | One message by UUID and number. |
| `list_revisions` | Archived message versions, with truncation reported. |
| `resolve_contact` | Candidate identities from archived contacts and an explicitly included personal snapshot. |
| `search_messages` | Bounded lexical search and metadata filtering across a number's archived chats. |
| `activity_summary` | Page-level counts of archived original message events by chat, sender and direction. |
| `open_attachment` | One attachment's contents, opened inside the attested reader; [media connections](#open-attachments-on-a-media-connection) only. |
| `draft_message` | A message for the user to review and send in the Wappie console; nothing is sent. [Sending connections](#drafts-and-own-chat-notes-on-a-sending-connection) only. |
| `send_to_self` | A text note sent at once to the number's own chat and nowhere else; sending connections whose consent switched it on only. |
| `list_outgoing` | The connection's drafts and sent notes, with their status; sending connections only. |

The remote HTTP transport exposes the same eight tools, `open_attachment`
on a media connection of the attested reader only, and `draft_message`,
`list_outgoing` and `send_to_self` on a sending connection of the attested
reader only. On the hosted metadata
connector (`"provided"`) sealed content is always reported as `locked`, because
that reader is never given a key. On the attested reader (`"enclave"`) content
opens with the connection's key, and a value that key cannot open is `locked`
with the reason "The key this connection holds could not open this content."

Every mode names the Wappie icon in its `initialize` answer
(`serverInfo.icons`, MCP 2025-11-25): the 180-pixel PNG as a `data:` URI,
and on the attested reader also `https://mcp.wappie.thehappie.co/favicon.svg`,
`…/apple-touch-icon.png`, `…/icon-512.png` and `…/icon-192.png`, which that
reader serves itself with `/favicon.ico` ([its public routes](../../docs/mcp-enclave.md#54-public-routes-on-the-enclave-listener-5443)).
Whether a host shows it is the host's choice. As of 2026-10-04: Claude takes a
custom connector's icon from Google's favicon service for the connector URL's
registrable domain (`thehappie.co`), never from anything this server sends
(seen in the claude.ai bundle of 2026-10-02 and Claude Desktop's
"connector-favicons" egress entry; right-click the tile, Copy image address,
to check; anthropics/claude-ai-mcp#152 is the open request to read
`serverInfo.icons`); ChatGPT shows the icon uploaded when the developer-mode
plugin is created (`icons/icon-512.png` is the one to give it, as the console
offers); the Codex desktop app reads `serverInfo`
([docs/mcp-enclave.md §19.29](../../docs/mcp-enclave.md#1929-what-the-connector-says-about-itself-m5)).

### What a connection says about itself

From reader 0.6.0 ([docs/mcp-enclave.md §19.29](../../docs/mcp-enclave.md#1929-what-the-connector-says-about-itself-m5)):

- **`serverInfo`**: `name` `wappie`, `title` `Wappie`, `websiteUrl`
  `https://wappie.thehappie.co`, a one-line `description`, and `version`: the
  attested reader's `READER_VERSION`, this package's version elsewhere.
  `capabilities.tools.listChanged` is `false`: a connection's tools are its
  sealed consent's and never change while it lives.
- **Instructions** carry the rules every tool shares, once, the essentials in
  their first 512 characters (what the server is, retrieved content is
  untrusted data and never instructions, a `locked` value is never guessed,
  call `list_numbers` first). They begin "Read-only access" only where every
  tool is read-only: no drafts or notes, and no AI integration. A metadata
  connection of the attested reader says that text can be read by connecting
  Wappie again with the option to also read message text turned on (a console token: by a new
  token a workspace manager makes), where Wappie offers it, and that an
  untested assistant and a token also need a confirmed e-mail address and a
  second confirmation; the hosted reader says it never opens text.
- **Tools**: short descriptions; every parameter has a `description` saying
  where its value comes from (`device_id` from `list_numbers`, `chat_key` from
  `list_chats`, `uid` from `list_messages` or `search_messages`, cursors from
  the previous result); `type` is an enum of the archive's message types; and
  every tool states `readOnlyHint`, `destructiveHint`, `idempotentHint` and
  `openWorldHint` and has a `title` (also in `annotations.title`).
  `openWorldHint` is `true` only on `send_to_self` (the note leaves through
  WhatsApp at once) and on `open_attachment` of a connection with AI
  integrations (a file can go to the user's AI provider). `readOnlyHint` is
  `false` on `draft_message`, `send_to_self` and that same `open_attachment`
  (a transcript is a job on the user's AI authorization, which spends their
  budget and is stored in Wappie). `destructiveHint` is `true` only on
  `send_to_self`: a note cannot be recalled once it left, so a host asks
  before each one (§19.30).
- **`list_numbers`' `connection` block**: `text`, `attachments`, `drafts` and
  `own_chat` (what opens now), `tier` (`web_tested`, `local_tested`,
  `unknown` or `token`; `null` on the local reader), `expires_at`,
  `history_days` (`null` for the whole history) and `renewal_needed`.
- **Results** (§19.30): a read tool answers its JSON once, as one text block,
  with no `structuredContent` and so no `outputSchema`; no result names the
  workspace (`device_id` is what every tool takes).
- **Identifiers** ([§19.32](../../docs/mcp-enclave.md#1932-the-identifiers-a-result-carries-2026-10-05)):
  a result carries the identifiers a tool takes, once. A message, a hit and
  an activity group name their sender by `sender_key` only (the sender's LID
  when the archive knows it, else its phone JID) and their chat by
  `chat_key`; a chat is its `chat_key`, `is_group`, `last_ts`, name and
  preview; a number is its `id`, `name`, `status` and `paused`, and its
  `name` is the console label, else the WhatsApp push name, else
  "Number 1", "Number 2"…, never its phone. A reply carries `reply_to_uid`,
  the uid of the message it quotes, when that message is among the rows the
  same call read, in the same chat; nothing is fetched to find it, so
  `get_message` never has it. No result carries WhatsApp's message id
  (`wa_id`, `send_to_self` included), a sender's or a chat's phone JID or
  LID beside its key, a chat's aliases or row uid, a number's phone, or a
  contact's row uid. A `chat_key` or `sender_key` that is a phone JID still
  shows the phone. Inputs are unchanged: `sender_keys` takes a phone JID,
  a LID or a key alike, as the archive matches any of the three.

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
identify their source; results include the explicit JID aliases
(`identifiers`, which `sender_keys` and `chat_key` take) and `ambiguous` when
several candidates match. Ask the user which candidate they mean before
choosing an identity. A candidate's E.164 `phones` come back only when the
query is a phone number (7 to 15 digits, with `+`, spaces, dots, dashes and
parentheses only) or the call passes `include_phones: true` because the user
asked for the number; `identifiers` can still hold a phone JID.

On the attested reader (`hosted-content`) each call reads exactly **four pages**
of 500 archived contacts, following `has_more` whatever matched, so the archive
cannot tell from the paging which contact was looked for; `next` continues after
the fourth page. Every other mode reads one page per call.

Follow the complete returned `next` object as the next call's arguments to scan
more archived contacts. Its `after_key` is sealed (AES-256-GCM under a key
derived from the connection's archive credential, bound to the number), since
the archive pages by contact key and the last key on a page is a third
party's JID; it opens only on the connection and number that returned it, and
a changed one is refused as `invalid_cursor`. A plain contact key, as 0.5.0
returned, is still accepted. If `omitted_candidates` is positive, narrow the query;
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
file contents (not even on a media connection) or use a semantic/vector index.
Text queries require `allow_plaintext: true`; without a query, metadata filters
also work with locked content. The body is searched before the returned excerpt
is shortened.

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

On a local install each hit includes a `source` reference with an
authenticated REST URL (`server`, `url`); a hosted hit is its own citation
(`uid`, `chat_key`, `device_id`) and keeps the row's `source` string, as
`list_messages` gives it. Each hit has an `archive_status`: `latest_archived`, `superseded`,
`deleted`, `control_event` or `unavailable`, or `not_checked` for a text query
on the attested reader (below). A search can match an old revision or a subsequently deleted
message. Check this state and use `list_revisions` before presenting a historical
statement as current. The source URL contains no credential and still requires
authorized access. To expand context, search the returned `chat_key` with a
bounded explicit time interval and no text query.

**Text search on the attested reader (`hosted-content`) scans a fixed window.**
Stopping at `limit`, or looking up the history of each hit, would show the
archive which rows hold the words. So a call with a `query` there always
examines the whole budget (`max_scan_messages`, 500 for the enclave) unless the
45-second deadline passes first, and its REST requests depend only on the range,
the filters and the budget:

- The first `limit` hits in scan order are returned; the rest are counted in
  `omitted_hits`. When it is above zero, narrow the range or the filters.
- Hits carry `archive_status: {"state": "not_checked"}` and no history is
  fetched. Use `list_revisions` before presenting a hit as current.
- `coverage.fixed_window` is `true`, and `coverage.deadline_reached` says
  whether the deadline cut the window short.
- `next` starts after the last row examined, not after the last hit returned;
  follow it unchanged while `has_more` is true.

Searches without a query, `activity_summary`, and every search in the other
modes behave as described above.

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

### Open attachments on a media connection

`open_attachment` exists only on a **media connection** of the attested
reader: a content connection whose consent (card version 2, given with the
approver's password) also switched on **Also read attachments**. Text
connections, whatever their consent version, the hosted metadata connector
and the local reader do not have the tool and never open attachment contents.
A text connection does not gain attachments by renewal: the user connects
again with attachments switched on and revokes the old connection.

It takes a `device_id` and a message `uid` (from `get_message`,
`list_messages` or `search_messages`) and opens that message's attachment
inside the enclave. The enclave opens the attachment's sealed media key with
the connection's grants, fetches its ciphertext from the archive with the
connection's API key, checks the archive's SHA-256 and WhatsApp's MAC before
decrypting anything, and hands the file to a parser in a jailed process with
no network, a read-only root and fixed memory and time limits (a plain-text
file is only decoded, in the reader itself, with no parser). What the AI
provider receives:

| Attachment | Sent to the assistant |
| --- | --- |
| Photo, or an image sent as a document (JPEG, PNG, WebP, GIF) | One JPEG, re-encoded: at most 1,568 pixels on the long edge and 300 KB, first frame only, with no location, camera or other metadata |
| Sticker | One PNG, at most 512 pixels on the long edge and 100 KB |
| PDF | Its text, page by page, and per result the scanned image of up to 4 pages without a text layer, or of the pages asked for with `pages` |
| docx, odt, xlsx, xls, ods, pptx | Text: paragraphs, tables and list items; each sheet's first rows as CSV; each slide's text |
| txt, csv, json, md | The text as written |
| Any other zip archive | Its entry names, never the files inside |
| Video, round video note, GIF | Its sealed preview image and the length the sender's app reported; the video itself is never fetched |

Each result is one text block (a JSON header line, then the text) followed by
0 to 4 JPEG or PNG images, never `structuredContent`, a resource or audio.
Text arrives in parts of at most 60,000 characters: pass `next_cursor` back
unchanged for the next one. For a PDF, `pages` takes one page or a range of up
to 4 (for example `"3-6"`) and returns their text and images; `images: false`
returns text only. An attachment that takes long to open answers
`status: "pending"` with `retry_after_s`; call again with the same arguments.
Attachments asked for at the same time on one connection are opened one
after another, in the order asked, with up to four waiting behind the one
being opened: each call waits for its turn within the host's inline wait
(40 seconds on claude.ai, 25 on ChatGPT) and answers `pending` if its turn
has not come by then. An identical call within ten minutes is answered from
the enclave's memory without a second fetch. The reader opens photos and stickers up to 16 MB and
documents up to 32 MB, and reads about 4 MB of text from one file, the first
2,000 pages of a PDF, 50 sheets of up to 2,000 rows and 200 entry names of a
zip archive; the header's `truncated` says what was left out.

These are never opened, and the tool says why with a stable code. A video,
a round video note or a GIF is the exception to `attachment_expired`,
`attachment_unverifiable` and `attachment_pending`: its preview image is
sealed in the message itself, so it is sent whatever the video's key, hash or
download status, and the video itself is never fetched.

| Code | Attachment |
| --- | --- |
| `view_once_excluded` | View-once media. The assistant learns that it exists, never its content. |
| `transcription_unavailable` | Audio and voice notes on readers without AI transcripts (before `ai_v1`). Their length, from `get_message`, is all there is. |
| `attachment_expired` | An attachment the archive never downloaded and WhatsApp no longer keeps (`gone`). It is never recovered: that would hand its media key to the archive server. |
| `attachment_unverifiable` | Keyless or unhashed media: without a sealed media key and a 32-byte `fileEncSHA256` the reader cannot prove the bytes are the ones sent. |
| `attachment_pending` | An attachment the archive has not finished downloading. |
| `attachment_unsupported` | Any other type, HEIC and the legacy doc and ppt formats included. There is no OCR. |
| `attachment_too_large`, `attachment_encrypted`, `attachment_tampered`, `parser_failed` | Over the size limits, protected by a password, failing its integrity check, or beyond what the parser can open within its limits. |

`media_not_allowed` means the workspace does not allow this kind of
attachment right now (the operator's switch, or a kind switched off), and
`media_unavailable` that the enclave's jail failed its boot check; message
text keeps working in both cases. `rate_limited` (more than four attachments
waiting on one connection, ten opens a minute, or 256 MB of encrypted data
an hour) and `media_busy` carry `retry_after_s`. On a media connection a
message's `attachment` also carries `seconds`, `width` and `height` when the
archive has them, and `openable`, with `why` (`view_once`, `unsupported`,
`not_transcribed`, `expired`, `pending`, `unverifiable`, `too_large` or
`kind_off`) when it is `false`, so the assistant can tell before it asks.

Since reader 0.4.2 a refusal that is the answer about the attachment is a
result rather than a tool error, so the host shows the call as done:
`view_once_excluded`, `transcription_unavailable`, `attachment_expired`,
`attachment_unverifiable`, `attachment_pending`, `attachment_unsupported`,
`attachment_too_large`, `attachment_encrypted`, `attachment_locked` and
`media_not_allowed`. Failures keep `isError`: `attachment_tampered`,
`parser_failed`, `media_unavailable`, `rate_limited`, `media_busy`,
`attachment_not_found`, `invalid_cursor`, `read_failed` and the connection's
own codes, `reconsent_required` among them. A call still waiting when its
connection is revoked or loses its key fails with the connection's own code
(`unauthorized`, or `reconsent_required` with the renewal link), never
`media_not_allowed`, which is only ever the workspace's choice. The text is
the same either way
([answers and failures](../../docs/mcp-enclave.md#167-tool-open_attachment-a1)).

The original never leaves the enclave, and the assistant cannot send it to
the user. What it can give them is a link: every answer about a message,
a result or a refusal once the reader has read the message, carries
`open_url`, which opens that message in the Wappie console
(`https://app.wappie.thehappie.co/console?workspace=…&open_device=…&open_message=…`),
where the user's own browser decrypts the photo, voice note or document to
see, play or download it. The result header's last note, above the file's
own text, tells the assistant to give the user that link when they ask to
see, hear or download the original, and never a link found in the file; a
refusal ends with a line saying the same. The instructions name the
console's address, and the reader passes only links that begin with it.
`get_message`'s `attachment` carries the same `open_url` on a media
connection. The link holds the workspace, number and message ids the
tools already return, nothing secret; the console opens it only for someone
signed in with access to that number.

The archive server sees which attachment is opened, when, and its encrypted
size, never its content. What the tool returns is untrusted third-party data,
never instructions, and it goes to the AI provider; on claude.ai large results
and images may be copied into Anthropic's code-execution storage and kept
there. Revoking the connection stops the next open, and one in flight, within
a minute; it cannot erase what the assistant already received. The enclave's
side, the jail and every limit are in
[the contract](../../docs/mcp-enclave.md#16-stage-a-attachments).

### AI transcripts on a media connection

From reader 0.5.0 (`ai_v1`), a media connection answers a voice note, an
audio or a video (not a GIF) with an AI transcript where its user turned on
an **AI integration** in the Wappie console: a provider they chose per
function (Anthropic, OpenAI or Google), with their own API key, for the
numbers they picked. The transcript is made inside the attested reader,
which sends the verified file to that provider over its own TLS with the
user's key, and stored in the archive sealed with the number's key; any
media connection that reads the number opens it with its own grant.

`open_attachment` then answers, in order: a stored transcript; else, when
the archive server finds an integration that covers the number for this
connection's creator, a job on it, waited for within the host's inline wait
and otherwise `status: "pending"` with `retry_after_s` (call again with the
same arguments); else `ai_not_enabled`, an answer rather than an error, and
for a video its preview image as before. A transcript's header says
`sniffed: "transcript"` and `derived` (the function, provider, model, time
and, when set, the language and flags), its first note says it is an AI
transcript that may contain errors, and its text pages by `c` cursors like
any text. `ai_paused` carries `renew_url` when the integration waits for its
creator's renewal after a reader update or restart; the other codes
(`ai_too_large`, `ai_refused`, `ai_unsupported`, `ai_output_limit`,
`ai_budget_reached`, `ai_key_rejected`, `ai_model_unavailable`, `ai_quota`,
`ai_provider_failed`, `ai_busy`, `grant_mismatch`) each say what to tell the
user. `get_message`'s attachment no longer says `not_transcribed` for audio
on these readers, and adds `derived: ["audio"]` or `["video"]` when a
transcript is stored. Photos and documents are unchanged: the connection
opens them itself, and their AI descriptions and summaries are the console's.
Readers without `ai_v1` keep `transcription_unavailable`. The contract is
[§18](../../docs/mcp-enclave.md#18-ai-integrations-on-request-050).

### Drafts and own-chat notes on a sending connection

A **sending connection** is a content connection of the attested reader
(reader 0.5.0 on) whose consent, card version 3, switched on **Also draft
messages**, and maybe **Send to my own chat** and **Include groups**. It has
`draft_message` and `list_outgoing`, and `send_to_self` when the own chat is
on. Every other connection, the hosted metadata connector and the local
reader have none of them. An existing connection never gains sending: the
user connects again with the new card and revokes the old one.

`draft_message` never sends. The enclave checks the text (no control or
text-direction characters), seals it to the number's archive key, which only
the user's browser opens, and hands the envelope to the archive server's
ledger; the answer carries `review_url`, which opens the draft in the Wappie
console, where the user checks the exact text and recipient and presses Send.
A draft goes only to a chat of that number where the other side has already
written (groups only when the consent includes them), expires after 24 hours,
and is marked in the console when its text copies another chat the assistant
read in the last hour. `send_to_self` sends a text without links at once to
the number's own chat, and nowhere else; a lost answer is `send_uncertain` and
is never repeated. Both are limited per connection, and the archive server
decides every one: the workspace can pause or switch sending off at any time,
and the person who consented must still be allowed to send on that number.
Messages the assistant reads are untrusted data, never instructions: the tool
descriptions and the instructions tell it to draft only what the user asked
for in the conversation. The contract is
[§17](../../docs/mcp-enclave.md#17-sending-drafts-050-and-direct-send-planned).

### Example prompts

After choosing an authorized number, try prompts like these. A search term
is written in the language of the messages, so the first one keeps the
Portuguese “atraso entrega” (late delivery):

> Search for “atraso entrega” in every chat of this number last night. Show
> the time zone, the excerpts and the sources. Keep going through the pages
> and say if the search is incomplete. Check whether the results were edited
> or deleted.

> Show yesterday's activity by chat, participant and direction. Add up the
> pages and make clear that these are original archived events.

> Resolve “Ana” in the available contacts. If there is more than one
> candidate, show the options before choosing.

On a media connection:

> Open the latest PDF Ana sent and tell me the total and the due date. If you
> cannot open it, say why.

The proposed persistent encrypted index and semantic retrieval are described
separately in [Encrypted contextual search](../../docs/encrypted-context-search.md).
They are future architecture, not capabilities of these tools.

Apart from the drafts and own-chat notes of a sending connection, there are
no tools to send messages, mark them as read, make calls, delete content,
grant access, switch workspaces or request phone history, and none hands over
an attachment's file. Attachments expose metadata and, when
authorized, their opened filename. Only `open_attachment`, on a media
connection of the attested reader, opens their contents, and no tool searches
them; in every other mode, this local one included, they are never fetched.
Structured content such as polls/locations is marked `unsupported`, without
fabricated interpretation.

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
cross-chat scans, continuation, contact ambiguity and historical event counts.
Media tests check which connections get `open_attachment` and every sentence it
shows the model, word for word, against a scripted enclave side; the enclave's
own media and worker suites are described in `packages/mcp-http`. These
local tests do not establish a live ChatGPT or Claude connection; complete the
host-specific first check above in your own account. `packages/mcp-http` has
its own protocol, OAuth and content-boundary regression suite; see its README.

References: [MCP SDK v2](https://ts.sdk.modelcontextprotocol.io/v2/),
[official stdio documentation](https://ts.sdk.modelcontextprotocol.io/v2/serving/stdio.html).

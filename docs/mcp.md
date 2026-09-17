# Local MCP for authorized archive reads

The public [`packages/mcp`](../packages/mcp/README.md) package connects an MCP
host to a Wappie installation's REST APIs. It provides number, chat, message,
revision and contact queries, bounded cross-chat lexical search and activity
counts without depending on the commercial app.

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

This release has no public HTTP MCP endpoint. A Wappie REST address cannot be
used as a remote MCP URL. The computer running the local connection must remain
available. A [manual setup](../packages/mcp/README.md#manual-configuration) also
works with public API/CLI credentials, without the commercial console.

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
and use `list_revisions` before describing a match as current. Exhausting an
archive interval does not establish that every original WhatsApp message was
captured. See [period semantics and continuation](../packages/mcp/README.md#calendar-periods-and-continuation)
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

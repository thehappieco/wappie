# Local MCP for authorized archive reads

The public [`packages/mcp`](../packages/mcp/README.md) package connects an MCP
host to a Wappie installation's REST APIs. It provides number, chat, message and
revision queries without depending on the commercial app.

## Connect an assistant

The console offers an **MCP** setup for workspace owners and administrators:
choose the installation, workspace and allowed numbers; decide whether to allow
message text; then download the private setup bundle. The bundle contains a
token and, when text is enabled, a private service key. Import it locally with
`packages/mcp/setup.mjs` and delete the original download after import.

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
- The model cannot choose another installation, workspace, credential or path.

Opened text is sent to the MCP host and model chosen by the user. Keys stay in
the local process, without a persistent cache, and current grants remain
required. A key stored on the computer does not bypass revocation or a workspace
change. Private credential files and TLS remain necessary.

## First-version contract

`list_numbers`, `list_chats`, `list_messages`, `get_message` and `list_revisions`
only read the persisted archive. They do not send messages, make calls, mark
messages as read, download media or sync history. Message listing preserves the
timestamp/sequence cursor provided by the server. Chats and revisions can report
explicit truncation; these directories do not yet have continuation cursors.
This release does not open structured payloads or attachments.

For limits, complete examples, identity setup and host configuration, see the
[MCP package guide](../packages/mcp/README.md).

The SDK's [`ArchiveClient`](../packages/client/README.md#read-only-rest-client)
also supports custom HTTP clients with fixed origins/workspaces, the same
sealed envelopes and local decryption through the public `Opener`.

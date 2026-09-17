# Wappie MCP: authorized local reads

An open source MCP server over **stdio** for querying a fixed Wappie installation
and workspace. It uses the public REST APIs and public SDK cryptography, without
depending on the private app. Requires Node.js 22 or later.

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
3. Create the connection and download `wappie-mcp-setup.json` before closing
   the setup view. This file contains an API token and, when text is enabled,
   a service account's private key. Keep it out of shared folders and chats.
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

If you already have this checkout and its dependencies, run only the import.
Adjust the download path if your browser saved a different filename. The output
must be an absolute path in an existing directory you own; it must not already
exist. The importer accepts an ordinary browser download, then creates a `700`
directory with `600` files: `config.json`, `token.txt` and, when needed,
`service-key.txt`. It makes no network requests and never replaces existing
files.

After a successful import, **delete the original download and remove it from the
trash**. The importer leaves it in place. Keep the generated files private; host
configuration below needs only the path to `config.json`, never its credentials.

## Connect to ChatGPT

This package speaks **stdio**. Connect it through OpenAI's Secure MCP Tunnel;
the Wappie server's REST address is not an MCP endpoint.

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
the conversation's connectors menu. This config is for the local desktop app;
do not add the Wappie REST address as a remote MCP URL in claude.ai. See also
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

## Tools and limits

| Tool | Purpose |
|---|---|
| `list_numbers` | Authorized numbers in the configured workspace. |
| `list_chats` | A number's chats, with names and previews when unlocked. |
| `list_messages` | A page of messages, with a cursor for older messages. |
| `get_message` | One message by UUID and number. |
| `list_revisions` | Archived message versions, with truncation reported. |

MCP pages contain up to 100 items, defaulting to 50. For `list_messages`, pass
`next` as `before` in the next request, preserving `ts` and `seq`. Chat listing
has no cursor in this version; `truncated: true` means the list is incomplete.
Truncated revisions also have no continuation in this first release.
`max_text_chars` limits each opened text (128–8192, default 4096); each text
reports `truncated`. Responses larger than 1 MiB are rejected with
`result_too_large`; reduce `limit`, `max_text_chars` or the configured number list.

There are no tools to send messages, mark them as read, make calls, download
media, delete content, grant access, switch workspaces or request phone history.
Attachments expose metadata only; structured content such as polls/locations is
marked `unsupported`, without fabricated interpretation.

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
overwrite destinations and keeping credential values out of diagnostics. These
local tests do not establish a live ChatGPT or Claude connection; complete the
host-specific first check above in your own account.

References: [MCP SDK v2](https://ts.sdk.modelcontextprotocol.io/v2/),
[official stdio documentation](https://ts.sdk.modelcontextprotocol.io/v2/serving/stdio.html).

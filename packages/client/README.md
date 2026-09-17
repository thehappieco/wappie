# Wappie public TypeScript client

Apache-2.0 client for the public HTTP/WebSocket API, account authentication,
passkeys, sealed archive and media formats. It has no Vue or private application
dependency. The only runtime dependency is Argon2id (`@noble/hashes`); encryption
uses WebCrypto. Node 22+ or a modern secure-context browser is required.

From this directory:

```sh
npm ci
npm run build
npm test
```

The tests use the public server's committed Go vectors and a browser-created
fixture in `testdata/browser-grant.json` which the Go tests independently open.
The WebSocket tests run a real local server and check request routing and closes.

```ts
import { Connection, protocol } from '@whatserver2/client'

const connection = await Connection.connect({
  serverURL: 'https://your-installation.example',
  credential: { kind: 'api_key', token: apiKey },
  onFrame: frame => console.log(frame),
  onClose: reason => console.log(reason),
})
const devices = await connection.request(protocol.TypeDevicesList, {}, protocol.TypeDevices)
connection.close()
```

Subpath exports include `api/auth`, `api/rest`, `api/passkeys`, `api/media`, `api/upload`,
`api/opener`, `api/protocol`, and `crypto/{bytes,hpke,seal,account,passkey,wamedia}`.
Build output includes types and browser KDF worker source. Applications may call
`setMessageResolver` from `messages` to translate diagnostics. Error codes and
server diagnostic details remain available without any UI framework.

An explicit `serverURL` always chooses that installation. An empty URL uses the
current page's origin. Credential persistence and which credentials to use are
application responsibilities; the SDK does not share session state between
installations. Never send credentials for one installation to another.

## Read-only REST client

`ArchiveClient` reads the versioned public archive endpoints without opening a
WebSocket. Pin the installation and operational workspace when constructing it;
every successful response must identify that same `tenant_id`. Redirects are
refused. HTTPS is required except for loopback development servers.

```ts
import { ArchiveClient } from '@whatserver2/client'

const archive = new ArchiveClient({
  serverURL: 'https://your-installation.example',
  workspaceID: workspaceUUID,
  token: sessionOrAPIKey, // load from your secret store, never a model argument
})
const { devices } = await archive.listDevices()
const chats = await archive.listChats(devices[0].id, { limit: 100 })
const page = await archive.listMessages(devices[0].id, {
  chatKey: chats.chats[0].chat_key, limit: 50,
})
if (page.has_more && page.next_ts && page.next_seq !== undefined) {
  const older = await archive.listMessages(devices[0].id, {
    chatKey: page.chat_key,
    before: { ts: page.next_ts, seq: page.next_seq },
  })
}
```

The methods are `listDevices`, `listChats`, `listMessages`, `getMessage`,
`history`, `grants` and `contentKeys`. They preserve the existing sealed protocol
rows; they do not send messages, mark them read or decrypt on the server. Chat
listing reports `truncated` and currently has no continuation cursor. Message
pagination uses the returned timestamp **and** sequence together; do not derive
a cursor from local ordering.

`archive.keySource(deviceID)` supplies the narrow `keys.get` interface expected
by `Opener`. Combine it with a locally authorized archive key, never send a
private key to the REST server. The public [MCP package](../mcp/README.md) is one
complete implementation, with metadata-only mode as its default.

## Archives moved between workspaces

`tenant_id` continues to select the workspace for authorization, API calls and
storage accounting. `archive_tenant_id` in devices, grants and content-key replies
is the device's immutable cryptographic namespace. A moved archive keeps its
original namespace, device ID, row IDs, epochs and content-key IDs. No ciphertext
format changes or server-side private keys are required.

The SDK opens grants with their archive namespace and exposes it as
`Readable.archiveTenantID`. `withDeviceKey` supplies it as the third callback
argument; use that value for `grantRow` and `sealDirect` when granting access.
`Opener` also reads the namespace from content-key replies. Missing metadata from
older servers falls back to the current workspace for compatibility.

Update clients before transferring a number. Old clients that always use the
current workspace as their cryptographic namespace cannot open transferred
archives. Returning an original namespace never authorizes access to that old
workspace: all requests still use the currently authenticated workspace.

The private app uses this package through a local file dependency during joint
checkout development. For separate checkout builds install a packed or published
version of this package and retain the same subpath imports.

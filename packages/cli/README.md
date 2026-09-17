# Public account and administration CLI

`wsctl` is an Apache-2.0 Node 22+ client for independently running servers. It uses `@whatserver2/client` directly; the private application and Vue are not dependencies. The Go `wsctl` remains useful for operator/API-key workflows; this package adds human password sessions and client-side key grants.

From a public source checkout:

```sh
npm --prefix packages/client ci
npm --prefix packages/client run build
npm --prefix packages/cli ci
node packages/cli/cli.mjs --help
```

Use the full `node packages/cli/cli.mjs` command below, or install its bin locally with `npm --prefix packages/cli link`. The local `file:../client` dependency is deliberate for a source distribution; neither package is claimed to be published to npm.

## Account access

```sh
wsctl login --server https://archive.example --email owner@example.com
wsctl signup --server https://archive.example --email reader@example.com --invite INVITATION --recovery-out ./recovery.txt
wsctl recover --server https://archive.example --email owner@example.com --recovery-out ./new-recovery.txt
wsctl password --server https://archive.example
wsctl logout --server https://archive.example
```

Passwords and recovery input are prompted without echo. Passwords are never sent to the server: the public SDK derives the authentication proof and opens the account wrap locally. `recover` rotates the recovery code and saves the replacement in a new private file. `signup` does the same for the first recovery code. Existing output files are never overwritten. Failed attempts may leave an empty reserved output file; inspect and remove it before retrying with that same filename.

For noninteractive jobs, use `--password-file FILE`, `--new-password-file FILE`, or `--code-file FILE`. Protect these input files and remove them when finished. Passwords are not command-line arguments. Session files contain only the bearer session and account identifiers, with mode 0600 in `~/.config/whatserver2`. Each origin has a separate hashed filename. `--state-dir DIR` supports an alternate profile. A session is refused after expiry or if its stored origin differs from the requested server. No private account/archive key is saved.

Public signup policy can be inspected with `signup-config`. When email verification is required, request it with `verify-email --email EMAIL`, then pass the received token to signup with `--verification TOKEN`.

## Workspace administration

```sh
wsctl workspaces --server https://archive.example
wsctl workspace WORKSPACE_UUID --server https://archive.example
wsctl members --server https://archive.example
wsctl storage --server https://archive.example
wsctl http GET /v1/auth/workspaces/storage/history --server https://archive.example
wsctl http POST /v1/auth/workspaces/storage/resume --server https://archive.example
```

The server enforces owner/admin permissions. Workspace selection creates a session bound to the selected workspace and replaces only this CLI profile's saved session. It does not mix credentials from different installations.

Any public JSON HTTP endpoint can be called with `http METHOD /v1/PATH --json FILE`. Use `--json -` for stdin. Requests stay on the selected origin and reject redirects. For example, put `{"email":"reader@example.com","role":"reader"}` in `invite.json` and run:

```sh
wsctl http POST /v1/auth/workspaces/invites --json invite.json --server https://archive.example
```

Member role/status changes use `PUT /v1/auth/workspaces/members/USER_UUID` with `{"role":"reader","status":"active"}`; removal uses DELETE on that path. These changes apply immediately when the server accepts them.

## Devices, API keys and encrypted grants

```sh
wsctl ws devices.list --reply devices --server https://archive.example
wsctl ws users.list --reply users --server https://archive.example
wsctl ws apikeys.list --reply apikeys --server https://archive.example
wsctl grant --device DEVICE_UUID --user USER_UUID --server https://archive.example
```

`grant` verifies the recipient against the workspace's user list, asks for your password again, opens an existing device grant locally, seals the device key to the recipient, and sends only the sealed grant. It does not create access to an archive you cannot already open. Optionally pin the expected recipient key using `--public-key BASE64`.

`ws REQUEST_TYPE --reply RESPONSE_TYPE --json FILE` exposes the public request/reply protocol for device controls, permissions and API-key administration. For example, `grant.revoke` with `{"device_id":"...","user_id":"..."}` replies with `device.readers`. Wire names and payloads are defined in `packages/client/src/api/protocol.ts` and `internal/wsapi/protocol.go`. Long-lived subscription/pairing streams are not implemented by this one-request command; existing operator CLI workflows remain available.

## Verification

`npm --prefix packages/cli test` checks isolated sessions, private file permissions, no password/key persistence, same-origin requests and redirect rejection, WebSocket session authentication/cleanup, recovery output protection, and a real public-SDK password derivation/account-unwrapping exchange against a local HTTP fixture.

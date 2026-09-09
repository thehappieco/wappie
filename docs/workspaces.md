# Wappie: identities and workspaces

## Product decisions

- Wappie is primarily an API product for businesses, with a simpler messaging client.
- Server, CLI, messaging client and basic workspace administration will be open source.
- Commercial hosting/billing will live separately. The core uses Apache-2.0.
- One identity can belong to several workspaces. Roles, integrations, numbers and subscriptions belong to a workspace.
- Hosted pricing will be based on contracted WhatsApp connection capacity, with storage/usage limits still to be decided.
- Pilot: two companies, four test numbers, free access and simulated payments, on the existing EC2. Maintenance interruptions are acceptable.
- Public repository: https://github.com/thehappieco/wappie
- Public site and documentation: `wappie.thehappie.co` and `/docs`.
- Administration: `console.wappie.thehappie.co`; messaging: `app.wappie.thehappie.co`; HTTP/WebSocket: `api.wappie.thehappie.co`.
- Joining a workspace does not grant archive access. Explicit device key grants unlock all stored history covered by the granted epochs. Revocation cannot erase already obtained keys or content.

## Implemented server foundation

Migration 0021 adds `workspace_memberships`, copying each existing user's role to their original workspace. Identity IDs, password/recovery envelopes and device key grants remain unchanged. New identities receive their initial membership transactionally through a trigger.

The existing `users.tenant_id` and `user_logins.tenant_id` remain stable credential-routing UUIDs for compatibility. They no longer cascade with workspace deletion. They are not authorization for a workspace: membership supplies that role. Removing the original workspace therefore preserves the identity and access in other spaces. Service identities remain registered to their original workspace and cannot redeem human workspace invitations.

Login prefers the original workspace if its membership and workspace are active; otherwise it selects the earliest active membership, breaking ties by workspace UUID. An identity without an active workspace receives an identity-only session (NULL workspace in storage; zero UUID on the wire). It can recover its account, list workspaces and accept invitations, but cannot use device APIs or administer a workspace. Selecting a workspace requires an active membership.

### HTTP interface

All routes below require `Authorization: Bearer <session-token>`. An API key cannot use them. Existing login, signup, recovery and `/v1/auth/me` wire formats remain compatible.

| Method and path | Request | Response |
| --- | --- | --- |
| `GET /v1/auth/workspaces` | None | `{"workspaces":[{"id":"UUID","name":"Workspace","avatar":"","role":"member","status":"active","created_at":"RFC3339"}]}` |
| `PUT /v1/auth/workspaces/current` | `{"name":"Support team","avatar":"data:image/jpeg;base64,..."}` | Updated workspace metadata. Owner/admin only; the session selects the workspace. |
| `POST /v1/auth/workspaces/accept-invite` | `{"invite":"one-time-code"}` | `{"tenant_id":"UUID"}` |
| `POST /v1/auth/workspaces/session` | `{"tenant_id":"UUID"}` | Existing login response: token, expiry and account with the selected workspace/role. |

Workspace profiles use names of 1–80 Unicode characters. `avatar` is an optional image represented as a data URL; send an empty string to remove it. The server accepts only PNG/JPEG, limits the decoded file to 32 KiB and each dimension to 512 pixels, and decodes/re-encodes the pixels to strip metadata and trailing payloads. It never fetches remote profile URLs. The browser crops JPG/PNG/WebP uploads locally to a compact square thumbnail. Profile changes serialize with membership changes and re-check the manager’s authority in the transaction. Invalid profiles return `400 invalid_workspace_profile`.

Workspace listing includes suspended spaces but excludes disabled memberships. Selecting a suspended space or one without membership returns `403 not_authorized`; malformed UUIDs return `400 bad_request`. Invalid, expired, consumed, wrong-recipient, service or duplicate-membership invitations return `403 invite_invalid`.

Invite validation, membership insertion and consumption share one transaction. Rejected acceptance does not spend an otherwise valid invitation or promote an existing member. Accepting does not switch the current session or create device grants.

Selecting a workspace creates a new token with the source session's expiry; switching cannot extend the authentication lifetime. It does not mutate the previous token or move existing WebSockets between spaces. Clients must close their old connection, discard the old space's loaded data/keys, load `/v1/auth/me` with the new token and reconnect using that token. Other tabs may keep their own sessions in different spaces. End unused tokens through the existing logout endpoint.

Password changes from any active workspace update the same identity and atomically revoke stored sessions across spaces.

## Phase 2: membership management and live revocation

The authenticated session selects the workspace for these routes. They accept no caller-supplied workspace override. API tokens cannot administer members.

| Method and path | Request | Response |
| --- | --- | --- |
| `GET /v1/auth/workspaces/members` | None | `{"members":[{"id":"UUID","email":"person@example.com","role":"member","status":"active","last_owner":false,"created_at":"RFC3339"}]}`; disabled memberships are included. No password or key envelopes are returned. |
| `PUT /v1/auth/workspaces/members/{userID}` | `{"role":"member","status":"disabled"}`; both fields required | `204` |
| `POST /v1/auth/workspaces/invites` | `{"role":"member","email":"person@example.com"}`; email optional | `201 {"invite":"one-use-code"}`; expires in seven days. No email is sent. |

Owners can manage all roles. Administrators can manage members and service accounts, but cannot modify administrators/owners or invite/promote somebody to those roles. Members and service accounts cannot manage memberships. Service accounts cannot be converted into people or vice versa.

The member directory marks the sole active owner with `last_owner:true`, allowing clients to disable role/status controls and explain how to add a backup. This is informational; the mutation endpoint independently enforces the invariant. At least one active owner must remain: attempting to demote or disable the last owner returns `409 last_owner`. Changes serialize on the workspace row and re-read the actor's permissions within that transaction, including concurrent self-demotions. Transfer ownership by first promoting another active person, then demoting the original owner.

Changing a role/status revokes that person's sessions in this workspace and expires their outstanding invitations here. Disabling additionally deletes all their device grants in the workspace and revokes tokens acting as that service account. Re-enabling restores the membership only: previous sessions, tokens and grants remain revoked. Other workspaces are unaffected. No-op updates preserve existing sessions.

Migration 0022 introduces a membership access revision, also advanced by grant deletion. WebSockets retain only authenticated session/key IDs and the revision, not raw tokens. Authorization is checked before dispatching commands and before writing queued frames. Local HTTP mutations wake idle sockets promptly; periodic checks every second cover other processes, direct database changes and expiration. Database check failures close the connection. Under normal database availability, idle invalid connections are detected at the next check; this is not a promise to recall bytes already sent or undo operations already in flight.

Logout, password change/recovery, membership changes, service disabling, API key revocation, grant removal and workspace suspension invalidate affected open connections. The connection closes with WebSocket code `1008`; clients must authenticate/reconnect as appropriate. Role changes intentionally require a new session rather than retaining cached privileges.

Members and service accounts see only currently granted devices in the device directory, history replay, live subscription and device-status notifications. Explicit subscription requests for ungranted devices are refused. Accounts with no grants cannot subscribe. Administrative roles do not implicitly grant conversation access.

## Delivery phases

| Phase | Status | Changes |
| --- | --- | --- |
| 1 — Identity and workspaces | Implemented and tested | Shared identity, memberships, invitations for existing users and workspace sessions; preserve existing keys. |
| 2 — Members and revocation | Implemented and tested | Member directory, guarded role/status changes and invitations, last-owner protection, active-connection revalidation and grant-aware event delivery. |
| 3 — Device/action permissions | Implemented and tested | Independent administration/read/send permissions for people and integrations, with consistent enforcement across HTTP and WebSocket. |
| 4 — Console and messaging client | Implemented and tested | Workspace/member/integration administration and workspace selection; identity-only onboarding/recovery when no workspace is active; preserve key isolation. |
| 5 — Pilot subscriptions | Implemented and tested | Contracted connection capacity and payment simulation. Provider, prices and storage/usage quotas remain undecided. |
| 6 — Publication and deployment | Published and verified | Homepage, HTTP/WebSocket documentation, license selection and public repository preparation, then EC2/DNS/TLS for the four product addresses. |

Database tests use isolated test schemas. The official pilot uses a new, independent database on the existing EC2; it does not migrate the other services' databases. DNS/TLS activation is tracked separately from code delivery.

## Device permissions and capacity

`GET /v1/auth/workspaces/devices/{deviceID}/permissions` returns `{"permissions":[{"device_id":"UUID","user_id":"UUID","read":true,"send":false,"manage":false,"has_key":true}]}`.
`PUT` on the same path accepts `user_id`, `read`, `send`, `manage`; the path supplies the device. Owner/admin roles implicitly retain device management. Read requires both `read` and a grant for the current archive epoch. Send works without read. These checks cover HTTP media and WebSocket commands, UID message lookup, event subscription, directories and status delivery. Existing grants migrate to read/send for compatibility. Removing read also removes grants; re-enabling read requires an explicit fresh key grant from a client holding the key.

`GET /v1/auth/workspaces/capacity` returns `{"max_devices":2,"used_devices":1}` to workspace managers. `max_devices:null` means no configured limit. A database trigger serializes new device creation against the workspace row and refuses creation at capacity. Self-hosted workspaces have no limit by default. All registered devices occupy a slot, including disconnected ones; deleting a device releases its slot.

The hosted build selects a private subscription component. Simulated approvals and declines, idempotency records and capacity changes live in the separate commercial module. Only owners change subscriptions; admins can view them. No card data, prices, provider secrets or live charges are implemented or required for this pilot.

The console uses a fresh document when changing workspaces. Only the target workspace UUID is included in the URL; credentials, keys and messages are never transferred there. The person signs in again, and the server issues a session bound to the selected workspace. This intentionally discards pending work and all in-memory archive state before opening another workspace.

Legacy API key device allowlists remain restricted even when the last allowed device is removed. Migration 0026 stores that distinction explicitly and versions list changes so existing WebSockets close instead of retaining the earlier subscription scope. Prefer service accounts and the console's per-device permissions for new integrations.

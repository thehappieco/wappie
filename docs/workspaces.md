# Wappie: identities and workspaces

## Product decisions

- Wappie is primarily an API product for businesses, with a simpler messaging client.
- Server, API/CLI administration and integration/cryptography libraries are open source. App and console development is private.
- App, console, hosting and billing live in the private `wappie-cloud` repository. The core uses Apache-2.0; previously released web versions retain that license.
- Every human identity has one personal workspace and may create or join team workspaces. Personal workspaces allow their owner and service identities; only teams admit additional people. Workspace type is independent of the subscription plan. Roles, integrations, numbers and subscriptions belong to a workspace.
- Private app subscriptions count commercial number bindings. Hosted storage is a separate package shared by the workspace; externally hosted archives have no Wappie storage charge. See [storage](storage.md) and [external clients](external-clients.md).
- Pilot: two companies, four test numbers, free access and simulated payments, on the existing EC2. Maintenance interruptions are acceptable.
- Public repository: https://github.com/thehappieco/wappie
- Public site and documentation: `wappie.thehappie.co` and `/docs`.
- Administration: `console.wappie.thehappie.co`; messaging: `app.wappie.thehappie.co`; HTTP/WebSocket: `api.wappie.thehappie.co`.
- Joining a workspace does not grant archive access. Explicit device key grants unlock all stored history covered by the granted epochs. Revocation cannot erase already obtained keys or content.

The current personal/team signup, account profile and invitation lifecycle contracts are documented in [Accounts and workspaces](accounts-workspaces.md).

## Implemented server foundation

Migration 0021 adds `workspace_memberships`, copying each existing user's role to their original workspace. Identity IDs, password/recovery envelopes and device key grants remain unchanged. New identities receive their initial membership transactionally through a trigger.

The existing `users.tenant_id` and `user_logins.tenant_id` remain stable credential-routing UUIDs for compatibility. They no longer cascade with workspace deletion. They are not authorization for a workspace: membership supplies that role. Removing the original workspace therefore preserves the identity and access in other spaces. Service identities remain registered to their original workspace and cannot redeem human workspace invitations.

Login prefers the original workspace if its membership and workspace are active; otherwise it selects the earliest active membership, breaking ties by workspace UUID. An identity without an active workspace receives an identity-only session (NULL workspace in storage; zero UUID on the wire). It can recover its account, list workspaces and accept invitations, but cannot use device APIs or administer a workspace. Selecting a workspace requires an active membership.

### HTTP interface

All routes below require `Authorization: Bearer <session-token>`. An API key cannot use them. Existing login, signup, recovery and `/v1/auth/me` wire formats remain compatible.

| Method and path | Request | Response |
| --- | --- | --- |
| `GET /v1/auth/workspaces` | None | `{"workspaces":[{"id":"UUID","name":"Workspace","avatar":"","kind":"team","role":"member","status":"active","device_count":2,"created_at":"RFC3339"}]}` |
| `PUT /v1/auth/workspaces/current` | `{"name":"Support team","avatar":"data:image/jpeg;base64,..."}` | Updated workspace metadata. Owner/admin only; the session selects the workspace. |
| `POST /v1/auth/workspaces/accept-invite` | `{"invite":"one-time-code"}` | `{"tenant_id":"UUID"}` |
| `POST /v1/auth/workspaces/session` | `{"tenant_id":"UUID"}` | Existing login response: token, expiry and account with the selected workspace/role. |

Workspace profiles use names of 1–80 Unicode characters. `avatar` is an optional image represented as a data URL; send an empty string to remove it. The server accepts only PNG/JPEG, limits the decoded file to 32 KiB and each dimension to 512 pixels, and decodes/re-encodes the pixels to strip metadata and trailing payloads. It never fetches remote profile URLs. The browser crops JPG/PNG/WebP uploads locally to a compact square thumbnail. Profile changes serialize with membership changes and re-check the manager’s authority in the transaction. Invalid profiles return `400 invalid_workspace_profile`.

Workspace listing includes suspended spaces but excludes disabled memberships. Selecting a suspended space or one without membership returns `403 not_authorized`; malformed UUIDs return `400 bad_request`. Invalid, expired, consumed, service or duplicate-membership invitations return `403 invite_invalid`. A valid invitation addressed to another email returns `403 invite_email_mismatch` without consuming the code.

`device_count` is the number of devices visible to this identity in that workspace, using the same permissions as `devices.list`: owners/admins see all registered numbers; other roles see numbers they can manage or send from, or can read with the current archive key. Disconnected and unpaired registered numbers are included when visible. Suspended workspaces expose no available devices and return zero. The directory and its counts use one database snapshot, do not issue additional sessions, and do not change the selected workspace. This is an operational count for the workspace picker, independent of commercial licenses or storage. Older servers and create/update workspace responses may omit the field; clients must distinguish an unavailable count from zero.

Invite validation, membership insertion and consumption share one transaction. Rejected acceptance does not spend an otherwise valid invitation or promote an existing member. Accepting does not switch the current session or create device grants.

Selecting a workspace creates a new token with the source session's expiry; switching cannot extend the authentication lifetime. It does not mutate the previous token or move existing WebSockets between spaces. Clients must close their old connection, discard the old space's loaded data/keys, load `/v1/auth/me` with the new token and reconnect using that token. Other tabs may keep their own sessions in different spaces. End unused tokens through the existing logout endpoint; the SDK's `restoreSignIn` (`packages/client`) does so for a token it made and then could not use (the new token's `/me` failed, or answered for another account), and tells its caller of each token it makes as soon as the server answers (`minted`), so that a page that goes meanwhile can end it too. Selecting spends a budget of its own (`ratelimit.DefaultWorkspaceSessions`), not the sign-in one: 30 at once and 60 a minute per account, 60 at once and 120 a minute per address, then `429 rate_limited` with `Retry-After`. The socket the client then opens with the new token is bounded more tightly: every WebSocket hello spends the sign-in budget's address limit (20 at once and 60 a minute, shared with the sign-ins from that address), so one address connects to about 20 workspaces at once, then one a second, and a later hello is refused with `rate_limited` although its selection went through.

Password changes from any active workspace update the same identity and atomically revoke stored sessions across spaces.

## Phase 2: membership management and live revocation

The authenticated session selects the workspace for these routes. They accept no caller-supplied workspace override. API tokens cannot administer members.

| Method and path | Request | Response |
| --- | --- | --- |
| `GET /v1/auth/workspaces/members` | None | `{"members":[{"id":"UUID","email":"person@example.com","role":"member","status":"active","last_owner":false,"created_at":"RFC3339"}]}`; disabled memberships are included. No password or key envelopes are returned. |
| `PUT /v1/auth/workspaces/members/{userID}` | `{"role":"member","status":"disabled"}`; both fields required; `"strand_deleted":true` is [the strand override](#the-strand-override) | `204` |
| `DELETE /v1/auth/workspaces/members/{userID}` | None; `?strand_deleted=true` is [the strand override](#the-strand-override) | `204`; removes membership only, preserving the account and its other workspaces. |
| `POST /v1/auth/workspaces/invites` | `{"role":"member","email":"person@example.com"}`; email optional | `201 {"invite":"one-use-code","invitation":{...},"email_sent":false}`; expires in seven days. Configured mail delivery sets `email_sent:true`. |

Owners can manage all roles. Administrators can manage members and service accounts, but cannot modify administrators/owners or invite/promote somebody to those roles. Members and service accounts cannot manage memberships. Service accounts cannot be converted into people or vice versa.

The member directory marks the sole active owner with `last_owner:true`, allowing clients to disable role/status controls and explain how to add a backup. This is informational; the mutation endpoint independently enforces the invariant. At least one active owner must remain: attempting to demote, disable or remove the last owner returns `409 last_owner`. Changes serialize on the workspace row and re-read the actor's permissions within that transaction, including concurrent self-demotions and removals. Transfer ownership by first promoting another active person, then demoting the original owner.

Changing a role/status revokes that person's sessions in this workspace and expires their outstanding invitations here. Disabling additionally deletes all their device grants in the workspace and revokes tokens acting as that service account and tokens the person created, as a removal does: a token verifies by itself, and one with no acting identity would otherwise go on reading every number, a recovered one included. Migration 0050 revoked the tokens of people disabled before it, or no longer members, the same way. Re-enabling restores the membership only: previous sessions, tokens and grants remain revoked. Other workspaces are unaffected. No-op updates preserve existing sessions.

Removal uses the same role hierarchy and deletes the membership instead of leaving a disabled member. It revokes this workspace's sessions, tokens acting as the removed service identity, and tokens created by the departing person, including tokens without an acting identity. Pending invitations created by the departing person or addressed to their email in this workspace are revoked as well. Device permissions, sealed key grants and reader preferences in the workspace are deleted. The global account, password, passkeys, personal workspace and other memberships remain intact. A removed human needs a new invitation and new device grants to return; rejoining never revives old sessions or credentials. Removing a disabled member is supported. Personal workspaces allow removal of service identities but retain their sole human owner.

Removing a member who holds the last recoverable read key for any nonretired archive generation returns `409 last_device_reader` without changing access. Give another active member both read permission and the required key grants first; an owner's management role alone is insufficient. When every such number is deleted and not yet purged ([device lifecycle](devices.md#deletion-and-recovery)), removing or disabling that member returns `409 last_reader_of_deleted` instead: an owner gets `numbers`, each with `device_id`, `label`, `push_name`, `pn` and `purge_after`, and anyone else no `numbers` at all. Wait for the purge (at most 30 days), or recover the number and share its key first. These checks also serialize with disabling, grant revocation and permission changes. A missing or cross-workspace target returns `404 not_found`; an unauthorised role returns `403 not_authorized`; malformed IDs return `400 bad_request`.

Migration 0033 retains a workspace-scoped email snapshot for attribution of historical API tokens and key grants issued to surviving members. It does not grant access to the removed person's current global profile. New session issuance takes the same workspace lock and rechecks membership, so an already-running login cannot create a usable session after removal has revoked access.

Migration 0022 introduces a membership access revision, also advanced by grant deletion. WebSockets retain only authenticated session/key IDs and the revision, not raw tokens. Authorization is checked before dispatching commands and before writing queued frames: once per batch of at most 64 frames already queued, so a frame queued after access ends is never written, and a connection still being written to closes at its next batch. Local HTTP mutations wake idle sockets promptly; periodic checks every second cover other processes, direct database changes and expiration. Database check failures close the connection. Under normal database availability, idle invalid connections are detected at the next check; this is not a promise to recall bytes already sent or undo operations already in flight.

Logout, password change/recovery, membership changes, service disabling, API key revocation, grant removal and workspace suspension invalidate affected open connections. The connection closes with WebSocket code `1008`; clients must authenticate/reconnect as appropriate. Role changes intentionally require a new session rather than retaining cached privileges.

Members and service accounts see only currently granted devices in the device directory, history replay, live subscription and device-status notifications. Explicit subscription requests for ungranted devices are refused. Accounts with no grants cannot subscribe. Administrative roles do not implicitly grant conversation access.

### The strand override

An owner may remove or disable the last key holder of deleted numbers anyway, when the platform will tell the workspace's other owners (decision 0040; the owner's confirmation of 2026-10-14): `"strand_deleted": true` in the `PUT`'s body, or `?strand_deleted=true` on the `DELETE` (a value that is not a boolean is `400 bad_request`; `false` is no flag). In this order:

1. the sign-in's rate budget (`429 rate_limited`);
2. owners only, by the session's role (`403 owner_only` for anyone else, before any step-up prompt);
3. a recent sign-in (`403 step_up_required`);
4. under the workspace's lock, the live role again (`403 owner_only`), and the gate: the contract is on and the workspace is a team a platform document names, not closed ([the contract](contract.md#the-owners-acts)). Where the gate is closed, a self-hosted installation included, the flag changes nothing and the answer is `409 last_reader_of_deleted`, as without it. When the gate is open and the workspace stays locked by another change for over 2 seconds, `503 workspace_busy` with `Retry-After: 2`, and nothing changed.

The members list (`GET /v1/auth/workspaces/members`) says where the override applies, so a console can ask before the refusal. For an owner, a member whose removal or disable would strand only deleted numbers carries `last_key_holder_of_deleted`, those numbers with `device_id`, `label`, `push_name`, `pn` and `purge_after`, and every row carries `strand_override: true` while the gate above is open (read without a lock; the act checks it again). For an admin, such a member carries `last_key_holder_of_deleted_any: true` alone, and no row carries `strand_override`. A member who would strand a live number is not listed: that act is `409 last_device_reader` whatever the flag. An older server sends none of these fields, and a console then offers no override.

The act then goes on, and each deleted number it leaves with no key holder keeps its purge date, readable by nobody. For each, one `stranded` [event](item-events.md) (the owner as actor; `person`, the target's platform sub; `cause`, `revoked` for a removal or `disabled` for a disable; the readers just before the change, the target among them), which the platform mails the other owners, and a `number_stranded` notice for each other active owner, never the actor or the target, until the purge (a recovery clears its date). A live number's last key holder stays unremovable (`409 last_device_reader`).

### Person invitations into platform teams

In a team a platform document names, person invitations (owner, admin or member) are paused while Wappie observes the platform's members ([the contract](contract.md#person-invitations-into-platform-teams)): issuing one (`POST /v1/auth/workspaces/invites`, the console's invite form), regenerating one, accepting one (`POST /v1/auth/workspaces/accept-invite`, or an invited sign-up) and the operator's `whatserverd invite` are refused with `409 invitations_paused`, before anything is spent, so a pending code stays valid. Service invitations stay open. The record of the team is the key, in every mode: only the 0051 down-step reopens them.

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

`GET /v1/auth/workspaces/capacity` returns `{"max_devices":2,"used_devices":1}` to workspace managers. `max_devices:null` means no configured limit. A database trigger serializes new device creation against the workspace row and refuses creation at capacity. Self-hosted workspaces have no limit by default. All registered devices occupy a slot, including disconnected ones. Deleting a number frees its slot at once, for its 30 days as well; recovering it takes the slot back, and is refused with `capacity_reached` when none is free.

The hosted build selects a private subscription component. Simulated approvals and declines, idempotency records and capacity changes live in the separate commercial module. Only owners change subscriptions; admins can view them. No card data, prices, provider secrets or live charges are implemented or required for this pilot.

The console uses a fresh document when changing workspaces. Only the target workspace UUID is included in the URL; credentials, keys and messages are never transferred there. The person signs in again, and the server issues a session bound to the selected workspace. This intentionally discards pending work and all in-memory archive state before opening another workspace.

Legacy API key device allowlists remain restricted even when the last allowed device is removed. Migration 0026 stores that distinction explicitly and versions list changes so existing WebSockets close instead of retaining the earlier subscription scope. Prefer service accounts and the console's per-device permissions for new integrations.

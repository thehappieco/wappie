# Accounts, personal workspaces and teams

Both account verification and workspace invitation emails share a branded,
responsive HTML template with an embedded PNG logo, action button, expiry and
copyable code. Multipart plain text carries the same action and code. No remote
images or tracking are required. Every action uses the configured HTTPS
`WS_APP_URL` with secrets in the URL fragment; production never derives links
from request headers. Localhost, loopback and wildcard origins are rejected by
both configuration and the sender, including development when mail is enabled.
Hosted Wappie uses `https://app.wappie.thehappie.co`. Do not use a local development
origin for real recipient tests; old emails keep the links they originally contained.

Migration 0031 keeps every existing workspace as `team` and adds exactly one fresh `personal` workspace for each human identity. Existing numbers, subscriptions, memberships, credentials and key grants stay in place. An insertion trigger creates the personal workspace for new human accounts, including trusted bootstrap and invitation signup. Service identities receive no personal workspace. The sole personal owner cannot be replaced by another human or disabled.

`POST /v1/auth/workspaces` creates a team for the current identity from `{name, avatar?}` and returns the new workspace with `kind:"team"` and `role:"owner"`. It does not move any number or change the selected session. Workspace metadata now contains `kind:"personal"|"team"`.

`GET /v1/auth/profile` returns `{id,email,name,avatar}`. `PUT` accepts `{name,avatar}` and updates the global identity across every workspace. Account responses include `name` and `avatar`; member rows additionally contain `device_access`, with `device_id`, `label`, `pn`, `has_key`, `read`, `send` and `manage`. These are current-epoch key availability and effective action permissions, and contain no key envelopes.

`DELETE /v1/auth/workspaces/members/{userID}` removes only the selected workspace membership and returns `204`. Owners may remove any role; administrators may remove members and service identities. The last active owner and the last recoverable reader of any archive generation are protected (`409 last_owner` / `409 last_device_reader`). Disabled memberships may also be removed. Unlike disabling, removal disappears from the member directory and a human needs a fresh invitation to return.

Removal atomically revokes that workspace's sessions, device permissions, key grants, reader preferences, tokens created by the departing person or acting as the removed identity, and pending invitations issued by or addressed to that identity. The person's global account, personal workspace, other memberships and their credentials remain intact. Rejoining does not reactivate prior sessions, tokens or grants. Migration 0033 adds a tenant-isolated attribution snapshot for historical token creators and grant issuers without exposing the former member's current profile. Full role, response and live-connection behavior is documented in [Workspace membership management](workspaces.md#phase-2-membership-management-and-live-revocation).

Public signup is opt-in (`WS_PUBLIC_SIGNUP`) and requires a configured verification mail sender. `GET /v1/auth/signup/config` reports `{enabled,email_verification_required:true}`. `POST /v1/auth/signup/verification` accepts `{email}` and responds generically with `202 {sent:true}`, including existing addresses and cooldown attempts. Verification codes expire after 30 minutes; requests for one email are limited to one per minute in addition to the normal IP/account limits. Existing accounts receive no new signup code. Verification codes are hashed in the database and never returned by HTTP.

Human `POST /v1/auth/signup` adds optional `display_name` and `email_verification_token` to the existing client-derived credential fields. Public signup requires a valid email-bound token. An invitation can substitute for separate email verification, with exact normalised-email matching for addressed invitations; trusted legacy bootstrap codes remain supported. Signup, personal creation, optional team membership and token consumption share one transaction. A wrong email, duplicate account, malformed credential or failed insertion leaves a valid invitation usable. Invited signup selects its team; ordinary signup selects its personal workspace. The legacy `name` signup field remains reserved for service identities.

Workspace managers can list invitations with `GET /v1/auth/workspaces/invites`: `{invites:[{id,email,role,status,created_at,expires_at,completed_at,revoked_at,can_reveal}]}`. Status is `pending`, `expired`, `accepted` or `revoked`. Pending invitations appear alongside members in the console, but no membership or archive grant exists before acceptance. Creation returns `{invite,invitation,email_sent}`; configured email delivery is optional and a failed delivery preserves the code for manual sharing.

`POST /v1/auth/workspaces/invites/{id}/reveal` returns `{invite}` to authorised managers. `DELETE` revokes it. `POST .../{id}/regenerate` revokes the old code and returns a fresh invitation with seven-day validity. Administrators cannot reveal, revoke or regenerate invitations carrying owner/admin roles. Accepted invitations cannot be regenerated or revoked.

Code recovery uses AES-GCM with `WS_INVITE_ENCRYPTION_KEY_HEX`, a separate persistent 32-byte server key. Associated data binds ciphertext to its workspace and public invitation UUID. The database retains a SHA-256 digest for redemption. Without the configured key, new invitations still work but cannot be recovered after creation. Legacy digest-only invitations are listed with `can_reveal:false`; generating a replacement is the only way to obtain a code. The original code is never reconstructed from a digest.

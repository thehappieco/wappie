# Sign-in through an identity provider

An installation can let people sign in with an account at an external
identity provider instead of a Wappie password. The hosted cloud
(`app.wappie.thehappie.co`) uses The Happie Co's id. (`id.thehappie.co`). A
self-hosted installation leaves it off, and nothing about its accounts
changes.

The Go side lives in the public core and does nothing until
`WS_PLATFORM_ISSUER` is set. The page side (the `/auth/callback` page, account
setup and the link ceremony) is in the private console only.

This document covers steps 1 and 2 of the plan: the Go routes (shipped dark)
and the console in development. Step-ups for consents and grants (step 4),
the cutover (step 5) and the end of the rollback window (migration 0049,
step 6) come later.

## What the provider gives and what Wappie keeps

When a sign-in asks for it (`account_key` scope, key delivery), id. gives the
page `sk_p`, an X25519 key derived from the account's root for the product
`wappie` and an epoch: `product_key_id` is `wappie:<epoch>`. The page gets
`sk_p` sealed to itself alone. The server only ever sees `pk_p`, through
userinfo.

Wappie keeps its own account key: the random X25519 key every grant, the AI
keychain and the personal contacts are sealed to, and `users.public_key`. It
does not replace that key with `sk_p` (owner decision D2). Instead it stores
the account key once more, wrapped under a key derived from `sk_p`:

```
K_pw = HKDF-SHA256(IKM = sk_p, salt = UTF-8("wappie/platform-wrap/v1"),
                   info = JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id]), L = 32)
aad  = JCS(["wappie/platform-wrap", 1, user_id, sub, product_key_id, base64url(users.public_key)])
wrap = 0x01 || nonce (12) || AES-256-GCM(K_pw, nonce, account key (32), aad)       61 bytes
```

- The wrap is symmetric on purpose. Anyone holding `pk_p`, the server
  included, could make an HPKE seal to it and so plant an account key of their
  choosing. Only a holder of `sk_p` can make this wrap.
- The page self-tests every wrap it makes: it opens the wrap again and
  compares. On every open it also checks that the key's public half is
  `users.public_key`.
- The server checks only the length and the version byte.
- The reference implementations are in the private console:
  `commercial/platformwrap` (Go) and `commercial/web/platform/platformWrap.ts`
  (TypeScript). Both check the same golden vectors
  (`commercial/platformwrap/testdata/vectors.json`). Both move unchanged into
  the kit's Wappie profile (v0.4.0), as platform decision 0023 records.
- This layer is deliberately not in `packages/client`, whose bytes are part
  of the attested reader's image.

Below the wrap, the hierarchy is the one a password account has: grants, the
vault (`wappie-browser-session`), sealed archives. The account key reaches
the browser vault as it does after a password sign-in, through
`finishSession`.

## Identities

| | `users.id` | Credentials in Wappie |
|---|---|---|
| A new account created through id. | `sub` (id.'s UUIDv7) | None: no password, no recovery code, no Wappie passkeys |
| A linked legacy account | Unchanged: grants, foreign keys and AADs bind it | The legacy password and recovery wraps stay until the end of the rollback window (D4, 14 days after the cutover) |

- Everything is keyed by `sub`. An e-mail address never links, creates or
  merges anything.
- userinfo's address is the provider's current verified one at that sign-in.
  An account created through id. follows it (`users.email`). A linked legacy
  account keeps its `users.email`, because its legacy password wrap is bound
  to it; the link row records id.'s address.

## The tables (migration 0048)

| Table | What it holds |
|---|---|
| `platform_key_pins` | The first `product_key` seen for each `(sub, product_key_id)`. Insert only: a trigger refuses every update and delete. No foreign key, so the pin outlives the account. |
| `platform_identities` | The link `sub` ↔ `users.id`, one each way, with `linked_from` (`new` or `legacy`) and id.'s address. Only the address and when it changed may be updated. |
| `platform_wraps` | The 61-byte wrap per account and epoch. Insert only. |
| `platform_login_tickets` | What a sign-in with no session may do next. Stored as SHA-256, single use, five minutes, bound to the sub and the pinned key, at most five failed link attempts. |
| `security_events` | `platform_account_key_changed` and `platform_linked`. Never a token, a key or an address. |

Other changes:

- `users.auth_source` is `local` or `platform`.
- `users_credentials_by_source` replaces 0020's `users_service_has_no_password`.
  It allows: a service with no password; a local person with all of the
  password columns; a platform person with either all of them (linked, in the
  window) or none.
- `sessions.step_up_at` and `step_up_not_before` are added for step 4 and are
  not used yet.
- None of the new tables carries row-level security. Each is read before a
  workspace is known, as `sessions` and `user_logins` are, and none holds a
  secret.

The migration header holds the down-step, checksum-gated against
`migration48_sha256` in the release's `RELEASE.json`.

- It refuses while any account created through the provider exists, because
  such an account has no password to fall back to. Delete those accounts
  explicitly first.
- A linked account becomes local again, with its old password.
- It runs before the down-steps of 0047 (the fewer steps) and earlier.

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `WS_PLATFORM_ISSUER` | The provider's origin, exactly as its ID tokens name it: `https://id.thehappie.co`, or `http://id.thehappie.localhost:8290` in development | empty: off |
| `WS_PLATFORM_CLIENT_ID` | This installation's client at the provider (`wappie-app`) | required with the issuer |
| `WS_PLATFORM_APP_ORIGIN` | The one page origin allowed to post a sign-in | the origin of `WS_APP_URL` |
| `WS_PLATFORM_ID_ADDR` | Development only: the `host:port` the userinfo request dials, because Go does not resolve `*.localhost`. The request's Host still names the issuer. | empty |
| `WS_LOCAL_LOGIN` | `on`, `link_only` or `off` | `on` |
| `WS_SECURITY_ALERT_EMAIL` | The operator's address for the account-key alert (needs mail) | empty |

Validation:

- In prod, the issuer and the page origin must be https, and
  `WS_PLATFORM_ID_ADDR` is refused.
- `link_only` and `off` are refused without an issuer.
- The startup line says `platform_login=on|off` and `local_login=…`.

What `WS_LOCAL_LOGIN` leaves open:

| Route | `on` | `link_only` | `off` |
|---|---|---|---|
| `/challenge`, `/recover/open` | yes | yes (the link needs a salt) | `local_login_disabled` |
| `/login`, `/signup` (a person), `/signup/verification`, `/recover/finish`, `/password`, `/recovery`, `/rewrap`, every `/passkeys` route | yes | `local_login_disabled` | `local_login_disabled` |
| `/signup` for a service (an invitation and a name) | yes | yes | yes: content consents register their service this way |
| `/platform/link/prepare`, `/platform/link` | yes | yes | `local_login_disabled` |

`/passkeys/config` and `/signup/config` answer "disabled" unless local login
is `on`.

## Routes

Every `/v1/auth/platform/*` route answers `403 platform_login_disabled` while
the issuer is unset. Before the body is read, each route applies kit
`oidcrp`'s session-handler rules:

- `POST` only;
- exactly one `Origin`, equal to `WS_PLATFORM_APP_ORIGIN`;
- exactly `Sec-Fetch-Site: same-origin`;
- `Content-Type: application/json`.

Without these rules, another site could post an access token of its own
account from the person's browser (a no-cors `text/plain` POST needs no
preflight) and sign that browser into its account. Bodies are at most 4 KiB,
with no unknown member. Answers are `Cache-Control: no-store`.

### `POST /v1/auth/platform/session {access_token}`

1. kit `oidcrp.Client.Login`:
   - the strict token shape;
   - one `GET {issuer}/oauth2/userinfo`, with no proxy, no redirect and no
     cookie;
   - `client_id` must be `wappie-app`;
   - `product_key_id` must be `wappie:<epoch>` with a valid key;
   - the insert-only pin (`store.PlatformPins`).
2. Then, by what Wappie knows of the sub:

| Answer | When |
|---|---|
| `200 {kind:"session", token, expires_at, user, pin, platform_wrap}` | A linked, active account with a wrap for this epoch |
| `200 {kind:"rewrap_required", ticket, pin, user_id, public_key}` | Linked, but no wrap for this epoch (a future key reset at id.) |
| `200 {kind:"link_required", ticket, pin, email}` | Not linked, and an unlinked active password account has id.'s address. This is a hint shown only to the verified owner of that address, never a link. |
| `200 {kind:"new", ticket, pin, email, name}` | Otherwise |

`pin` is the kit's `{sub, product_key_id, product_key}` (base64url). The page
keeps `sk_p` only once that triple names it (`keepProductKey`). Other binary
fields are standard base64, as in every auth reply.

Refusals:

- `401 token_refused`: userinfo answered 401. The token works once and is
  never retried.
- `403 wrong_client`.
- `502 userinfo`: any other userinfo failure, or no verified address.
- `400 bad_request`: not an access token. Nothing is sent to id.
- `403 account_disabled`.
- `409 account_key_changed {product_key_id}`: the key differs from the pin.
  No session is started and the pin is kept. The alert (O1) is:
  - a `security_events` row;
  - an Error log line with `event=platform_account_key_changed` and the
    product key id only;
  - a mail to `WS_SECURITY_ALERT_EMAIL` and to the account's address.

### `POST /v1/auth/platform/account {ticket, public_key, platform_wrap, display_name?}`

For a `new` ticket. One transaction:

- spends the ticket;
- inserts the account (`users.id = sub`, `auth_source = 'platform'`, no
  password columns). The insertion trigger creates its personal workspace,
  as it does for every person (D6, until the platform's workspaces);
- inserts the link and the wrap;
- records `platform_linked {from: "new"}`.

It then answers `kind: "session"`. Possible refusals: `401 ticket_invalid`,
`409 email_taken`, `409 already_linked`, `400 bad_request`.

### `POST /v1/auth/platform/link/prepare {ticket, email, auth_key | recovery_proof}`

For a `new` or `link_required` ticket. It checks the legacy proof exactly as a
password sign-in does. It then hands back what the browser opens the account
key with: `{user_id, public_key, wrapped_usk}` for the password, or
`{user_id, public_key, recovery_wrap}` for the recovery code.

Nothing is spent. A wrong proof costs one of the ticket's five attempts, on
top of the address and account rate limits.

The wrap is handed back only against the proof, never to a ticket alone, so
an id. account cannot fetch somebody's legacy wrap to attack offline.

### `POST /v1/auth/platform/link {ticket, email, auth_key | recovery_proof, platform_wrap}`

One transaction, under the account's lock. It:

1. spends the ticket;
2. checks again that the account is active, a person, local and unlinked, and
   that the hash the proof was checked against is unchanged;
3. inserts the link and the wrap and sets `auth_source = 'platform'`;
4. revokes every session and every Wappie passkey of the account;
5. records `platform_linked {from: "legacy" | "legacy_recovery"}`.

It then answers `kind: "session"`. Two id. accounts racing for one Wappie
account: one links and the other gets `409 already_linked`.

### `POST /v1/auth/platform/rewrap {ticket, platform_wrap}` (with a bearer session)

Stores a linked account's wrap for a new epoch. It needs the `rewrap_required`
ticket and the session of the same account, because only a browser that
still holds the account key can make the wrap.

The console does not offer this step yet. A `rewrap_required` sign-in shows
an error and keeps nothing.

### Discovery and headers

When the provider is configured:

- `/.well-known/wappie` and `/v1/discovery` advertise
  `platform_login: {issuer, client_id, product, local_login}` and the
  capability `auth.platform.v1`. `auth.password` is dropped only when local
  login is `off`.
- The console document gets the issuer in `connect-src`.
- Every document gets `Referrer-Policy: strict-origin` (O2), so the callback's
  `?code` never rides in a `Referer`, not even to this origin's own assets.
  This still sends the `Origin` that the MCP consent post needs, unlike
  `no-referrer`. The cloud build's `index.html` carries the same policy in its
  meta tag.

In development, `browserorigin` treats `*.localhost` names (RFC 6761) as
loopback. This lets `http://app.wappie.thehappie.localhost:5173` reach the
API through the Vite proxy. Production never allows cleartext.

Go logs no request URL. In the cloud, nginx's `location = /auth/callback` has
`access_log off` (`commercial/deploy/nginx-https.conf`).

## The page (private console)

All of it is behind the cloud build's aliases: `@signin` and `@platform`, in
`commercial/web/vite.config.ts`. A console built without `WAPPIE_CLOUD_BUILD=1`
contains no OpenID Connect code.

It uses `@thehappieco/kit/oidc-rp` v0.3.0 (`begin`, `finishSignIn`,
`keepProductKey`, `logoutURL`), in `commercial/web/platform/`:

1. **Sign-in screen.** "Sign in with The Happie Co", and "I already have a
   Wappie account" unless local login is `off`. Sign-up, recovery and Wappie
   passkeys are hidden while the switch is on. The password form stays only
   while local login is `on`, with a banner asking to link. The return path
   (path and query, so pending assistant and message links survive) rides in
   the flow. A workspace invitation never does: it waits in `sessionStorage`
   and is accepted after the sign-in.
2. **`/auth/callback`** (`App.vue`'s restore is skipped):
   - the kit drops the query and completes the flow;
   - the access token goes to `/platform/session`;
   - `sk_p` is kept only after the server's pin names it;
   - then: `session` opens the wrap and signs in; `new` offers account setup
     (the account key is generated in the browser, wrapped, self-tested, and
     only the wrap and the public key are uploaded); `link_required` (or the
     person's choice) offers the link ceremony;
   - finally the return path goes back in the address bar before the console
     starts.
3. **The link ceremony.** The person types the old e-mail and password, or the
   recovery code:
   - the browser derives the keys as a password sign-in does;
   - the server checks the auth key or proof and hands back the legacy wrap;
   - the browser opens the account key, checks it against the account's
     public key, wraps it under `sk_p` and sends the link;
   - Go never sees a plaintext key or the password.
4. **Zeroing.** `sk_p` is held for at most the ticket's five minutes and
   zeroed when it is used, on expiry and on every refusal. The account key is
   zeroed once the session has imported it.
5. **Account screen.** While the switch is on, it shows "Manage your The Happie
   Co account" and "Sign out of The Happie Co too" in place of the password,
   recovery and passkey sections, plus "Link to The Happie Co" for an account
   that still signs in with a password. An explicit sign-out also deletes the
   kit's `thehappie-rp` flow store.

## Development

1. The platform's development stack serves id. at
   `http://id.thehappie.localhost:8290`. Its development registry has
   `wappie-app` at `http://app.wappie.thehappie.localhost:5173`, with
   redirect `/auth/callback`, post-logout `/`, product `wappie`, key delivery,
   and scopes `openid email profile account_key`. id. sign-in is
   password-only for now.
2. Run whatserverd with:

   ```dotenv
   WS_HTTP_ADDR=:8090
   WS_BROWSER_ORIGINS=http://app.wappie.thehappie.localhost:5173
   WS_PLATFORM_ISSUER=http://id.thehappie.localhost:8290
   WS_PLATFORM_CLIENT_ID=wappie-app
   WS_PLATFORM_APP_ORIGIN=http://app.wappie.thehappie.localhost:5173
   WS_PLATFORM_ID_ADDR=127.0.0.1:8290
   WS_LOCAL_LOGIN=on
   ```

3. Run the console with the cloud aliases:
   `WAPPIE_CLOUD_BUILD=1 npm --prefix commercial/web run dev`, then open
   `http://app.wappie.thehappie.localhost:5173`.
   - The dev server adds the issuer to the meta policy's `connect-src`. Set
     `WAPPIE_DEV_PLATFORM_ISSUER` for another one.
   - The Vite proxy keeps `Host`, which is why `*.localhost` is a development
     loopback origin.

## Rollback

| Level | What | Effect |
|---|---|---|
| Switch | Unset `WS_PLATFORM_ISSUER`, set `WS_LOCAL_LOGIN=on`, restart | Password sign-in is back for unlinked and linked accounts. Accounts created through id. cannot sign in until the switch returns. |
| Release | A release that knows version 48 | As in `deployment.md` |
| Schema | 0048's down-step | Refused while accounts created through id. exist |

## Not yet

- **Step-ups (step 4).** A consent, a grant or an AI integration still asks
  for the Wappie password (`withDeviceKeys`). An account created through id.
  has no password, so it cannot give those consents yet.
- **The cutover (step 5) and the end of the window (step 6).** Migration 0049
  will null the legacy credentials of linked accounts and delete their
  passkeys, with no down-step.
- **The rewrap of a new epoch in the console.**
- **Wappie's export.** It will carry the platform wrap (decision 0015, 0023).

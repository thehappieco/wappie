# Sign-in through an identity provider

An installation can let people sign in with an account at an external
identity provider instead of a Wappie password. The hosted cloud
(`app.wappie.thehappie.co`) uses The Happie Co's id. (`id.thehappie.co`). A
self-hosted installation leaves it off, and nothing about its accounts
changes.

The Go side lives in the public core and does nothing until
`WS_PLATFORM_ISSUER` is set. The page side (the `/auth/callback` page, account
setup and the link ceremony) is in the private console only.

This document covers steps 1, 2 and 4 of the plan: the Go routes (shipped
dark), the console in development, and the step-up of an account that signs
in through id. (step 4, owner decision D3). The cutover (step 5) and the end
of the rollback window (migration 0049, step 6) come later.

**Not in the pilot before step 4 is deployed.** The owner decided on
2026-10-05 that the platform sign-in is not switched on in the pilot
(`WS_PLATFORM_ISSUER`) before step 4 exists, and on 2026-10-06 (Decision 8
of step 4) that it is switched on, both doors open (`WS_LOCAL_LOGIN=on`),
only once step 4 is deployed with the switch off and an end-to-end test
against the production id. passes on the owner's account in Chromium,
Firefox and Safari, and the platform's session has been told (platform
decision 0030).

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
wrap = 0x03 || nonce (12) || AES-256-GCM(K_pw, nonce, account key (32), aad)       61 bytes
```

- The wrap is symmetric on purpose. Anyone holding `pk_p`, the server
  included, could make an HPKE seal to it and so plant an account key of their
  choosing. Only a holder of `sk_p` can make this wrap.
- The page self-tests every wrap it makes: it opens the wrap again and
  compares. On every open it also checks that the key's public half is
  `users.public_key`.
- The header is `0x03` (kit SPEC section 6.8). Wappie's other 61-byte
  envelopes of the account key start with `0x01` (the passkey envelope) and
  `0x02` (the password and recovery wraps), so a blob in the wrong column
  fails at its header. The header is in neither the HKDF input nor the AAD.
- The server checks only the length and the header byte
  (`internal/store` calls the kit's `wappie.CheckPlatformWrapShape`;
  0048's CHECK on `platform_wraps.wrap` is the same rule).
- The implementation is the kit's Wappie profile since v0.5.0
  (`github.com/thehappieco/kit/profiles/wappie` in Go,
  `@thehappieco/kit/profiles/wappie` in TypeScript), taken from the private
  console's, as platform decision 0023 records, with its vectors under the
  kit's `vectors/wappie/`. The console seals and opens through it.
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
  to it; the link row records id.'s address, and an invitation addressed to
  that address is accepted too.

## The tables (migration 0048)

| Table | What it holds |
|---|---|
| `platform_key_pins` | The first `product_key` seen for each `(sub, product_key_id)`. Insert only: a row trigger refuses every update and delete, and a statement trigger refuses `TRUNCATE`. No foreign key, so the pin outlives the account. |
| `platform_identities` | The link `sub` ↔ `users.id`, one each way, with `linked_from` (`new` or `legacy`) and id.'s address. Only the address and when it changed may be updated; `TRUNCATE` is refused. |
| `platform_wraps` | The 61-byte wrap per account and epoch. Insert only, `TRUNCATE` included. |
| `platform_login_tickets` | What a sign-in with no session may do next. Stored as SHA-256, single use, five minutes, bound to the sub and the pinned key, at most five failed link attempts. |
| `security_events` | `platform_account_key_changed` and `platform_linked`. Never a token, a key or an address. Insert only, `TRUNCATE` included. |

Other changes:

- `users.auth_source` is `local` or `platform`.
- `users_credentials_by_source` replaces 0020's `users_service_has_no_password`.
  It allows: a service with no password; a local person with all of the
  password columns; a platform person with either all of them (linked, in the
  window) or none.
- `sessions.step_up_not_before` is when the session last started a step-up
  at id. (see "Step-ups"). The proof itself is 0047's
  `sessions.authenticated_at`, so 0048 adds no second record of it.
- `sessions.via_provider` marks a session started through id.
  (`/platform/session`, `/platform/account`, `/platform/link`) or switched
  from one. Such a session is never handed the legacy password wrap (see
  "The rollback window"), and the down-step signs it out. A step-up
  overwrites `authenticated_at`, so `-infinity` could not serve as that
  mark.
- `platform_login_tickets.auth_time` is id.'s `auth_time` in the userinfo
  the ticket was issued on, so a new account's first session starts with
  the same proof as any sign-in through id.
- 0048 was amended in place for step 4 (Decision 9) before it was deployed
  anywhere: `via_provider`, the ticket's `auth_time` and the down-step's
  sign-out changed the file, and so `migration48_sha256`. A development
  database that applied the earlier text stops at boot with a checksum
  mismatch; recreate it.
- None of the new tables carries row-level security. Each is read before a
  workspace is known, as `sessions` and `user_logins` are, and none holds a
  secret.
- "Insert only" holds against the application's own statements, not against
  SQL run as the owner. The API's role runs the migrations and so owns these
  tables; a session with its credentials can still
  `ALTER TABLE … DISABLE TRIGGER` and then delete a pin, and the next sign-in
  would then pin whatever key id. presents. Moving the pins to a role that
  may only `SELECT` and `INSERT`, as kit `oidcrp` describes, needs a second
  database role in the deployment and is not done yet.

The migration header holds the down-step, checksum-gated against
`migration48_sha256` in the release's `RELEASE.json`.

- It refuses while any account created through the provider exists, because
  such an account has no password to fall back to. Delete those accounts
  explicitly first.
- A linked account becomes local again, with its old password.
- Every session started through the provider (`via_provider`) is signed
  out, even one a step-up at id. has since given a proof: it came through a
  provider the older binary does not know, and one with no proof holds
  `authenticated_at = -infinity`, which the older binary cannot read (any
  such session goes too). The person signs in again with the old password.
- It runs before the down-steps of 0047 (the fewer steps) and earlier.
  0047's refuses while version 48 is still in the ledger.

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
| `/challenge` | yes | yes (the link needs a salt) | `local_login_disabled` |
| `/login`, `/signup` (a person), `/signup/verification`, `/recover/open`, `/recover/finish`, `/password`, `/recovery`, `/rewrap`, every `/passkeys` route | yes | `local_login_disabled` | `local_login_disabled` |
| `/signup` for a service (an invitation and a name) | yes | yes | yes: content consents register their service this way |
| `/platform/link/prepare`, `/platform/link` | yes | yes | `local_login_disabled` |
| `/step-up/passkey/options`, `/step-up/passkey`, `/step-up/password` | yes | `local_login_disabled` | `local_login_disabled` |
| `/platform/step-up/start`, `/platform/step-up/finish` | yes | yes | yes |

A platform account gets `409 step_up_at_provider` from the three `/step-up`
routes instead, in every mode, while the provider is configured (which
`link_only` and `off` require). The two passkey ones answer `404
passkeys_disabled` first once `WS_PASSKEY_*` is unset. `GET /step-up` stays
open: the console reads from it what to ask for.

`/passkeys/config` and `/signup/config` answer "disabled" unless local login
is `on`. The link ceremony proves a recovery code at `/platform/link/prepare`,
behind its ticket, so `link_only` does not keep `/recover/open`.

With `off`, the verified owner of an unlinked password account's address has
no step left: the link routes are closed, and a new account cannot take an
address another account holds. `/platform/session` answers
`403 legacy_account_unlinked`, with no ticket, and the console explains it.
The operator's procedure: set `WS_LOCAL_LOGIN=link_only` while the person
links ("I already have a Wappie account" on the sign-in screen), then back to
`off`.

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
fields are standard base64, as in every auth reply. `user.wrapped_usk` is
always empty in a platform answer (see "The rollback window").

The session is `via_provider`, and its step-up proof is userinfo's
`auth_time` (owner Decision 2 of step 4), never later than now on the
database's clock and never the session's creation: the console asks id.
for `prompt=login`, so a fresh sign-in asks nothing more for ten minutes,
while one id. answered from an old session of its own proves only what its
`auth_time` says. A userinfo with no `auth_time` gives no proof
(`-infinity`).

Refusals:

- `401 token_refused`: userinfo answered 401. The token works once and is
  never retried.
- `403 wrong_client`.
- `502 userinfo`: any other userinfo failure, or no verified address.
- `400 bad_request`: not an access token. Nothing is sent to id.
- `403 account_disabled`, with no session.
- `403 legacy_account_unlinked`: with local login `off`, an unlinked password
  account has id.'s address (see Configuration).
- `409 account_key_changed {product_key_id}`: the key differs from the pin.
  No session is started and the pin is kept. The alert (O1) is:
  - a `security_events` row;
  - an Error log line with `event=platform_account_key_changed` and the
    product key id only;
  - a mail to `WS_SECURITY_ALERT_EMAIL`, in English, and to the account's
    address, in the account's language (`users.locale`: en, pt, es, fr or
    de; English when it never said one). Its advice is the callback page's,
    word for word: change the The Happie Co password now and contact Wappie
    support before signing in again.

### `POST /v1/auth/platform/account {ticket, public_key, platform_wrap, display_name?}`

For a `new` ticket. One transaction:

- spends the ticket;
- inserts the account (`users.id = sub`, `auth_source = 'platform'`, no
  password columns). The insertion trigger creates its personal workspace,
  as it does for every person (D6, until the platform's workspaces);
- inserts the link and the wrap;
- records `platform_linked {from: "new"}`.

It then answers `kind: "session"`, whose proof is the ticket's `auth_time`,
as at `/platform/session`. Possible refusals: `401 ticket_invalid`,
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

It then answers `kind: "session"`, whose proof is now: the link proved the
old password (or the recovery code) in the same request, as a password
sign-in does. Two id. accounts racing for one Wappie account: one links and
the other gets `409 already_linked`.

### `POST /v1/auth/platform/rewrap {ticket, platform_wrap}` (with a bearer session)

Stores a linked account's wrap for a new epoch. It needs the `rewrap_required`
ticket and the session of the same account, because only a browser that
still holds the account key can make the wrap.

The console does not offer this step yet. A `rewrap_required` sign-in shows
an error and keeps nothing.

### `POST /v1/auth/platform/step-up/start {}` (with a bearer session)

Starts a step-up at id. for the session (see "Step-ups"):

- the account must sign in through id. (`auth_source` `platform`):
  otherwise `409 step_up_here`, since a local account steps up here, with a
  passkey or the password;
- it sets `sessions.step_up_not_before` to now, on the database's clock. A
  newer start replaces an older one, which then proves nothing;
- it answers `200 {login_hint, window_seconds}`: id.'s address in the
  account's link (for a linked account it may differ from the Wappie
  address), which the console passes to `begin` as `loginHint` and names in
  C-STEP-22, and `600`, how long the start waits for its finish.

An account starts at most five in ten minutes, across its sessions, beside
the address limit: `429 rate_limited` with `Retry-After`. Also `401
unauthorized` and `500 internal`.

### `POST /v1/auth/platform/step-up/finish {access_token}` (with a bearer session)

Before anything leaves this server:

- `409 step_up_here` for a local account;
- `400 bad_request` for a string that is not an access token;
- `409 step_up_not_started` when no live session of the session's family
  has a start younger than ten minutes: never started, already used,
  replaced, or too old. The family is the browser sign-in the session was
  derived from and every session derived from it (`sessions.family_id`, the
  set a sign-out ends): the console's window holds only the sign-in's token,
  while the page that started works in a session a workspace switch made
  from it. A session of another sign-in, even of the same account, finds no
  start, and nothing is sent to id.

Then one `GET {issuer}/oauth2/userinfo` (kit `oidcrp.FetchUserinfo`), never
repeated, and in this order:

| Refusal | When |
|---|---|
| `401 token_refused` | userinfo answered 401 |
| `403 wrong_client` | the token is another client's |
| `502 userinfo` | any other userinfo failure, or no product key |
| `403 step_up_other_account` | the `sub` is not the one linked to the account: the person confirmed with another id. account |
| `403 account_disabled` | the account was disabled meanwhile |
| `409 account_key_changed {product_key_id}` | the product key differs from the pin of its epoch, or no sign-in here pinned that epoch (Decision 4). The pin is read, never made or replaced. The alert is the sign-in's (a `security_events` row with `step: "step_up"`, and `pin: "missing"` for an unpinned epoch; the Error line `event=platform_account_key_changed`; mail to `WS_SECURITY_ALERT_EMAIL` and to the account in its language, with the words E-ALERT-10 to 14). No proof is recorded and the session stays. |
| `403 step_up_stale` | userinfo's `auth_time` is more than a minute before the start, or absent: id. did not ask for the password or a passkey again (Decision 3) |
| `409 step_up_not_started` | the start was used or replaced meanwhile |

Otherwise one statement records the proof, `authenticated_at = now()` on the
database's clock, on the session that started and on the one that finished,
and clears the start, against the value read before the call: the start is
still that one, the family's newest, younger than ten minutes, and the
`auth_time` is not more than a minute before it. Every session the sign-in
derives later copies the proof, as a workspace switch does. So one start
makes one proof: a second finish from any session of the family, two
windows racing, or the finish of a replaced start records nothing. The log says `step-up confirmed method=provider`, and
the answer is `GET /v1/auth/step-up`'s: `200 {fresh, remaining_seconds,
window_seconds, passkey: false, provider: true}`. No refusal clears the
start; a new start replaces it.

The `auth_time` is id.'s clock, the proof always this database's. The minute
allows for the two clocks behind the start and nothing ahead of it: a proof
is never dated later than now.

### Discovery and headers

When the provider is configured:

- `/.well-known/wappie` and `/v1/discovery` advertise
  `platform_login: {issuer, client_id, product, local_login}` and the
  capabilities `auth.platform.v1` and `auth.platform.stepup.v1` (the two
  step-up routes). `auth.password` is dropped only when local login is
  `off`.
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
contains no OpenID Connect code and none of its texts.

It uses the kit v0.5.0's `@thehappieco/kit/oidc-rp` (`begin`, `finishSignIn`,
`keepProductKey`, `logoutURL`) and `@thehappieco/kit/profiles/wappie`
(`sealPlatformWrap`, `openPlatformWrap`), in `commercial/web/platform/`:

1. **Sign-in screen.** "Sign in with The Happie Co", and "I already have a
   Wappie account" unless local login is `off`. Sign-up, recovery and Wappie
   passkeys are hidden while the switch is on. The password form stays only
   while local login is `on`, with a banner asking to link. The return path
   (path and query, so pending assistant and message links survive) rides in
   the flow. A workspace invitation never does: it waits in `sessionStorage`
   and is accepted after the sign-in.
2. **`/auth/callback`** (`App.vue`'s restore is skipped):
   - the page drops the query from the address bar as it loads, before
     discovery or anything else can wait or fail, and the kit completes the
     flow from the address it took;
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

## Step-ups

One step-up serves every account: the fewer steps' `internal/stepup`
(`docs/mcp-enclave.md` §19.35). A content consent, its renewal, an AI
integration and its renewal, the provisional service invitation they write
and every grant of a number's key need a proof of the person within the last
ten minutes, recorded in `sessions.authenticated_at` on the database's clock
and checked by the server. What differs by account is how its session earns
that proof, never what a guarded write asks.

| Account | Its proof |
|---|---|
| `auth_source` `local` | The sign-in that started the session's family, then a Wappie passkey (WebAuthn, user verification) or the password, checked by this server. |
| `auth_source` `platform`, provider configured | The sign-in through id., from its userinfo's `auth_time`; then a re-authentication at id. with `prompt=login` (owner decision D3, step 4). Wappie runs no WebAuthn for these accounts (platform decision 0008) and takes no password from them. A link proves the old password, so its session's proof is now. |
| `auth_source` `platform`, provider unset (a rollback) | As a local account: a linked account signs in and steps up with its legacy password, and may add a Wappie passkey. An account created through id. cannot sign in. |

**The step-up at id. (step 4).** Nothing that asks for a proof changes;
only how a platform session earns one (the routes are under "Routes"):

1. The console's step-up field, in `provider` mode, says that the account
   confirms at The Happie Co, in a new window, and that the password goes
   only on id.'s host (C-STEP-14 and 15). On submit it opens the window
   before any `await` (a later `window.open` is blocked).
2. `POST /v1/auth/platform/step-up/start` sets `sessions.step_up_not_before`
   to now and answers the `login_hint`.
3. The window goes to id. with `prompt=login`, `login_hint` and no key
   delivery (kit `begin` with `wantKey: false`); id. asks for the password
   or a passkey there and comes back to `/auth/callback` in the window.
4. The callback, in its step-up branch, completes the flow with the kit's
   `callback` (refusing and zeroing a product key if one came) and posts the
   access token to `POST /v1/auth/platform/step-up/finish` with the bearer
   token of the browser's sign-in, the only one the window can read (from
   the browser's vault, without opening the account key). The page that
   started works in a session a workspace switch derived from that sign-in:
   the two are one family (`sessions.family_id`), and the finish answers the
   family's newest start. The server takes the access token to id.'s
   userinfo, never the ID token, and records the proof (`authenticated_at =
   now()`) against that start, on both sessions. The window tells the page through a `BroadcastChannel`, since the
   two documents' `Cross-Origin-Opener-Policy: same-origin` cuts the
   opener link, and closes.
5. The page re-reads `GET /v1/auth/step-up` and goes on as after a passkey.
   With the window blocked, the same steps run in the tab itself (Decision
   1).

The rules (owner Decisions 2 to 4 of step 4, approved 2026-10-06):

- **A sign-in through id. is a proof** from its userinfo's `auth_time`,
  never from the session's creation, and never later than now; the console's
  sign-in asks for `prompt=login`. A new account's first session takes the
  `auth_time` its ticket was issued on.
- **The clocks.** An `auth_time` up to a minute before the start counts;
  nothing ahead of the start is needed or credited, since the proof is
  recorded at now on this database's clock. The finish must come within ten
  minutes of the start.
- **One start, one proof.** The finish records the proof and clears the
  start in one statement, against the value it read before calling id.; a
  newer start voids an older one, and two windows or tabs make one proof.
  The start and the finish may be different sessions of one family (one
  browser sign-in and what it derived), never of two: a confirmation made
  in another browser, or after another sign-in, proves nothing here. Two
  tabs of the family that start one after the other share the newer start,
  whichever window finishes it.
- **The account key.** The finish compares userinfo's product key with the
  pin of its epoch and never pins one: another key, or an epoch no sign-in
  pinned, is `account_key_changed`, with the alert, and no proof.

Also, for such an account:

- `GET /v1/auth/step-up` answers `provider: true` (and `passkey: false`);
- `POST /v1/auth/step-up/passkey/options`, `/step-up/passkey` and
  `/step-up/password` answer `409 step_up_at_provider`, whose message names
  the start route;
- `POST /v1/auth/passkeys/register/options` answers `409
  passkeys_at_provider`, so no Wappie passkey replaces the ones the link
  revoked;
- a workspace switch copies the session's proof and `via_provider`, never a
  pending start (a finish from either session answers the family's newest
  start, above).

A linked account that signs in with its legacy password while
`WS_LOCAL_LOGIN=on` (both doors) has that sign-in as its proof for ten
minutes, as any password sign-in does; its step-ups after that are id.'s,
from that session too. Once `WS_LOCAL_LOGIN` narrows the password routes,
the passkey and password step-ups close with them: `403
local_login_disabled` for a local account, while a platform account still
gets `409 step_up_at_provider` first (the route table under
"Configuration"). The step-up at id. stays open in every mode.

## The rollback window

A linked account keeps its legacy password columns (`auth_hash`, `kdf_salt`,
`wrapped_usk`, the recovery pair) until migration 0049 at the end of the
window (step 6).

- Steps 1 to 3 accepted one consequence of that, which step 4 closes:
  `/v1/auth/me` handed a linked account's `wrapped_usk`, its key under the
  old password, to any session of the account, including one started at
  `/platform/session`. Anybody who could obtain an id. access token for the
  sub, without `sk_p`, could fetch that wrap and attack the old password
  offline: a compromised id., the case the pin is there for, or someone who
  intercepted a token before the page used it.
- Since step 4, `/v1/auth/me` answers `wrapped_usk` empty to a session that
  came through the provider (`via_provider`: `/platform/session`,
  `/platform/account`, `/platform/link`, and every workspace switch made
  from one), before and after a step-up, and so does the workspace switch's
  own answer. The platform answers themselves (`session`, `account`,
  `link`) never carried it, and an account created through id. has no such
  wrap.
- A session of the same linked account that signed in with the old password
  (both doors) still gets it, since it proved the password: the paths that
  still open the account key with the password (`withDeviceKeys` for a
  session without an account key of its own, and the password, recovery
  and passkey changes) read it from `/v1/auth/me`, and they live in
  `packages/client`, part of the attested reader's image, which step 4 does
  not change. Consents, renewals, AI integrations and, in the console,
  Members' grants seal with the session's account key after a step-up.
- 0049 ends the window in any case. Until then, link an account only once
  its old password is a strong one: change a weak one before linking.

## Rollback

| Level | What | Effect |
|---|---|---|
| Switch | Unset `WS_PLATFORM_ISSUER`, set `WS_LOCAL_LOGIN=on`, restart | Password sign-in is back for unlinked and linked accounts. Accounts created through id. cannot sign in until the switch returns. |
| Release | A release that knows version 48 | As in `deployment.md` |
| Schema | 0048's down-step, before 0047's and every older one | Refused while accounts created through id. exist; signs out every session started through the provider (`via_provider`), confirmed at id. or not |

## The texts (approved 2026-10-05)

The owner approved every text of this branch and of the fewer steps that the
list of 2026-10-05 collected (codes C- for the console, E- for the Go server),
with thirteen recommendations; `docs/mcp-enclave.md` §19.35 lists all of
them. Those that change this branch's texts:

- **"a Wappie" and "o Wappie" (3).** Portuguese writes "a Wappie" where
  Wappie checks or receives (C-AUTH-12, C-AUTH-19, C-SIGNIN-03, C-AUTHERR-06)
  and keeps "o Wappie" for the app and the connector ("pelo Wappie",
  "desbloqueia o Wappie", "conta Wappie"). The alert e-mail keeps its
  approved words, "Uma entrada na Wappie" and the button "Abrir a Wappie"
  (E-ALERT-01, 02, 05 and 06), which the recommendation does not name.
- **"entrar" and "entrada" (4).** Portuguese says "entrada" for a sign-in
  ("Entrada recusada", "Voltar para a entrada", "Este link de entrada já foi
  usado ou expirou", and every other refusal of the callback page); "acesso"
  stays for access to numbers, so the sign-in screen says "Outras formas de
  entrar" and Minha conta "suas formas de entrar". Spanish ("inicio de
  sesión") and German ("Anmeldung") had no such ambiguity. French has it:
  "connexion" is above all an assistant's connection in the console. It
  keeps "connexion" for a sign-in on the callback page, which shows nothing
  else, and uses the verb where an assistant's connection is near: "Impossible
  de vous connecter avec The Happie Co. Vérifiez votre accès à Internet et
  réessayez." (C-SIGNIN-06), and the step-up field's C-STEP-02 and C-STEP-07
  (the fewer steps).
- **One security alert (8).** The callback page and the e-mail give the same
  advice: "If you did not reset your The Happie Co account, change its
  password now and contact Wappie support before signing in again."
  (C-AUTHERR-04, E-ALERT-07). The e-mail goes in the account's language (see
  "Routes").
- **No server English on the screen (9).** The callback page says "Too many
  attempts. Try again in a few minutes." for `rate_limited`, in the
  console's five languages, instead of the server's message, and shows it
  even when the refusal comes before any form.
- **The Happie Co by name (10).** C-STEP-13 says "Your account signs in
  through The Happie Co, and confirming it is you there is not available
  yet." Members and permissions refuses a grant to such an account up front
  with it, before its dialog asks for a Wappie password the account does not
  have. The platform sign-in waits for step 4 in the pilot (above).
- **The link ceremony (11).** "Its other sessions end and its Wappie passkeys
  stop working." (C-AUTH-19), since the link revokes the passkeys.
- **Wappie support (12).** The callback page, which only the cloud build
  has, sends a password account that cannot be linked to Wappie support
  (C-AUTHERR-10), and every text a person reads uses the typographic
  apostrophe. The API's own messages (E-SIGNIN), which programs read, keep
  ASCII and the operator.

## The texts of step 4 (approved 2026-10-06)

The owner approved step 4's texts and plan on 2026-10-06 with every
recommendation (Decisions 1 to 12). In this repository:

- **E-STEP-01** (`step_up_required`, every guarded write) now names the
  identity provider: "confirm it is you first: with your passkey or your
  password, or at the identity provider your account signs in with, or sign
  in again; ...".
- **E-STEP-15** (`step_up_at_provider`) names the start route instead of
  saying the step is not offered yet.
- **E-STEP-16 to 24** are the two routes' messages (`step_up_here`, the
  start's `internal`, `token_refused`, `wrong_client`, `userinfo`,
  `step_up_not_started`, `step_up_other_account`, `step_up_stale`,
  `account_key_changed`). Like E-SIGNIN they say "identity provider", since
  the core is public and the provider configurable, and keep ASCII
  (Decision 11). The console never shows them: it shows its own words by
  code.
- **E-ALERT-10 to 14** are the step-up's alert e-mail in the five languages
  (`internal/mailer`): a confirmation, not a sign-in, was refused; its advice
  is the console's C-STEP-25, without "before signing in again".

The console's texts (C-STEP-14 to 25, C-AUTH-27 to 32, C-AUTH-19 changed)
are in the cloud build only; C-STEP-13 stays, unchanged, in the open build
(Decision 6), which has no OpenID Connect code and so no step-up at id.

## Not yet

- **Step 4 in the pilot.** Deployed with the switch off first; the sign-in is
  switched on only after the end-to-end test (Decision 8, above).
- **The cutover (step 5) and the end of the window (step 6).** Migration 0049
  will null the legacy credentials of linked accounts and delete their
  passkeys, with no down-step.
- **The rewrap of a new epoch in the console.**
- **Wappie's export.** It will carry the platform wrap (decision 0015, 0023).

# Browser session lifecycle

Account sessions survive refresh, payment-provider round trips and navigation
between the hosted app and console. A session remains authorized until the
server's existing expiration, explicit logout, password/recovery changes, or
another applicable server-side revocation. No password is remembered.

The browser imports the account's private key as a non-extractable X25519
`CryptoKey` for use in memory. Before sign-in wipes the decrypted private bytes,
it seals them with a fresh non-extractable AES-GCM-256 key, a random 12-byte
nonce, and an AAD binding of `['wappie/browser-account-key',1,userID,publicKey]`.
IndexedDB stores that AES handle and ciphertext, never plaintext private bytes.
Restoration decrypts the local envelope, imports X25519 as non-extractable, and
wipes the temporary bytes. A second non-extractable AES-GCM key encrypts the persisted
bearer token with account, workspace, server, expiration and browser generation
bound as additional authenticated data. The token is not placed in cookies,
URLs, localStorage or sessionStorage. The server continues to receive only the
encrypted account envelope and public authentication material.
This uses the standardized [Web Crypto serialization model](https://www.w3.org/TR/webcrypto-2/),
which permits non-extractable CryptoKeys in IndexedDB and origin-checked postMessage exchanges.
The version-two record deliberately omits the X25519 handle because
[WebKit bug 312279](https://bugs.webkit.org/show_bug.cgi?id=312279) makes a
successful write of that handle return a null record on subsequent reads.
Existing version-one records remain readable on browsers where they work; no
existing non-extractable key is exported to migrate it. Browser algorithm
availability errors preserve the encrypted record for retry.

This deliberately changes browser trust: an authorized browser profile can
reopen its session without a password or biometric prompt. A non-extractable
key cannot be exported through WebCrypto, but scripts executing in that origin
can use it. This is not a claim of hardware-backed key storage or protection
against malware, malicious extensions or a compromised browser profile.

## Hosted app and console

The interactive application uses `https://app.wappie.thehappie.co/` for messages
and `/console` for account/workspace management. The separate
`https://console.wappie.thehappie.co/` address remains a public entry point and
redirects HTML navigation to that canonical console route, preserving the
workspace and payment-return parameters. API requests keep their existing
addresses. This puts both screens in the same first-party storage origin,
including browsers that partition storage even between same-site subdomains.

Each successful login writes an origin-local IndexedDB record. An invisible
page at `https://api.wappie.thehappie.co/session-bridge.html` additionally stores
a shared copy in the background where browser policy permits it. The app can
open as soon as the local record is durable; an optional bridge timeout does
not delay this path. Bridge writes from each page are serialized so a slow
earlier token cannot overwrite a subsequent password rotation. Restoration
also reads the local record first. A legacy shared-only record is copied into
local storage when recovered, and a new browser without a generation marker
does not contact the bridge before showing sign-in.
Its `frame-ancestors` allowlist contains only the
HTTPS app and console origins. Those UIs permit only this exact bridge URL in
`frame-src`; their own documents remain unframeable. The bridge checks both the
actual parent window and exact message origin. Requests and replies use exact
`postMessage` target origins and structured clone, never wildcard origins or
secret URL parameters. Private keys and tokens do not travel through an HTTP
handoff service.

A shared cookie contains only a random public browser-generation marker. It
cannot authenticate or decrypt anything; the API does not use it for access.
Its purpose is to invalidate an older stored login on both UI origins even if
logout happens while the API and iframe are unavailable. It is restricted to
the Wappie subdomain, Secure, SameSite=Strict and the session's maximum lifetime.
Durable per-login tombstones also prevent late writes and pending restores
from resurrecting a logged-out or replaced account.

The local copy is written even if the iframe acknowledged its write: a
successful iframe write does not establish that its partition is shared or
durable. WebKit can partition IndexedDB by the embedding origin and discard
iframe data on navigation. It reproduces as successful initial login followed
by an empty vault on refresh, without a CSP error. The canonical first-party
route and local copy avoid relying on that iframe behavior for refresh,
app/console navigation or payment returns. If the browser refuses all persistence,
sign-in still works for the current page and the UI says it could not save the
session. Private browsing storage may disappear when that browsing session
ends; browsers may also evict inactive website data.
See WebKit's [cross-origin storage policy](https://webkit.org/blog/14403/updates-to-storage-policy/)
and [same-site subdomain partitioning report](https://bugs.webkit.org/show_bug.cgi?id=225297).

## Last opened number

The app remembers the last successfully opened number in this browser, scoped
by server origin, the authenticated user's stable ID, and the authorized
workspace ID. The separate localStorage preference contains only a device UUID;
it contains no phone number, email, token, or encryption key. It survives logout
so the same person can return to that number on a later sign-in. It does not
synchronize between computers, browser profiles, or separate self-hosted origins.
If browser storage is unavailable, the app still works with its ordinary fallback.

On a fresh opening, a valid explicit device link takes priority. Otherwise the
app restores the remembered number if it still appears in the current server
list and the account still has a readable grant. The fallback is an authorized
running number, then another authorized number; with none, it opens the console.
The console's return-to-app action follows the same preference. Reconnecting an
already open tab keeps its current authorized number. A successful device switch
updates the route so reload cannot return to an earlier link, and logout clears
the device selection from the login URL without removing the scoped preference.
Pasted API/archive keys have no stable account user identity and do not persist
this preference. There is no workspace-wide default or fixed primary number.

## Restoration and revocation

Before opening grants, restoration verifies the current bearer token through
`GET /v1/auth/me`, checks the account identity and public key, and opens only
the grants returned now. Expired, revoked or mismatched authorization removes
the stored login. A network outage retains it and offers retry; restoration
requests have a fifteen-second deadline. A requested unavailable workspace
falls back to the base session's workspace with a visible notice.

The sign-in form switches immediately to visible progress while contacting the
server, deriving the password key, confirming access or awaiting the passkey
prompt. Account and grant preparation then hand off to the session and
conversation loading indicators. This is feedback for the actual operations;
password derivation parameters and access checks are unchanged.

Each tab may derive a token for its requested workspace while preserving the
base browser login. Workspace links and payment return URLs retain their
workspace context. Derived tokens inherit a server-side session family and do
not extend authentication lifetime. Explicit browser logout submits
`POST /v1/auth/logout` with `{ "all_related": true }`, revoking that family,
including tokens in other workspaces. Other independent browser logins remain
valid. The existing empty-body logout semantics revoke only one token, for
internal credential replacement. Password changes still revoke older sessions
and update the remembered token.

Normal document navigation and component disposal clear in-memory state without
logging out. Explicit logout clears persisted state and broadcasts a non-secret
invalidation to other open app/console tabs. Session issuance, family logout,
passkey revocation and recovery share consistent database locking so a concurrent
workspace token cannot escape revocation.

Migration 30 adds session-family identifiers without changing existing tokens
or requiring secret cookie configuration. Self-hosted deployments use their
own origin's IndexedDB and do not enable the hosted iframe bridge.

## Optional browser regression

`web/test/browser/session.mjs` exercises the actual built Vue application and
login form in a fresh Playwright Chromium or WebKit profile. It generates a
synthetic account with real Argon2id, account-key wrapping and encrypted device
grants; all API and WebSocket traffic is intercepted, so no production account
or data is used. It verifies initial login, a readable device, refresh,
app/console navigation, the console entry redirect, an external payment return,
logout and another login. It prints only success flags and counts.

Playwright and its browsers are optional external QA dependencies, not required
for the normal Vitest suite. Run from `web/`, using a previously built hosted
client in `QA_DIST`:

```sh
QA_DIST=/absolute/path/to/hosted-dist \
QA_PLAYWRIGHT_MODULE=/absolute/path/to/playwright-core/index.mjs \
PLAYWRIGHT_BROWSERS_PATH=/absolute/path/to/browsers \
QA_BROWSER=webkit node test/browser/session.mjs
```

Use `QA_BROWSER=chromium` for Chromium; `QA_BROWSER_EXECUTABLE` optionally points
to an installed Chrome binary. Without `QA_DIST`, the runner uses the deployed
HTML/assets as well. With `QA_DIST`, it uses local assets and live document
security headers; the console redirect is simulated according to the separate
Go handler tests. The shared iframe document remains live in both modes, so
the test includes its real deployed CSP and postMessage transport.
Add `QA_PROGRESS=1` to assert immediate password/passkey progress, simulate an
ordinary cancelled platform passkey prompt, and report stage timings. That
mode adds 400 ms to the synthetic challenge response so the initial loading
state is observable independently of the real Argon2 worker duration.

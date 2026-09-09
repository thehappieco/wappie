# Browser session lifecycle

Account sessions survive refresh, payment-provider round trips and navigation
between the hosted app and console. A session remains authorized until the
server's existing expiration, explicit logout, password/recovery changes, or
another applicable server-side revocation. No password is remembered.

The browser imports the account's private key as a non-extractable X25519
`CryptoKey`. IndexedDB structured-clones that handle; it does not store exported
private-key bytes. A second non-extractable AES-GCM key encrypts the persisted
bearer token with account, workspace, server, expiration and browser generation
bound as additional authenticated data. The token is not placed in cookies,
URLs, localStorage or sessionStorage. The server continues to receive only the
encrypted account envelope and public authentication material.
This uses the standardized [Web Crypto serialization model](https://www.w3.org/TR/webcrypto-2/),
which permits non-extractable CryptoKeys in IndexedDB and origin-checked postMessage exchanges.

This deliberately changes browser trust: an authorized browser profile can
reopen its session without a password or biometric prompt. A non-extractable
key cannot be exported through WebCrypto, but scripts executing in that origin
can use it. This is not a claim of hardware-backed key storage or protection
against malware, malicious extensions or a compromised browser profile.

## Hosted app and console

An invisible page at `https://api.wappie.thehappie.co/session-bridge.html` owns
the shared IndexedDB record. Its `frame-ancestors` allowlist contains only the
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

The hosted origins are same-site. Browser privacy settings may still block
iframe storage; the client then uses origin-local IndexedDB so refresh and
payment returns can continue to work. If the browser refuses all persistence,
sign-in still works for the current page and the UI says it could not save the
session. Private browsing storage may disappear when that browsing session
ends; browsers may also evict inactive website data.
WebKit documents both its [same-site storage rules and eviction/privacy limits](https://webkit.org/tracking-prevention/).

## Restoration and revocation

Before opening grants, restoration verifies the current bearer token through
`GET /v1/auth/me`, checks the account identity and public key, and opens only
the grants returned now. Expired, revoked or mismatched authorization removes
the stored login. A network outage retains it and offers retry; restoration
requests have a fifteen-second deadline. A requested unavailable workspace
falls back to the base session's workspace with a visible notice.

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

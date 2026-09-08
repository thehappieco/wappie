# Passkeys and encrypted account keys

Passkeys are optional and belong to the global user identity. Workspace roles,
device grants and token permissions continue to determine archive access.
Registration and deletion require a valid bearer session and the current
password-derived `auth_key`. Password authentication remains available.

In the console, open **Minha conta → Passkeys → Adicionar passkey**. Confirm
the current password once and follow the browser's prompts. Future visits use
**Entrar com passkey** without typing an email or password. The authenticator
must support WebAuthn PRF to unlock the account; unsupported providers do not
complete registration. Chrome/Safari password forms also retain standard
`username`, `current-password` and `new-password` autocomplete semantics.

Enable the feature with both environment variables:

```dotenv
WS_PASSKEY_RP_ID=wappie.thehappie.co
WS_PASSKEY_ORIGINS=https://app.wappie.thehappie.co,https://console.wappie.thehappie.co
```

Origins are exact HTTPS origins, including a non-default port when applicable.
The server never infers the RP or allowed origins from request headers. Local
development may use `localhost` with an HTTP origin; production requires HTTPS.
All ceremony and deletion requests must carry an allowed `Origin` header.
The RP ID is a durable credential and envelope binding: changing it makes
credentials registered under the previous RP unavailable for login.

## HTTP contract

All endpoints are below `/v1/auth/passkeys`. Responses use `Cache-Control:
no-store`. Native WebAuthn binary fields use unpadded base64url. `prf_salt` and
`wrapped_usk` use standard base64.

| Method and path | Authorization and input | Successful response |
| --- | --- | --- |
| `GET /config` | Public | `{enabled:boolean,rp_id:string,origins:string[]}`; disabled returns an empty RP and origin list |
| `GET /` (without trailing slash) | Bearer | `{passkeys:[{id,label,created_at,last_used_at?}]}` |
| `POST /register/options` | Bearer; `{auth_key,label}` | `{flow_id,publicKey,prf_salt,rp_id,user_id}` |
| `POST /register/finish` | Same bearer session; `{flow_id,credential,wrapped_usk}` | `{passkey:{id,label,created_at}}` |
| `DELETE /{id}` | Bearer; `{auth_key}` | `{ok:true}` |
| `POST /login/options` | Public; `{}` | `{flow_id,publicKey,prf_salt,rp_id}` |
| `POST /login/finish` | Public; `{flow_id,credential}` | `{token,expires_at,user,passkey:{id,wrapped_usk,prf_salt}}` |

`user` in the login response has the same shape as password login, including
its password-encrypted `wrapped_usk`. The passkey client instead opens
`passkey.wrapped_usk`. Listing returns metadata, without public key material,
credential IDs or encrypted envelopes. Labels contain 1–80 characters; each
account can have at most 12 active passkeys.

`publicKey` is directly compatible with WebAuthn JSON options after binary-field
decoding. Registration requires a resident credential and user verification;
login is discoverable and also requires user verification. The server requests
PRF and, at registration, `credProps`. `credential` is the normal serialized
creation or assertion response, but its `clientExtensionResults` may contain
only `credProps.rk` and `prf.enabled`. **Never submit `prf.results`**. The server
rejects it, and does not persist or log request credentials on verification
failures.

Challenges expire after five minutes and are consumed atomically before
verification. They cannot be retried, even after an invalid signature. Each
flow is bound to the exact originating UI; registration also binds the global
user and the starting bearer session. A challenge started in the app cannot
finish in the console; a fresh ceremony can use the same credential there.

## Client encryption

The public PRF salt is SHA-256 of UTF-8
`wappie/passkey-vault/v1/` followed by the RP ID. A stable per-RP salt supports
discoverable login without requesting an email or enumerating credentials.
The authenticator's PRF result remains secret and credential-specific.

The client derives an AES-GCM-256 key from the first PRF output using
HKDF-SHA-256, with UTF-8 RP ID as salt and UTF-8 `wappie/passkey-wrap/v1` as
info. It encrypts the existing 32-byte account private key, with a random
12-byte nonce and this UTF-8 JSON array as additional authenticated data:

```json
["wappie/passkey-vault",1,"<rp_id>","<canonical user UUID>","<credential rawId in canonical base64url>"]
```

The resulting opaque envelope is 61 bytes: version byte `1`, nonce (12),
ciphertext (32), authentication tag (16). The server validates only its version
and length; it has neither the PRF output nor the wrapping key. If creation
enables PRF but does not return its output, a client may perform an additional
local assertion for the new credential before submitting registration. That
assertion and its PRF output are not sent to the server.

## Revocation and recovery

Removing a passkey revokes sessions authenticated by it, including sessions
subsequently created when selecting another workspace. Other password sessions
and other passkeys remain valid. Recovery with a recovery code revokes every
passkey, pending registration and session. An ordinary password change retains
passkey envelopes because the account private key has not changed, while
revoking existing sessions as before.

Registration and recovery serialize per identity before locking sessions or
credential rows. Session creation locks and rechecks its passkey, so concurrent
revocation cannot leave a newly issued session valid. Assertion counter updates
use optimistic concurrency and reject clone warnings; authenticators using a
zero counter remain supported.

The PostgreSQL migration is additive. Public authenticator records and opaque
envelopes are protected by identity-scoped forced row-level security. No
password, PRF output or plaintext account private key is stored in these tables.

# Wappie

Multi-tenant WhatsApp API server with a sealed archive, plus a web client that
consumes the same API.

Wappie connects business systems to WhatsApp through HTTP and WebSocket, with
shared workspaces, per-number permissions and a messaging client.

- [Product and documentation](https://wappie.thehappie.co)
- [Workspace console](https://console.wappie.thehappie.co)
- [Messaging client](https://app.wappie.thehappie.co)
- Hosted API: `https://api.wappie.thehappie.co` (`/v1/ws` for WebSocket)
- [Workspace model and API contracts](docs/workspaces.md)
- [Personal accounts, Team workspaces and invitations](docs/accounts-workspaces.md)
- [Deployment guide](docs/deployment.md)
- [Passkeys and encrypted login](docs/passkeys-api.md)

The server, CLI, web client and basic administration are Apache-2.0 open source.
Managed hosting and commercial billing are maintained separately. The hosted
pilot uses free access and sandbox payments. No live charges. Public signup is
opt-in and requires email verification; invitation signup also remains available.

## Status

There is a browser client, and now there are accounts. Signing in is what turns
a sealed archive into a readable one: the password derives a key that unwraps
your own private key, that opens a **key grant** per WhatsApp account, and each
grant is that device's archive key. Nothing has to be written down, and a
forgotten password has a recovery code behind it.

The archive key belongs to a **device**, not to a tenant. With one key per
tenant, "this operator may read that WhatsApp account and not this one" is a
rule the server enforces — and the premise here is that server-enforced rules
do not survive a compromised server. Per device it is arithmetic instead.

The client opens everything **in the page**: the private key never reaches the
server. Conversations, names, profile pictures, attachments and the edit
history all render from ciphertext the server cannot open.

Before it, phases 0 to 6: a device pairs from the terminal, its traffic is
sealed on the way in, the history sync is ingested, `wsctl history` shows every
version of an edited message, the text of a deleted one, and which version each
reader had on screen, and attachments are stored as the ciphertext the CDN
served — never decrypted by this server at all.

| Phase | | |
|---|---|---|
| 0 | Skeleton, migrations, media crypto, RLS, CI | done |
| 1 | Pair a device (QR and 8-character code) | done |
| 2 | The ingest pipeline, sealing, live delivery, text send | done |
| 3 | Edit / revoke / react projection, receipts, who saw which version | done |
| 4 | Media inbound, and structured content: location, poll, contact, event | done |
| 4b | Media outbound: upload and send. View-once now works | done |
| 5 | History sync ingest | done |
| 5b | Media retry: recovering attachments with expired urls | done |
| 6 | Contacts, names and profile pictures | done |
| 5c | On-demand backfill | done |
| 8 | Web client: reading the archive in a browser | done |
| 9 | Per-device keys, accounts, key grants, recovery | done |
| 10 | Admin console: devices, pairing, tokens, grants | next |
| 8b | Web client: sending, editing, reacting, attachments | done |
| 12 | Conversation layer: unread, ticks, presence, groups, polls | done |
| 11 | Incognito per device, quotas, hardening | done |
| 13 | Security audit: recovery, rate limits, key scopes, SSRF, retention | done |

Design and rationale: `~/.claude/plans/meu-objetivo-criar-playful-conway.md`.
Decisions taken while building, and the invariants that are easy to break:
[docs/decisions.md](docs/decisions.md).

## Running locally

Needs PostgreSQL 18 or newer, for `uuidv7()`. Object storage is optional: with
none configured the server says so and carries on, and attachments queue in the
database until it appears — nothing is lost, and configuring storage later
drains the backlog.

```
cp .env.example .env   # then edit WS_POSTGRES_DSN
make dev-up            # optional: Postgres + MinIO in Docker
make build && ./bin/whatserverd
```

Both binaries read `.env` from the working directory. Real environment
variables always win, so a stale file cannot redirect a deployment.

Already have Postgres locally? Point `WS_POSTGRES_DSN` at it. The role must not
be a superuser: superusers bypass row-level security, and the isolation tests
would then pass no matter how broken the policies were.

```
CREATE ROLE whatserver2_app LOGIN PASSWORD 'dev'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE DATABASE whatserver2 OWNER whatserver2_app;
```

```
make check           # fmt, vet, layout, tests with -race
make web-check       # typecheck, tests and build for the browser client
make cover
make fuzz
```

Tests skip when no database is reachable. CI sets `WS_TEST_POSTGRES_REQUIRED`
so a skip there is a failure. Each test runs in its own Postgres schema, because
`go test ./...` runs packages in parallel and a shared schema means one package
can drop tables out from under another.

## Getting started

```
./bin/whatserverd bootstrap -tenant "My Company"   # tenant and an API key
./bin/whatserverd invite -tenant <ID>              # a one-time signup code
./bin/whatserverd key -tenant <ID> -scope read     # a narrower key for a program
```

An API key has a **scope**: `read` reaches the archive as ciphertext and
nothing that touches WhatsApp; `send` adds outbound messages and attachments;
`full` adds pairing, stopping devices, history backfill and joining groups.
`bootstrap` prints a full key for `wsctl`. Everything else should get the
narrowest one that works, because a key is the credential most likely to leak
and a leaked `send` key is a message to somebody's customers.

Then open the web client and sign up with that code. Do this **before** pairing
anything: pairing generates the device's archive key and seals it to the
accounts that exist at that moment, and a device paired with no account behind
it leaves a key somebody has to keep in a file.

```
export WS_API_KEY=...
./bin/wsctl pair -phone +5511999999999
```

Pairing generates the archive key in the client, seals a copy to every account,
and forgets it. It refuses to run when there is no account to seal to, because
that is how an archive gets lost; `-orphan` overrides it and prints the key
once.

`wsctl` reads the same `.env`, so changing `WS_HTTP_ADDR` moves both sides at
once rather than leaving the client pointed at a stale default.

That prints an eight-character code to type into the phone under Settings →
Linked devices → Link with phone number instead. `-method qr` renders a QR in
the terminal instead, which mostly means photographing your own screen — the
code is easier.

Either way the window is 160 seconds and cannot be extended: WhatsApp closes the
login socket once its QR sequence runs out. The phone number and the display
name are validated locally first, because a malformed request comes back as an
opaque 400 *after* the window has already started.

```
./bin/wsctl devices     # what is paired, and what this server is supervising
```

Devices default to passive receipts. See below.

## The web client

The browser is where the archive is actually readable. Everywhere else it is
ciphertext, including on this server.

```
make web-install    # once
make web-build      # writes web/dist
./bin/whatserverd   # serves it at /
```

`WS_WEB_DIR` points at the built client and defaults to `web/dist`. Nothing is
embedded in the binary: `go build` must not need a JavaScript toolchain, and CI
has none. With no build present the server logs that it is serving the API only
and carries on.

For development, `cd web && npm run dev` runs Vite on :5173 and proxies `/v1`
to :8090. Go through the proxy rather than pointing the client at :8090
directly — the websocket handler accepts same-origin connections only, and a
cross-origin attempt is refused at the upgrade, before the app sees an error it
could report.

Opening it means signing in with an email and a password. The password never
reaches the server: the browser derives a master key with Argon2id, keeps the
branch that unwraps your private key, and sends only the branch that proves who
you are — stored there as a slow hash. A signup prints a recovery code once,
which wraps the same private key and is the only way back from a forgotten
password: "Esqueci a senha" on the sign-in screen takes the code, proves it to
the server the same way a password is proved, opens the key in the page, and
sets a new password and a new code. The console's account panel changes the
password and regenerates the code; both end every other session.

Every human identity receives one Personal workspace. Additional Team workspaces
support multiple members; number capacity and billing belong to each workspace
independently of its type. Existing workspaces are preserved as Team, with their
numbers, memberships, grants and subscriptions unchanged. Account names and
avatars are shared profile metadata; WhatsApp photos remain encrypted.

To open public signup, configure `WS_APP_URL`, the `WS_SMTP_*` settings and
`WS_MAIL_FROM`, then set `WS_PUBLIC_SIGNUP=true`. Mail uses verified TLS and signup
requires an email-bound, expiring proof. Invitations to a specific email can also
create the Personal workspace and join the invited Team atomically. Failed signup
does not consume the invitation. `WS_INVITE_ENCRYPTION_KEY_HEX` enables recovery
of new invitation codes; old hash-only codes must be regenerated. See the account
guide above for endpoints, migration behavior and deployment checks.

Accounts created before recovery could be redeemed hold a code the server
cannot hand back. They see a notice on the console and generate a new one.

There is still a way in without an account: paste an API key and one device's
archive key, optionally sealed under a passphrase in that browser's IndexedDB.
It is the escape hatch for a machine that should hold no account, and it is
also exactly how the first archive of this project was lost — so it is a link
at the bottom of the sign-in screen rather than the front door.

What the page can do, it does locally. HPKE, the content keys, the message
bodies, the contact names, the profile pictures and the attachment decryption
all run in the tab, against bytes the server hands over without being able to
read them. Clicking any message opens the panel that is the whole point of the
product: every version of an edited message, the text of a deleted one, every
reaction including the withdrawn ones, and which revision each reader had on
screen — with "inferred" marked as inferred.

A dropped connection retries with backoff and picks up where it was, rather
than leaving a close code on screen until someone reloads. The open
conversation is re-read from the archive on the way back, because live traffic
that happened while the socket was down was missed.

This slice reads. Sending, editing, reacting and marking as read are already in
the protocol and already work from `wsctl`; the browser does not offer them yet.

### The second implementation problem

The client is a second implementation of the sealed archive format, in another
language. A second implementation that is subtly wrong opens everything it
sealed itself and fails only against real data — which is the worst possible
time to find out.

So neither side is trusted to agree with itself:

- `internal/crypto/seal/testdata/vectors.json` and
  `internal/crypto/wamedia/testdata/vectors.json` are generated by Go and
  opened by both. They include values that **must not** open: a blob moved to
  another row, one presented under another kind, one with a flipped header bit.
  An implementation that skipped the AAD binding passes every positive test and
  fails all of those.
- `internal/wsapi/testdata/frames.json` holds whole frames sealed the way the
  ingest pipeline seals them. It catches the other half of the problem: not
  whether the crypto is right, but whether the client asks for the *right* row
  and the right kind. A message body binds to the message, a chat name to the
  chat, a contact name to the contact, and a file name — confusingly — to the
  message under the contact-name kind. Get any of those wrong and everything
  comes back as tampered with the correct key in hand.

Regenerate a fixture deliberately, never as a way to make a test pass:

```
go test ./internal/crypto/seal -run Vectors -update
go test ./internal/crypto/wamedia -run Vectors -update
go test ./internal/wsapi -run Fixtures -update
```

### Trying it without a phone

`seeddemo` writes a small, obviously fake conversation through the real ingest
pipeline — edited messages, a deleted one, reactions, a location, a poll — so
the client can be developed without pairing a device and without testing on
someone's actual messages.

```
./bin/whatserverd bootstrap -tenant demo
./bin/whatserverd archive-key -tenant <ID>
./bin/seeddemo -tenant <ID>
```

## How the archive is protected

Media arrives from the Meta CDN already encrypted — AES-256-CBC with an
encrypt-then-MAC HMAC, keyed by a 32-byte `mediaKey`. The blob is stored exactly
as received and only the `mediaKey` is sealed to the device's public key. The v1
server got the first half right and then wrote `media_key` in the clear in the
column beside the ciphertext, which defeated the whole thing.

Message bodies are sealed with HPKE (RFC 9180, X25519 + HKDF-SHA256 +
AES-256-GCM) under a content key that covers a batch. Batching is not an
optimisation: one asymmetric operation per message costs 12-33 seconds to open a
10k-message history on a mid-range Android, and about ten operations total once
batched.

The server holds only public keys. It can seal and cannot open. Each device has
an archive keypair, generated by whichever client paired it; the private half is
sealed to the public key of every account that may read the device (a **key
grant**) and then forgotten. Each account's own private key is generated in its
browser at signup, wrapped under a key derived from the password with Argon2id
and bound to the account's address, and never transmitted. The recovery code
wraps the same key a second time.

Who may reach what, on the server side:

- A **member** reaches only the devices granted to them — content and envelope
  alike. Without a grant the server answers with `not_authorized`, not with a
  chat list they cannot open.
- An **owner or admin** administers numbers, pairing, grants and API keys. Reading
  encrypted content still requires a usable grant. Removing the last active
  reader's usable grant is refused, including disabling the member.
- A human reader's **discreet mode** is a per-user, per-number preference. The
  app uses `reader.mode`; automation retains the legacy `device.mode` policy.
  Badges and the physical WhatsApp connection remain shared by the number.
- An **API key** does what its scope says, and the server checks it on every
  frame. No scope reaches the tenant's configuration.

Sign-in attempts are rate-limited per address and per account, on the HTTP
endpoints and on the websocket hello alike: each attempt costs the server an
Argon2id derivation and each wrong one is a guess. Behind a reverse proxy, set
`WS_TRUSTED_PROXIES` so the limit sees the client and not the proxy.

Attachment URLs come from the message that carries them — from the sender —
and are fetched only from `*.whatsapp.net` over TLS, with every redirect and
every resolved address checked, so a message cannot point this server at an
address of the sender's choosing.

## Giving a system access

A third party that needs to read the archive does not get a device key by
hand. It gets a **service account**: an account with a keypair and no
password, granted devices like a person and reached through an API key that
acts as it.

```
./bin/wsctl service-key                                  # on the third party's machine
./bin/whatserverd invite -tenant <ID> -role service      # an invite for a system
```

The system registers its public key with that invite under "Registrar um
sistema" on the sign-in screen. In the console an owner grants it devices —
the same button as for a person; the device key is sealed to the system's
public key in the owner's browser — and mints an API key that *acts as* the
account, with the narrowest scope that works. The system then asks for its
grants and opens them with the private key that never left it:

```
WS_API_KEY=... ./bin/wsctl grants -service-key <PRIVATE>            # what it may open
WS_API_KEY=... ./bin/wsctl grants -service-key <PRIVATE> -device ID # that device's key, for -key
```

A key acting as a service reaches only the devices the account was granted.
Revoking the grant, or the key, is revoking the access; nothing was ever sent
in the clear for anyone to keep.

## Retention and erasure

Nothing expires by default. A tenant that wants a window sets one:

```
./bin/whatserverd retention -tenant <ID> -days 90
./bin/whatserverd retention -tenant <ID> -forever
```

The running server applies it hourly: messages, receipts, group events and
attachments older than the window go, with their objects in storage. Chats and
contacts stay. Disappearing messages are still preserved until then — that is a
product decision with a legal dimension, stated in the section below.

A person can be removed from a tenant's archive across every device:

```
./bin/whatserverd erase -tenant <ID> -id +5511999999999 -yes-erase
```

Their direct conversation, everything they sent in groups, every receipt they
produced, their contact row and their group memberships go; what other people
said in those groups stays. Deleting a device, or `reset-archive`, now removes
its attachment objects from storage as well.

Logs mask identifiers at every level: a JID keeps its server and last four
digits, an email its first letter and domain. `WS_LOG_WIRE` puts whatsmeow's own
protocol trace — message bodies in the clear — into the log, and is refused in
prod.

## What this does not protect against

Worth stating plainly, because "encrypted at rest" is often read as more than it
is.

- **An attacker running code on a live server sees plaintext in flight.**
  Messages are decrypted by the Signal session, sealed, and stored; the
  plaintext exists in memory in between. At-rest sealing protects a stolen disk,
  a leaked backup and a database dump. It does not protect a compromised
  running process.

- **The whatsmeow session store must stay readable by the process.** Without it
  the connection cannot be maintained. Whoever steals it can impersonate the
  device and read *new* messages — but not the archive, which is sealed to a key
  the server does not have.

- **Outbound text passes through in the clear.** The Signal session lives on the
  server, so it needs the plaintext to encrypt for WhatsApp. Outbound *media*
  does not: the browser can produce the ciphertext and hashes itself.

- **Inbound media is never decrypted here at all.** whatsmeow's download helpers
  decrypt on the way past; this server fetches the CDN's ciphertext with its own
  HTTP client and stores it byte for byte. The download is still verifiable,
  because `fileEncSHA256` is a hash of the ciphertext.

- **Attachment metadata is readable**: type, size, dimensions, duration, and the
  hashes. The bytes and the file name are not.

- **Routing metadata is in the clear**, so the server can paginate and order.
  A database dump reveals who talks to whom, when, how often, and the type and
  size of attachments. The social graph and operational pattern survive; the
  content does not.

- **Receipts are in the clear too**, and they are the sharpest part of that
  metadata: who read what, and at what minute. There is nothing in a receipt to
  seal — it is a party, a message id and a time — and it is what makes "who saw
  which version" answerable at all. Worth knowing it is there.

- **An authorized browser remembers its session until logout or expiration.**
  IndexedDB stores the account key and bearer token as ciphertext protected by
  non-extractable AES-GCM keys; passwords and plaintext private keys are not
  persisted. Each restoration validates the session and current device grants
  with the server. Hosted messages and console share one browser origin, with
  a narrowly restricted bridge for compatible older hosted sessions;
  self-hosted clients use their own origin's storage. Anything that can execute
  script in an authorized origin can still use these keys to obtain plaintext. The client
  ships a content security policy, loads no third-party hosted JavaScript, and
  implements HPKE over WebCrypto. Non-extractable WebCrypto keys are not a promise of
  hardware-backed storage or protection from a compromised browser profile.
  See [browser session lifecycle](docs/browser-sessions.md) for persistence and logout behavior.

- **The password is what protects an account, and the wrapped key is on the
  server.** Argon2id at 64 MiB and three passes, derived in a worker so the tab
  does not freeze, and split so that the branch which opens things never leaves
  the browser. A dump still yields an offline target: a hash to attack and a
  wrapped key to attack. A weak password is weak. The online side is bounded —
  five attempts a minute per account — but that is a limit on guessing, not a
  substitute for a password worth guessing at.

- **The whatsmeow session store has no retention.** `erase` removes a person
  from the archive; whatsmeow's own contact and group caches are refreshed from
  the phone and are outside it.

- **A grant is not a lock.** Removing one stops somebody obtaining the key
  again; it says nothing about a copy they already unlocked, because the key was
  in their browser. Only rotating the device's epoch and re-sealing is
  retroactive, and that is not built yet.

- **One dependency handles the password**, `@noble/hashes` for Argon2id, because
  WebCrypto has nothing memory-hard. Everything else in the client — HPKE, the
  envelope format, the media scheme — is WebCrypto and no packages.

- **Lose every access path and the archive is gone.** Permanently, for everyone,
  including the operator. That is the trade the design makes.

## Seeing what a normal client hides

```
./bin/wsctl history -key $ARCHIVE_KEY -uid <uid>
```

Edits, deletions and reactions are stored as rows of their own rather than as
changes to the message they act on, so nothing is ever written over. The
projection assembles them into the life of one message:

- every version, in order, with the window of time each was the current one;
- the text of a deleted message, which a normal client replaces with a notice;
- reactions including the ones later replaced or withdrawn;
- for each reader, the revision they had on screen when they read it.

That last one is stated carefully. Every version — the original and each edit —
is a stanza with a WhatsApp id of its own, so a delivery receipt naming an
edit's id is the reader's own device confirming that exact text arrived. When
that confirmation exists, the answer is proof. When it does not, the answer is
inferred by comparing our clock with WhatsApp's, and the output says
`[inferred]` rather than claiming somebody read a correction they may never
have been shown.

None of it requires active mode. This server suppresses the receipts it sends;
that has no effect on the ones it receives.

## Attachments

The bytes on WhatsApp's CDN are already AES-256-CBC ciphertext under a 32-byte
media key. That ciphertext is what gets stored — verbatim, with its trailing
MAC — and the key is sealed into the message row. So a stolen bucket, or a
public one, yields noise.

Nothing here decrypts on the way in. whatsmeow's download helpers do, which
would put every photograph and voice note through this process in the clear;
`internal/media` fetches with its own HTTP client instead. The download is still
checked, because `fileEncSHA256` is a hash of the *ciphertext* — verifiable
without a key.

```
./bin/wsctl media -uid <uid> -key $ARCHIVE_KEY        # opens it here
./bin/wsctl media -uid <uid> -raw -o out.enc          # what the bucket holds
```

Attachments travel over `GET /v1/media/{uid}` rather than the websocket: a two
hundred megabyte video framed down the same connection as live messages would
stall every other frame behind it. The endpoint sets
`application/octet-stream` and `nosniff`, because labelling ciphertext
`image/jpeg` would be both false and a hint.

Storage is content-addressed by the ciphertext hash and prefixed by tenant, so
one image forwarded into twenty chats is one object — and two tenants holding
the same file still hold it separately.

**Sending** works the other way round, and this is the honest limit:

```
./bin/wsctl send-media -device ID -to NUMBER -file photo.jpg -view-once
```

WhatsApp's upload takes cleartext and encrypts on the way out, and offers no
exported way to hand it ciphertext produced elsewhere. So an attachment being
*sent* passes through the server in the clear, exactly as outbound text already
does, and is sealed the moment it is archived. Making the outbound side match
the inbound one means reimplementing the upload handshake, whose authorisation
token whatsmeow keeps internal — a fork, and a standing maintenance cost.

`-view-once` works here and only here: it is a media feature, which is why
`wsctl send` refuses it on text.

## History

Pairing a device makes WhatsApp send a bootstrap sync — every conversation it
can still reach, once. It is ingested in the background, off the goroutine that
reads the socket, because doing it inline stops that device receiving anything
until it finishes.

```
./bin/wsctl chats -device ID -key $ARCHIVE_KEY
```

Chat names arrive with that sync and nowhere else: nothing on the live path
carries one, which is why a group shows as a numeric id until a sync has run.
Names are sealed like message bodies — for a direct chat, a name is a person's
name.

A sync covers what the phone still holds and stops. Anything earlier is asked
for one conversation at a time, anchored on the oldest message already stored:

```
./bin/wsctl backfill -device ID -to NUMBER -count 50
```

The answer arrives minutes later as an on-demand sync, ingested like a
bootstrap. Run it again afterwards: if the anchor has not moved, the phone has
nothing older.

Re-pairing is how an existing deployment picks up history it never had. Pairing
creates a new device row rather than replacing one, so nothing needs deleting
first; deleting the old device would cascade its messages away. While both are
linked every message is archived twice, so unlink the old one once the new sync
has landed.

### Attachments a history sync cannot fetch

WhatsApp signs media urls with an expiry and puts the same signature on the
direct path. A sync replays months-old messages carrying the url minted back
then, so a bootstrap arrives with many attachments already unreachable — 403,
body `URL signature expired`. No header helps and no library does better:
whatsmeow's download sends the same three headers, and the media connection's
auth token is used only for uploads.

The recovery is to ask the sender to upload the file again:

```
./bin/wsctl media-retry -device ID -key $ARCHIVE_KEY -n 200
```

The media key has to come from you. It authenticates the request and decrypts
the answer, and the server cannot open its own sealed copy — so it is held in
memory for the exchange and never written down. Expect a partial recovery: the
sender has to be reachable and still hold the file.

## Who the numbers belong to

```
./bin/wsctl chats  -device ID -key $ARCHIVE_KEY
./bin/wsctl avatar -device ID -key $ARCHIVE_KEY -contact NUMBER
```

Three names are kept per contact and the server chooses between none of them:
the push name someone set for themselves, the name this account saved them
under, and a verified business name. Which to show depends on what the client
is for. All three are sealed — a dump that revealed who the identifiers belong
to would hand over most of what a social graph is.

The bulk arrives in one history-sync payload and lands in whatsmeow's own
store, so the archive imports from there at every boot rather than waiting for
five thousand people to each send a message.

Profile pictures are the one thing in this system that arrives unencrypted:
WhatsApp serves them over plain HTTP to anyone with the URL. There is no
ciphertext to preserve, so unlike message media — never decrypted here — a
profile picture is necessarily seen by this process and is sealed on the way
in. Fetching is paced, because each question is a query over the socket that
carries messages.

## Disappearing messages

A chat setting, not a message option: WhatsApp has no way to make one message
vanish and leave the next one alone.

```
./bin/wsctl chat-timer -device ID -to NUMBER -seconds 86400   # 24h
./bin/wsctl chat-timer -device ID -to NUMBER -off
```

Every later message in that chat then disappears, and the timer is applied
automatically — including the envelope the message has to travel in, which is
the part that makes it actually vanish rather than merely declaring a number.
The timer is also learned from incoming messages, because that is the only way
a linked device finds out about one set on the phone.

The archive keeps them all, marked with when they were meant to go. That was a
deliberate choice and there is a legal dimension to it in some jurisdictions.

## Incognito

The server stays connected while explicitly announcing WhatsApp presence as
`unavailable`, including after reconnecting. This applies to both `active` and
`passive` receipt settings, so existing numbers do not remain publicly online
just because an integration permits read confirmations. Messages, media and
history continue to be processed, and outgoing messages remain available.

Each person's incognito preference separately suppresses their read/played
confirmations and typing actions. Normal mode permits those actions without
announcing the server online. A read confirmation can still clear a phone's
notification for that message. Other linked clients can also affect the
number's public presence and unread state.

The normal protocol delivery receipts still leave, using upstream's `inactive`
behavior. Observing contacts' online state, last seen or typing may be limited
while our connection is publicly unavailable. The console's connected status
describes the connection, not public presence. See
[presence and reading preferences](docs/message-presence.md) for details.

## Layout

```
cmd/whatserverd        server
cmd/wsctl              CLI over the public SDK, dogfooding the protocol
internal/config        environment-only configuration
internal/obs           logging and metrics
internal/pg            three pools, tenant transactions for RLS
internal/migrate       versioned migrations, checksummed, advisory-locked
internal/crypto/wamedia WhatsApp's media scheme
internal/crypto/seal   HPKE envelopes and content keys
internal/wa            whatsmeow wrapper; upstream_contract_test.go pins the API
internal/ingest        the one canonical event pipeline
internal/store         persistence and projection
internal/wsapi         websocket sessions, replay, backpressure
pkg/waclient           public Go SDK
web/                   Vue 3 client
```

## Notes from the previous six attempts

Each fixed something structural that a predecessor got wrong.

- Three connection pools, not one. v1 ran SQLite with `SetMaxOpenConns(1)` and a
  10k-message history sync stalled everything behind it.
- One canonical pipeline. v1 had the live and history paths duplicated in four
  places, and all four had already diverged.
- Identity is a `(lid, pn)` pair with LID primary. v1 rewrote every LID to a
  phone number; upstream now routes DMs over LID, and LID exists precisely to
  withhold the number, so for some contacts there will never be one.
- Configuration is environment-only. v1 committed a `config.yaml` holding a live
  API key.
- Every ignored upstream event increments a counter. v1 ended its handler with
  `_ = v // ignore the rest for MVP`, dropped about forty event types, and its
  `contacts` table was created, queried and never written to.
- `errcheck` runs with `check-blank`, and silencing one needs a reason on the
  line. The v1 bug it would have caught: `_ = c.saveCanonical(...)` turned failed
  writes into silent successes.

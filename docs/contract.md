# The product contract's membership part

The hosted cloud follows The Happie Co's platform for who belongs to which
workspace (platform decisions 0040, 0041, 0043 and 0044; the normative spec
is the platform's `docs/contract/v1/README.md`, "the spec" below, cited by
section). Wappie is one of the platform's apps: it subscribes the people it
holds, follows the platform's feed of their account documents, sends an
access snapshot of every platform workspace, and sends the platform the
item events its owners and readers are mailed from. A self-hosted
installation has none of this: with no `WS_CONTRACT_*` setting nothing calls
the platform, and the mode stays `off`.

This release **observes**: it receives and sends, and enforces nothing
(platform decision 0005, "observe mode (receives and sends, does not
enforce)"). It compares the documents with Wappie's own members and logs
the differences, and changes nobody's membership, role, status, session or
key because of one. A later release, **enforce**, applies them
([what enforce adds](#what-enforce-adds)).

Everything below lives in `internal/membership` (the calls, the leader, the
senders, freshness), `internal/store/contract*.go` (the state, under the
same rules as the rest of the store) and `cmd/whatserverd/contract*.go` (the
wiring and the commands). Migration 0051 holds the state; its header
describes every table and column.

## What observe does, and its three exceptions

At observe Wappie stores the last document of each sub (newer versions
only), records every workspace a document names, and compares; nothing in
`users`, `workspace_memberships`, `sessions`, `api_keys`, grants or
`tenants` changes because of a document. Three things do change, and are
the only ones:

1. **A new account's home.** Once the contract has been observed, a new
   account's personal workspace is created with the id of the platform's
   personal workspace in its document, in every mode since, `off`
   included. An account the platform does not answer for is refused,
   retryably, and never given an id of Wappie's choosing
   ([sign-in](platform-sign-in.md#the-contract-at-sign-in)).
2. **The record of platform workspaces.** Every workspace a document names
   is recorded for good in `contract_workspaces`, with its kind (`personal`
   or `team`), which never changes. A document whose workspace kind
   differs from the record or from Wappie's own workspace of that id is not
   stored (ERROR "contract: workspace kind changed").
3. **Person invitations into a recorded team are paused**
   ([below](#person-invitations-into-platform-teams)).

The checks enforce will make binding run now **in shadow**: they reach
their verdict, log "would refuse", and let the act go on
([freshness](#freshness)).

## Transport

- **The socket.** `WS_CONTRACT_SOCKET`, `/run/platform/contract.sock` in
  production (spec 2): HTTP/1.1 without TLS, owned by root and the group
  `platform-contract`, mode 0660, made by systemd. The server's unit joins
  that group (`SupplementaryGroups=platform-contract`); the platform reads
  the peer's uid and maps it to the app `wappie`. Every request's URL is
  `http://contract/...`; the host is never dialled.
- **The peer's own checks**, before each connection (spec 2): the socket's
  directory is a real directory (not a symbolic link) owned by uid 0 that
  neither its group nor others may write, and the socket is a socket owned
  by uid 0. A socket that fails them gets no request, and none for a minute
  after (ERROR "contract: the socket failed its peer checks; no request goes
  to it for a minute"). The signed answers are the real proof (spec 5).
- **No answer.** A missing socket, a refused connection or a permission
  denied (the socket goes whenever the platform's socket unit restarts) is
  no answer: retried with backoff, never alarmed on the first.
- **Development.** `WS_CONTRACT_ADDR` dials the platform's loopback TCP
  transport (`127.0.0.1:8291`): refused in prod, beside the socket, and for
  any address that is not a loopback IP.
- **Every call** goes through the kit's contract client
  (`github.com/thehappieco/kit/contract`), which signs the request
  (`thehappie-platform-hmac/v1`), checks the answer's signature against the
  nonce sent, validates the wire and bounds the call (15 s; a long-poll its
  wait plus 15 s). No proxy, no redirect. Wappie sorts each outcome as
  **answered** (a signed, valid answer), **refused** (a signed refusal, acted
  on by its code), **unverified** (an answer whose signature does not hold,
  ignored whatever its status) or **unavailable**. A signed `replay` or
  `unavailable` is tried once more, signed afresh. Only an answer confirms a
  membership.

## Settings

| Setting | Meaning |
|---|---|
| `WS_CONTRACT_SOCKET` | The platform's socket, an absolute path. Set means the transport is configured. |
| `WS_CONTRACT_ADDR` | Development only: the platform's loopback `host:port`. |
| `WS_CONTRACT_SECRET_FILE` | The secret Wappie signs with: a THCSEAL envelope under Wappie's KMS key; in development without a key, the 43 characters in plain text. Required with the transport. |
| `WS_CONTRACT_SECRET_OTHER_FILE` | During a rotation, the other secret, also accepted on answers. May be absent on disk: no rotation is under way. Required in prod, and never the same file. |
| `WS_CONTRACT_KMS_KEY_ARN`, `WS_CONTRACT_KMS_REGION` | Wappie's own key, a full key ARN (never an alias), and its region. Required in prod with the transport. |
| `WS_CONTRACT_LOADED_FILE` | Where the server publishes what it loaded, by default `/var/lib/wappie/contract-secrets.loaded`. |

All or nothing, as object storage is: a file or a key without a transport
is refused, and so are relative paths in prod. **The secret is never a
setting**: `WS_CONTRACT_SECRET` is refused in every environment, whatever
its value. **The mode is not a setting either**: it lives in the database
([the mode](#the-mode)), so a container or a restored `runtime.env` without
these settings never reopens what the contract closed. An older binary
ignores every `WS_CONTRACT_*` variable.

## The secret

The secret is 43 base64url characters, keyed as written, and kept tier 2
(spec 4, 7.3; platform decision 0003): an envelope under Wappie's KMS key,
never plain text in `runtime.env`, a backup or a log.

**The files**, beside each other in one directory (`/opt/wappie/sealed` in
the cloud, root:wappie 0750, outside every release, so a rollback of the
release link keeps them):

- `contract-secret.thcseal`: the secret Wappie signs with (the current one);
- `contract-secret.other.thcseal`: during a rotation, the other one, also
  accepted on answers (the next one before the promote, the old one after
  it);
- `contract-secret.state`: one word, where the two stand: `steady` (the
  current file only), `next` (current is the old secret, other the next:
  the spec's 7.3 step 2 done), `promoted` (current is the next secret, other
  the old: step 3 done). No state file and no envelope is "none". While
  `promote` or `unpromote` runs it holds the swap's intent instead
  (below), which every other command reads as a disagreement.

Each is written through a temporary file in the same directory, synced,
renamed and the directory synced, 0640 in the directory's group. Both
envelopes are sealed under the same encryption context, `service=wappie`,
`env=prod`, `purpose=contract-secret`, `ref=platform`: the ref is the
secret's source, so a promote is a rename, never a reseal. A file's
**fingerprint** is the first 12 hex digits of its sha256: it names an
envelope and says nothing of the secret.

**Loading, in the server.** `serve` loads the secret lazily, in the
background: it opens Wappie's key (the kit's `awskms`, whose first call is
`DescribeKey` on the pinned ARN), opens both envelopes and checks the pair
(43 characters each, the two different). It tries at once, then every
30 seconds for ten minutes, then every five minutes. Until a load
succeeds, the contract is unavailable and fail-static (spec 7.2): nothing
is called, a returning sign-in goes on, and only a new account is refused.
A load never stops the process.

- **SIGHUP** loads both files again and swaps the client whole; calls in
  flight finish on the secrets they began with. A reload that fails keeps
  what was loaded before (ERROR "contract: secrets reload failed; the
  secrets loaded before stay in use"). `serve` takes SIGHUP as its first
  act, in every configuration, because Go's default for it is to exit,
  which systemd counts as clean and would not restart; without a
  transport it logs "SIGHUP: nothing to reload, the contract has no
  transport configured". The unit needs no `ExecReload`: the installer
  signals the main process itself, by its pid, and only after
  `whatserverd contract-secret capabilities` on the running binary prints
  `sighup` (an older binary answers any unknown command with exit 2, and
  dies on a SIGHUP) and that process has published a load of its own:
  before its first, it may still be starting, where a SIGHUP ends it too.
- **What it published.** After every load and reload, successful or not,
  the server writes `WS_CONTRACT_LOADED_FILE`, one `key=value` a line:
  `pid`, `loaded_at`, `reloads` (the SIGHUPs since it started), `current`
  and `other` (the fingerprints in use, `none`, or `plaintext` for a
  development file; a failed reload keeps the ones before it) and `error`
  (the step that failed, or `none`). The installer waits for it, with its
  own pid and fingerprints, before it calls a step done. It logs INFO
  "contract: secrets loaded" with the same fingerprints and count. A file
  it cannot write logs ERROR "contract: could not publish the loaded
  secrets; the installer will not see this load": the installer's wait then
  times out, and `--check` finds the published fingerprints unequal to the
  files' (or no load published).
- **A failure** is logged by its step (`kms`, `open`, `check`) and a closed
  class (`malformed`, `decrypt`, `provider_mismatch`, `too_large`, `unwrap`,
  `context`, `secret_shape`, `not_found`, `permission`, `timeout`, KMS's
  error code such as `AccessDeniedException`, `key_arn`, `key_refused`,
  `unexpected_response`, `unreachable`, `other`), never the error's text,
  which names the role's ARN, the account and the key. No current file is
  the step `missing`: logged once at INFO ("contract: no secret is
  installed yet; the contract stays unavailable until one is"), and no
  failure.
- **Development.** Without `WS_CONTRACT_KMS_KEY_ARN` (refused in prod) the
  files hold the secret in plain text, one line, as the platform's
  `bin/platformd export-contract-secret wappie` prints it.
- The unit dumps no core (`LimitCORE=0`): the secret is in the process's
  memory.

### The root commands

`whatserverd contract-secret` is the secret's root half. The hosted cloud
runs the subcommands that take or move the secret (`seal --slot`,
`promote`, `unpromote`, `drop`, `reset`) only through its installer
(wappie-cloud's `contract-secret.sh`), at the owner's prompt on the host,
never from a kit or an agent's session (the platform's answer of
2026-10-14). `seal --check-kms` and `capabilities` carry no secret and
write nothing: a deploy kit runs them as root, `--check-kms` as the
transport release's KMS gate. It opens no database and reads no
`.env`; of the env file it takes `WS_CONTRACT_KMS_KEY_ARN` and
`WS_CONTRACT_KMS_REGION` alone, and refuses a file that assigns either
twice. Every subcommand but `capabilities` turns core dumps off first.

```
whatserverd contract-secret seal --slot current|other --dir D --env-file F
whatserverd contract-secret seal --check-kms --env-file F
whatserverd contract-secret promote --dir D
whatserverd contract-secret unpromote --dir D
whatserverd contract-secret drop --dir D
whatserverd contract-secret reset --dir D
whatserverd contract-secret capabilities
```

- `seal` takes the secret only on stdin, from the platform's
  `platform-cli export-contract-secret wappie` in a pipe: it refuses a
  terminal, reads at most 64 bytes, trims one newline, checks the shape
  before KMS is asked anything (and, for `other`, that it differs from the
  current one, which it opens), seals, opens the envelope again to compare,
  writes the file and the state (`--slot current`: none to `steady`;
  `--slot other`: `steady` to `next`), and prints `sealed <slot>
  <fingerprint>`. An empty stdin exits `4` (`contract-secret seal: no
  input`), apart from every other failure (1), so the installer tells
  "platform-cli gave nothing" from a secret it refused. Out of turn is
  refused before stdin is read.
- `seal --check-kms` is the key end to end, in memory, nothing written: it
  opens the key, seals and opens 32 random bytes under the real context,
  and prints `kms: ok`, or names the step that failed (`kms: describe`,
  `kms: generate`, `kms: decrypt`).
- `promote` (`next` to `promoted`) and `unpromote` (`promoted` to `next`)
  first write their intent in the state file (`promoting` or
  `unpromoting`, and the fingerprint of the file the swap makes current),
  then swap the two files in one step, `renameat2(RENAME_EXCHANGE)`, so a
  crash leaves both whole, then write the state: Linux only (elsewhere they
  refuse, and the state is as before). `drop` removes the other file and
  writes `steady`, from `next` or `promoted`. `reset` removes everything
  from any state, a reinstall's first half (after a platform restore, when
  Wappie holds a secret the platform no longer has). Each prints the files'
  fingerprints as the server publishes them.
- Each refuses out of turn, and when the files and the state disagree, but
  for the one disagreement a crash inside a step leaves: `seal --slot
  other`, `promote`, `unpromote` and `drop` finish what an earlier run of
  themselves left half done, and say so on stderr (a swap's intent tells
  from the files' fingerprints whether they were exchanged already, so a
  second run never swaps them back). A current file with no state (an
  install a crash stopped) goes by `reset`.
- `capabilities` prints `sighup`: the installer's probe of the running
  binary before it signals it.

### Checking the secret: contract check

```
whatserverd contract check [--other|--only-current|--only-other]
```

One signed `GET /contract/v1/feed?after=0&wait=0` (the platform's "Checking
it"), as the service user with the socket's group, from the files the
server reads. It reads no `.env` and no database, and publishes nothing.

| Flag | Signs with | Accepts | Proves |
|---|---|---|---|
| none | current | either | the install, and after every step |
| `--other` | other | either | the platform accepts the next secret (before Wappie's promote) |
| `--only-current` | current | current | before a drop: the platform signs with the secret Wappie signs with (its step 4); before a cancel from `next`: it still signs with the old one |
| `--only-other` | other | other | before a cancel from `promoted`: the platform still signs with the old secret, which Wappie keeps as the other |

| Exit | It prints | Meaning |
|---|---|---|
| `0` | `signed answer: generation <id> confirmed <bool> head <n>`, or `signed refusal: <code>` | a signed answer this check accepts (a signed refusal proves the secret as well) |
| `3` | `unsigned 401: not the platform's secret` | the platform refuses the request's secret |
| `4` | `signed answer, but signed with the other secret, which this check does not accept` (or `current`) | signed with the secret this check excludes |
| `5` | `no answer from the platform`, with its cause (a permission denied on the socket, no socket at the path, a refused connection, a timeout), or `unsigned 429: the platform is busy` / `unsigned 503: the platform is busy` | no answer: try again, never proceed |
| `1` | anything else: `unsigned 404: the platform does not serve this caller: wappie is not mapped (PLATFORM_CONTRACT_APPS), or this process is not the wappie user`, `unsigned 401 stale_timestamp: this host's clock and the platform's differ by over a minute`, a peer that failed its checks, no such secret | a fault no retry fixes |

### Rotation

The spec's 7.3 has six steps; Wappie's are 2, 3 and 5, and the cancel.
Every step is on its own, ends with the signal and the wait for the
server's published fingerprints, and goes on only on a verified probe: a
probe that **fails** proves nothing (the socket also vanishes at the
platform's own restart after its promote), so a step never reads a failure
as "not promoted".

| Step | Files | Wappie's commands, in order |
|---|---|---|
| install | none to `steady` | `seal --slot current`, signal, wait, `contract check` |
| 2, the next secret | `steady` to `next` | `seal --slot other` (from `export-contract-secret wappie --next`), signal, wait, `contract check --other` |
| 3, the promote | `next` to `promoted` | `contract check --other`, `promote`, signal, wait, `contract check` |
| 5, the drop | `promoted` to `steady` | `contract check --only-current` must exit `0` (on `4` the platform has not promoted: finish its step 4 first, or cancel), then `drop`, signal, wait |
| cancel from `next` | `next` to `steady` | `contract check --only-current` must exit `0` (on `4` the platform promoted early: finish the rotation instead), then `drop`, signal, wait, `contract check --only-current` |
| cancel from `promoted` | `promoted` to `next` to `steady` | `contract check --only-other` must exit `0` (on `4` the platform promoted: finish the rotation), then `unpromote`, signal, wait, `contract check --only-current`, `drop`, signal, wait, `contract check --only-current`; only then may the platform run `secret-cancel` |
| reinstall | any to `steady` | `reset`, then the install |
| install, run again | `steady`, unchanged | signal, wait, `contract check` |
| 2, run again | `next`, unchanged | signal, wait, `contract check --other` |
| 3, run again | `promoted`, unchanged | signal, wait, `contract check` |
| 5, run again | `steady`, unchanged | signal, wait |
| cancel from `steady` | `steady`, unchanged | signal, wait, `contract check --only-current`; only then may the platform run `secret-cancel` |

A step that changed the files and then stopped (its signal, its wait or its
last probe failed: the server not running, a reload that failed, a wait that
ran out, no answer) has not told the platform to go on, and is run again as
it is: at the state it leaves, it changes nothing, signals and waits, and
runs its last probe (the rows "run again"). The signal and the wait are left
out when the server already published, under the pid running and with no
error, that it holds the files on disk. A cancel from `steady` is a cancel
that dropped the next secret and stopped, or one of a rotation Wappie never
took; a cancel from `promoted` that stopped after its unpromote is at
`next`, and goes on as a cancel from `next`. The installer runs one step at
a time.

`TestRotationNeverFails` plays these rules between the kit's fake platform
and Wappie's commands, with a feed call after each step: none fails. Each
step it plays runs the commands of its row above, in that order (a step a
probe refuses, up to that probe), and each flag of `contract check` signs
and accepts as the table before says.

## The mode

`contract_state.mode` is `off` or `observe` (enforce widens 0051's CHECK).
It is the database's, so every process reads the same one; each trusts
what it read for at most 5 seconds.

```
whatserverd contract mode off|observe
```

A database write only, as the service user from the server's working
directory ([contract commands](deployment.md#contract-commands)).

- **Only a server that can take part.** From `off`, `contract mode
  observe` first reads what the server published of its secrets
  (`WS_CONTRACT_LOADED_FILE`) and refuses, exit `3` with "contract mode
  observe: not ready: …" and nothing changed, unless a transport is
  configured and that file names a current secret, with error `none`,
  under a process that still runs. Once observed, a new account is refused
  `503 platform_unavailable` whenever there is no transport or no secret,
  in every mode, until 0051's down-step: a switch before the settings and
  the install would refuse every sign-up for good.
- **`off` to `observe`**, in one transaction: the mode, `events_from` set
  once (the first switch: no item event written before it is ever sent),
  the off period that ends added to `events_off`, and the round asked again.
  It then notifies every process. It prints how many events it will now
  send (undelivered from before the pause, and deletions, recoveries and
  purges written while off) and how many it holds back for good (pauses,
  strandings and moves written while off).
- **`observe` to `off`**: the leader stops at its next step, returning
  sign-ins stop subscribing within 5 seconds, and the freshness shadow
  stops. Item events written while off wait: deletions, recoveries and
  purges are sent after the return to observe; pauses, strandings and moves
  never ([events](contract-events.md#which-rows-are-sent)). The
  subscriptions stay (a held sub is never unsubscribed), so tell the
  platform, which may unmap Wappie: for the off period its two alerts fire
  (the feed silent after 10 minutes, the snapshots stale after 90), and
  after 90 minutes the console shows the protection of the people in the
  stale snapshots as unknown, and removing one of them from a platform team
  needs an owner's override (the spec's 10).
- **`off` before the first observe** (`events_from` unset) is release A:
  no call, a home of Wappie's choosing, nothing sent. **`off` after an
  observe** keeps the home rule: a new account still subscribes for the
  platform's home, and is refused `platform_unavailable` without a signed
  document. Wappie never goes back to homes of its own once it has passed
  the platform's.
- Person invitations into recorded teams stay paused at `off`.

Every process logs one line at start, after the deletion ledger's check:
`contract: mode=off transport=none secret=missing`, with the mode the
database holds (`unknown` when it cannot be read within seconds), the
transport (`socket`, `tcp` or `none`) and the secret (`loaded`, `pending`:
a file not loaded yet, or `missing`).

## Sign-in, the round and the sweep

- **The PUT at sign-in** (spec 6.1): every sign-in through id. of a person
  Wappie holds sends `PUT /contract/v1/accounts/{sub}`, while the contract is
  on, at `/v1/auth/platform/session` and after a link; a new account's at
  `/v1/auth/platform/account`, once the contract has been observed. Never
  for an unlinked sign-in that only gets a ticket. Each is bounded to
  5 seconds. Its document is stored and makes the sub fresh. A returning
  sign-in never waits on the platform: a document that is not `active`, or
  no document while the last trusted `published_through` is over an hour
  old, is logged WARN "contract: sign-in would refuse" (`reason`
  `account_disabled`, `account_closed` or `stale`), and the sign-in goes on.
  The routes, the home and the refusals are in
  [sign-in](platform-sign-in.md#the-contract-at-sign-in).
- **Intent rows.** Every PUT is preceded by its own committed statement
  that writes the sub's row in `contract_accounts` with `subscribed_at`
  now, so every subscription Wappie makes has a row the sweep can see.
- **The round** (spec 6.1, "once for every person the app holds when it
  connects"; 7.4): the leader PUTs every sub Wappie holds
  (`platform_identities`) whose row has no version of the stored
  generation, each after its intent row, at the leader's one pace: 10
  calls a second for all of the leader's calls together, the round's, the
  sweep's and both senders', which take their turns from it, so the
  leader never makes more than that whatever runs at once. Once none is
  left it records `round_generation`. It runs at the leader's start, after
  a new generation, at the switch to observe, within a minute of a GET's
  `not_found` for a held sub, and every minute once done; a pass that left
  subs is tried again after a backoff of 2 seconds doubled up to a minute.
  PUTs that keep failing for 15 minutes log one ERROR ("contract: held subs
  still have no document of this generation; their PUTs fail") and a
  `--check` finding. A `not_found` on a PUT is a platform fault, retried,
  never "closed".
- **The sweep** is the backstop: it unsubscribes every sub Wappie does not
  hold that no DELETE at sign-up removed (a refused sign-up whose DELETE
  failed or was never sent, an `already_linked` or `ticket_invalid`
  refusal's subscription, an abandoned sign-up). A sign-up refused
  `email_taken` or `workspace_conflict`, or whose document is not active, is
  DELETEd inline, once a fresh read finds the sub still not linked
  ([sign-in](platform-sign-in.md#the-contract-at-sign-in)). A row whose sub
  has no `platform_identities` row and whose last intent is over 15 minutes
  old gets `DELETE /contract/v1/accounts/{sub}`.
  On the platform's signed `{"subscribed": false}` the row is removed by
  compare-and-set on the intent it read; when that removes nothing (a
  sign-in's PUT or a link came in between), the sub is PUT again at once.
  It runs at the leader's start and every 5 minutes, at the leader's pace.
  A sub Wappie holds is never unsubscribed.

## The leader and the follower

**One leader.** Of every process on one database, only the one that holds
the advisory lock `contract` runs the background work: the follower, the
round and the sweep, the snapshot sender and the event sender. A process
tries the lock while the contract is on and its secret is loaded, every
30 seconds and at once on a mode notice. The lock is held on a connection
of its own, which is checked every 10 seconds: a lost connection ends the
leader at once, a lock that went quietly within 10 seconds, a link that
went silent within 20. A leader that lost its lock waits a minute before
it tries again, so a process that was waiting takes over first. Every
write the leader makes to the shared state is compare-and-set on what it
read, so a late commit of a stale leader changes nothing. It logs INFO
"contract: leading" when it starts; a leader that loses its lock logs WARN
"contract: the leader's lock is lost; stopping", and one that stops for the
mode or at shutdown INFO "contract: no longer leading". Sign-in PUTs and the
freshness GETs run in whichever process serves the request.

**The follower** (spec 6.3, 7.4) long-polls `GET /contract/v1/feed` with a
wait of 25 seconds, from the stored cursor.

- Only a signed page moves the cursor, and only a page that moves as the
  spec says (its `next_after` never behind the cursor; with `more`, its
  last item's seq, past it). Anything else is no page.
- A page's documents are stored when they are of the stored generation and
  newer than the row's (the revocation times always at the highest seen),
  each workspace they name recorded. They never make a sub fresh: a page
  vouches through `published_through`, which is stored only from a page with
  `more: false`, and never one past the database's clock by more than
  5 minutes (ERROR "contract: published_through ahead of the clock; the last
  trusted one is kept"). A document of a sub Wappie does not hold is stored
  but names no platform workspace. A document Wappie cannot hold (ERROR
  "contract: a document cannot be stored", or a kind that changed) is
  skipped, its sub's version forgotten so the round asks again, and the page
  commits.
- **The first page** (the first observe, or after `gone`) adopts its
  generation; so does the first answer of a sign-in or the round, whichever
  comes first.
- **A new generation or a signed `gone`** (spec 7.4) restarts the stored
  state: the generation (unset after `gone`), the cursor 0,
  `published_through` and the round unset, every sub's version and
  freshness forgotten (its document and highest revocation times kept),
  every workspace's `wversion` 0, its snapshot and queue due now with no
  accepted snapshot, every park released. Then the round PUTs every sub
  again while the feed is read from 0, side by side (WARN "contract: the
  platform's generation changed: every sub is subscribed again and the feed
  read from 0").
- **No page** (no answer, unverified, a signed refusal) moves nothing:
  backoff from 2 seconds doubled to a minute, a WARN at most once a minute,
  and after 15 minutes without a page one ERROR ("contract: no feed page for
  a long time"). The first page after a run of failures makes every
  backed-off snapshot and queue due at once, so they come back with the
  platform.
- **An early empty page** (no items, `more: false`, back in under half
  the wait it asked for: the platform shutting down, or a faulty answer)
  is a page and commits, and the next call waits the backoff's first 2
  seconds, so an answer that comes at once never makes a loop of calls.
- An answer at sign-in of another generation than the stored one is not
  stored; it wakes the leader, whose next call finds it.

## Observe's comparison

Each document newly stored (from the feed, the round, a sign-in or a GET)
is compared, read-only, with Wappie's own members (people only: not service
identities, not memberships with a deadline). One INFO line per document:
"contract observe: matches", or "contract observe: differences" with each
difference as a group `d1`, `d2`, … of ids, roles, statuses and counts.

| Kind | Meaning |
|---|---|
| `personal_mismatch` | the document's personal workspace is not the person's own personal workspace here (with how many numbers the local one has) |
| `local_only` | a linked person has a membership here in a platform workspace their document lacks |
| `no_sub` | a person in a platform workspace has no platform link |
| `platform_only` | the document names a workspace where the person has no membership here (`tenant_missing` when Wappie has no such workspace) |
| `role` | the roles differ |
| `account_status` | the document is `disabled` or `closed` and the person is active here, or the reverse |
| `membership_status` | the membership here is disabled while the document lists it |
| `team_closed` | the platform's team is closed and Wappie's is not |
| `name` | the platform's team has another name (never logged) |
| `sessions_would_end` | live sessions that began before the document's `sessions_revoked_at` |
| `credentials_would_stop` | API keys, connections and standing service accounts created before its `credentials_revoked_at` |
| `unnamed_tenant` | (`contract diff` only) a team here that no document names |

```
whatserverd contract diff [--tenant T]
```

recomputes every difference from the stored documents and Wappie's tables,
one line each, by ids, roles and counts, then `N differences`; with
`--tenant`, only those that name that workspace. It is what enforce would
change.

## Freshness

A sub is **fresh** while the later of its last validated document (the
answer to a PUT or a GET, of the stored generation, whatever its version)
and the last trusted `published_through` is under an hour old, on the
database's clock (spec 7.1). `published_through` counts only for a sub the
platform follows in the stored generation. A signed refusal of any code
(`unavailable`, `rate_limited`, `replay`, `not_found`, `invalid_request`)
and an unverified answer confirm nothing. A GET's `not_found` for a held
sub forgets its version, and the round PUTs it again.

**The hooks.** Every act the spec's 7.1 gates asks before its store
transaction, never inside one (a GET never runs inside a write
transaction):

| Hook | Where it gates | What it asks |
|---|---|---|
| `RequireFresh` | an act on a team's number, in a recorded team | each party fresh, or a GET (`IfStale`, `Always`); `Stored` reads the stored freshness only, with no call |
| `RequireWidening` | an act that widens access, in every recorded workspace | in a team, as `RequireFresh`; in a personal workspace, the actor's own stored status only, with no call |
| `RequireBackups` | an act that narrows who holds a number's key, in a recorded team | the minute rule: a remaining key holder counts as a backup only on a document that is active, lists the team, and is fresh within a minute as stored or comes from a GET; holders left and none confirmed is a would-refuse (`no_confirmed_backup`) |
| `RequireMover` | a move out of a team | the mover's document from a fresh GET, listing them as the team's owner with an owner count of 1 (decision 0043) |

| Act (its name in the logs) | Hook | Parties |
|---|---|---|
| `device.delete`, `device.recover` | `RequireFresh` | the owner, `IfStale` |
| `device.stop` by a person | `RequireFresh` | the person, `IfStale` (an API key's stop is never gated) |
| `pair` | `RequireFresh` | the person `IfStale`, each other account the pairing's grants give the key to `Always` (a key's pairing is never gated) |
| `device.transfer.preview` | `RequireFresh` | the mover, `Stored` |
| `device.transfer` | `RequireMover` | the mover, once the preview finds the move possible |
| a person's sends and group administration (every frame that needs Send but `calls.list`, and `group.create`, `group.participants.update`, `group.leave`, `group.join`) | `RequireFresh` | the person, `Stored`, in the background |
| `mcp.send` | `RequireFresh` | the consenting person, `Stored`, in the background |
| `grant.add` | `RequireWidening` | the actor `IfStale`, a person recipient `Always` |
| `apikeys.create` | `RequireWidening` | the actor, `IfStale` |
| `permission.raise` | `RequireWidening` | the actor and the recipient, `IfStale`, when a flag goes from false to true |
| `service.invite`, `service.signup` | `RequireWidening` | the inviting person, `IfStale` |
| `mcp.connect`, `mcp.token`, `ai.connect` | `RequireWidening` | the person, `IfStale` |
| `mcp.renew` | `RequireWidening` | the person, `Always` |
| `grant.revoke`, `permission.withhold_read` | `RequireBackups` | the number's other key holders |
| the console's `item.sync_stop`, `item.sync_resume` | `RequireFresh` | the actor, `IfStale` |
| the console's `item.flags_raise` | `RequireWidening` | the actor and the target, `IfStale` (a target not active locally is `not_found` before it) |
| the console's `item.flags_drop` of read, `item.access_remove` | `RequireBackups` | the number's other key holders, when the target reads the number or holds its key |

- **Parties.** Only a member of the workspace who is a person counts: a
  service identity, a membership with a deadline or a connection's account
  is left out before any read or call. A party with no sub, a stale
  `Stored` party, a party whose GET got no document, and a document that is
  not active make the verdict a refusal.
- **Calls.** An act's GETs run at once, at most 4 in flight, within one
  5-second bound, and each first takes a token from the process's budget
  (10 a second, bursts of 20) and its workspace's (5 a second, bursts of
  20): one that would not get them in time is `throttled`, with no call. A
  late answer is still stored. With the leader's 10 a second, that is 20
  calls a second, 40 in a second that starts with the budget full, under
  the platform's 50 for all of an app's calls, sign-ins and the feed
  included.
- **The hot paths** never wait: a send's or a group act's check runs in
  the background on the stored freshness, at most once a minute per
  session, act and number (per connection and number for `mcp.send`). Two
  bounds, each per process, keep them few: at most 16 at once for the
  socket's sends and group acts, and 16 at once for `mcp.send`; the rest
  are skipped. They make no contract call.
- **The step-up's GET.** After a step-up at id., a stale person's document
  is asked for, so an act right after it finds them fresh; its failure
  changes nothing.
- **At observe nothing is refused** (the owner's decision, 2026-10-14): a
  verdict is logged WARN "freshness: would refuse" (act, workspace, user,
  sub, reason: `no_sub`, `account_disabled`, `account_closed`,
  `refused:<code>`, `unverified`, `unavailable`, `throttled`, `not_stored`,
  or `no_confirmed_backup` with each holder's), a `Stored` party's
  staleness INFO "freshness: stale at act", a mover's verdict WARN
  "transfer: would refuse" (`no_document`, `not_a_member`, `role_<role>`,
  `owners_<n>`), and the act goes on, a failure to read included. Enforce
  answers a refusal with `memberships_unconfirmed` (503 over HTTP, with
  `Retry-After: 60`; the socket's error code) and changes nothing.
- The local sole-owner check of a move, and every other refusal of
  Wappie's own, decide as before ([moving a number](device-personal-transfer.md)).

## Access snapshots

For every recorded platform workspace, personal ones included, the leader
sends `PUT /contract/v1/workspaces/{id}/access` (spec 8), an absolute
snapshot of what Wappie's own tables say, measured in one REPEATABLE READ
transaction with the database's clock, which first takes its
`snapshot_seq` under the workspace's record and then reads, read-only
(DS3). A workspace Wappie has no
workspace for gets an empty one (`"items": []`): the console counts a
missing snapshot as unknown protection.

- **Items** are the workspace's numbers with a known identity or a past
  connection (a pending registration is none), deleted ones until their
  purge, by id, `kind: "number"`, with the contract's `label` and `hint`
  ([the label rule](contract-events.md#labels-and-hints)).
- **State and reason**, the first that holds: `deleted` (with `purge_at`,
  its `purge_after`); `sync_paused` with `needs_reauth` (logged out, until
  it is [linked again](devices.md#linking-a-number-again)),
  `error` (banned, or a workspace that is not active), `quota` (the
  workspace's storage refuses capture: its stop recorded, 105% of its limit,
  or its 72 hours of grace spent), `by_person` (a person's or a key's stop,
  or an owner's recovery, `devices.pause_cause` `person`), or `error` for
  any other pause (Wappie's own, around a move); else `active`. A paused
  number is never `active`. A number nobody can read is `active`: Wappie
  does not pause capture for it.
- **People**, by sub (a person with no platform link is never listed):
  everyone with a permission row or a key at an epoch not retired. `can` is
  their stored flags (`read`, `send`, `manage`); `reads` is Read, a key at
  the current epoch, an active membership with no deadline passed and an
  active account, whatever the workspace's status; `waiting` the same
  without the key yet; `holds_key` a key at any epoch not retired; and
  `enrolled` is always true (a person exists here only after the sign-in
  that pins their key).
- **`protected`** is Wappie's own rule, the one that refuses removing or
  disabling them: the subs whose key is the number's last recoverable one
  (the SQL function `sole_key_holders`, which the removal's refusal reads
  too). A suspended person, whose account is disabled while their
  membership stands, is protected as an active one is (Wappie's reply of
  2026-10-14; the platform's verdict ignores the account's status); only
  an active person counts as their backup. **`other_backups`** counts the
  holders without a sub the rule counts as a backup: standing service
  accounts and people never linked to the platform. A deleted number is
  reported as it was live until its purge, its readers, holders and
  `protected` included (platform decision 0044).
- **Limits.** At most 1000 items, 5000 people on an item and a 1 MiB body,
  and the kit's validation (labels and hints as the platform's strict
  intake checks them). A snapshot past them is not sent (ERROR "contract: a
  workspace's snapshot is not sent: Wappie would not send it"), recorded
  `local_invalid:<rule>`, and retried with the backoff.
- **`snapshot_seq`** is the greater of the measurement's milliseconds and
  the last one numbered plus one (which may be one whose send failed), or
  the workspace's last section's plus one, stored before the send, so it
  rises across leaders. It is taken first in the snapshot's own measuring
  transaction, under the workspace's record, as a section's is (DS3): an
  act that holds the record (a rename, a stop, a resume) makes the
  snapshot wait and measure again, so a snapshot at or above an act's seq
  always shows it. A read that meets the record busy tries again after a
  short random pause, up to eight times, before it counts as a failure.

**When.** At the leader's start, every recorded workspace (and every park
released for one try); 2 seconds after the first of a run of changes the
snapshot shows (a number's state, label, identity or deletion, a
permission, a grant, a membership, a person's status, a new platform link,
the workspace's status or storage stop: 0051's triggers notify the leader
at each commit); at once after a document that changes the workspace's
members or names it first; and 55 minutes after the last accepted one, so
a snapshot is never an hour old. One sender, in the order they are due, at
the leader's pace.

**Outcomes.** `{"accepted": true}` resets its backoff. A signed `not_found`
is retried with the backoff for 24 hours, then the workspace's snapshots
are parked (ERROR "contract: a workspace's snapshot is parked") until a
document names it again, a restart or a leader's start. A signed
`invalid_request` parks it at once (a Wappie bug), until a restart or a
leader's start. No answer, an unverified one or another refusal: 5 seconds
doubled with each failure, up to an hour. Each accepted snapshot logs, at
most hourly per workspace, INFO "contract: snapshot labels": how many of
its labels fall in each class (named, phone, placeholder, legacy id,
empty), never a label.

## Events

The leader sends the platform `POST /contract/v1/events` (spec 9), rendered
at send time from release A's `item_events` rows: one queue per platform
workspace, in `seq` order, delivered only on a signed `accepted` or
`duplicate`. The shapes, which rows are sent, the coalescing of pauses, the
outcomes, parks and the 29-day expiry are in [contract events](contract-events.md).

## Settings and commands

The platform's console draws Wappie's settings pages from documents Wappie
sends, and passes on the changes a person makes there as commands (the
spec's section 14; platform decision 0054; kit v0.10.1's `SettingsDoc`,
`Command`, `CommandFeed` and `CommandResults`). Step 12a ships it in two
releases. The first, **read**, sends every recorded platform workspace's
`numbers` section with `accepts: []`, so the console offers no button,
follows the command feed, keeps every command it takes in a ledger, and
answers each one `kind_not_accepted`. The second, **commands**, adds every
followed person's own document and, in the mode `on`, runs the `numbers`
kinds and the person's two ([the kinds](#the-kinds)).
The decisions are DS1 to DS17 in [decisions](decisions.md#the-contracts-settings-part-2026-11-08);
migration 0052 holds the schema of both releases. Step 12b adds the
console's three flags kinds with no migration (release R3, `flags-pilot`;
DS18 to DS25 and DS46 in [decisions](decisions.md#the-consoles-flags-kinds-2026-11-09)).

### The settings mode

`contract_settings_state.mode` is `off`, `read` or `on`, apart from the
contract's own mode (DS2):

```
whatserverd contract settings off|read|on [--platform-told]
whatserverd contract settings status [--check]
```

- `read` and `on` need the contract on (`contract settings: the contract is
  off; settings follow it`, exit `3`). `contract mode off` turns settings
  off in its own transaction, and says so (`settings: off with it`), and,
  once the feed was read, that the platform watches it (`… since …: tell
  it`); with settings off already it says neither, the platform being told
  when they went off.
- From the first read of the command feed the platform watches it for good
  and alerts after 10 minutes without one (`contract_commands_silent`). So
  the first switch that follows the feed, and `off` once it was read, need
  `--platform-told` (exit `4` without it, nothing changed; DS16). Tell the
  platform first.
- `read` lists no kind in any `accepts`, and answers every command
  `kind_not_accepted`; `on` lists the kinds this binary runs (`item.rename`,
  `item.sync_stop`, `item.sync_resume`, `item.sync_now`,
  `item.registration_delete`, `item.flags_raise`, `item.flags_drop` and
  `item.access_remove` in `numbers`; `person.notices_dismiss` and
  `person.sign_out_everywhere` in the person's document) and runs them.
  There is no switch per kind: a binary lists the kinds it runs from its
  start, so the platform is told before a release that adds kinds (DS46). A switch makes every section and
  person document due at once, with the new `accepts`: in its own
  transaction, and again once the leader's watcher holds the new mode, so
  a document measured in between, and sent with the old `accepts`, goes
  again (INFO "contract: settings switched"). The way back from
  `on` is `read` (no button is left that Wappie refuses), before any older
  binary.
- The leader's watcher reads the mode at its start, every 5 seconds and at
  each mode notice, and starts or stops the settings part's four loops: the
  section sender, the command follower, the executor and the results
  poster (INFO "contract: settings started", "contract: settings
  stopped"). A mode this binary does not know reads as `read`.

### The numbers section

Each recorded platform workspace's `numbers` section
(`PUT /contract/v1/workspaces/{id}/settings/numbers`, the kit's
`NumbersSettings`), measured in its own transaction after it takes its
`state_seq` on the workspace's one clock, shared with the snapshot (DS3):

| Member | From |
|---|---|
| `state_seq`, `snapshot_seq` | `contract_workspaces.sections_seq` (the greatest of the clock in milliseconds and both columns plus one), and the last snapshot numbered; a workspace with no snapshot numbered yet sends no section |
| `truncated` | a list over its bound (`pending` over 50, `items` over 1000) goes empty with `truncated`, never cut |
| `accepts` | `[]` in `read`; in `on` the eight `numbers` kinds of [the kinds](#the-kinds) |
| `can_link` | the workspace active, below its capacity as `check_device_capacity` counts it (a deleted number takes no place), and not stopped by its storage |
| `places_free` | `null` until entitlements reach Wappie |
| `storage_paused` | the snapshot's quota verdict |
| `pending[]` | registrations with no identity, never connected, not deleted, newest first; `pairing` is the leader's registry's pairing, `can_retry` true when the registry neither pairs nor holds it and it has a key (DS8) |
| `items[].connection` | `pairing`, `online`, `offline`; `logged_out_phone` or `logged_out_deletion` by `devices.logout_cause` (DS6); `banned`; a deleted number `logged_out_deletion`, or `banned` |
| `items[].capture` | `paused` when the number is paused or deleted, else `on` |
| `items[].paused_by` | `{kind, sub, at}` from `devices.paused_at`, `paused_by_kind` and the sub of `paused_by_user`; `null` whenever the time or the actor is not known (DS7) |
| `items[].can_resume` | paused, not deleted, its identity known, not logged out or banned |
| `items[].read_only` | logged out, banned or deleted, or no identity stored (it connected for a pairing that never linked, or, rarely, Wappie failed to save the identity of one that did: no session Wappie could start from what it stored, so its sync now is `not_linked`, and a pause of it could not be lifted from the console; DS12) |
| `items[].key_epoch` | the number's epoch, `null` for 0 |
| `items[].recovery_open` | deleted, its purge ahead and not started |
| `items[].move_out`, `items[].bytes` | `null` |

A row carries no label: a number's label lives in the access snapshot. The
rows are the snapshot's numbers (a known identity or a past connection),
deleted ones until their purge, joined to its items by id. The data is
encoded with no HTML escaping, and every document passes the kit's
`Validate` before it goes. A row the wire refuses is left out and the
section goes `truncated` (the spec's 14.2, "A row the wire refuses"), with
an ERROR once per run (`section_invalid`): no row of the database makes
one, only a bug of Wappie's. A section that still fails (with no row at
all, an item twice, or over the call's limit) is recorded
`local_invalid:<why>` and logged at ERROR once per run, never sent.

**Cadence** (the spec's 14.2; DS12): within 2 seconds of a change a
section shows (0052's triggers on its own channel, `wappie_contract_settings`,
and every payload of the snapshot's dirty channel, members included),
within 30 seconds of a connection that only flipped between online and
offline, at once after a reset, at the leader's start, when the pairing
look (every 10 seconds) finds a pending row's pairing changed, and 55
minutes after its last accepted one. A workspace recorded after the leader
started gets its row at once, and its first section within the pairing
look of its first snapshot. Outcomes are the snapshot's: `not_found` is
retried and parks after 24 hours, `invalid_request` parks, anything else
backs off from 5 seconds doubling to an hour; a park is released at the
leader's start. After an outage the sections come back with the platform,
as the snapshots do with the account feed: the command feed's first page
after a failure makes every section that backs off due now, its tries
forgotten (`contract: failing sections due again`). A section is sent for
every recorded workspace whose snapshot is numbered, a parked snapshot's
included: its own `not_found` run and park stand for it, and a snapshot
Wappie's check refused does not hold back a section the platform takes.
A binary sends only the sections it renders (`numbers` today): a row of
another section, which a later binary added (`mcp`, `integrations`), is
never picked, so after a rollback the older binary never loops on it
(DS25).

### The command feed and the ledger

The leader long-polls `GET /contract/v1/commands` with one request at a
time (a wait of 25 seconds), from `contract_settings_state.feed_cursor`
under the one generation the account feed adopted; the next request's
`after` is the acknowledgement, sent only once the page is committed. A
page that is not one the spec describes (its `next_after` behind the
cursor, a command at or before the cursor or past `next_after`, or `more`
not ending at its last command: one that would be asked again with its own
commands), or no answer, backs off from 2 seconds doubling to 20. A reset
of the account side between the follower's read of the state and its
request is not lost: the follower reads the state again first.

Each command of a page is decided in the spec's order (DS5): a body that
is not one well-formed object the kit can canonicalize, that names another
app, or whose MAC holds under neither the current nor the other secret
(each written to the security log as `contract_command_invalid`, naming no
person: the command's id, its cseq and why); a command of another
generation than its page (`invalid_command`, an ERROR, never a reset); one
whose MAC holds but that does not decode as a command (the platform signed
it: `invalid_command`, not a forgery), one the kit's `ValidateIn`
refuses for its workspace's kind (a workspace no document named with
`Validate` alone), or whose cseq is not its item's (`invalid_command`); one
issued over 30 days before the page was signed, unless delivered again, or
carried after its `expires_at` (`expired`); one whose `wseq` the memory has
passed with another id (`invalid_command`). Each is answered in the page's
transaction. A command refused before `ValidateIn` passed keeps no decoded
field, and an item whose id is no UUID gets no row: a malformed command
never blocks the feed. The id is the `id` member named exactly, as the kit
reads the command it verifies: an `ID` or `Id` beside it names nothing.

The ledger (`contract_commands`) keeps each command as received, its MAC
its proof, exactly 30 days from its take (decision 0056; 720 hours,
whatever the session's time zone and its daylight saving time): every read
ignores an older row, the leader trims every 5 minutes and every process's
maintenance hourly (DS4). A command delivered again with the same body
(its canonical form without `generation`, `cseq`, `secret` and `mac`) is a
replay: its result is posted again. Another body under the same id, from a
copy whose MAC holds, refuses an open row `invalid_command`; a forged copy
only reaches the security log.

**The executor** runs one row at a time, in take order, one open row per
workspace and producer. In `read` it answers every row `kind_not_accepted`
(R0) with the seq it was judged on; in `on` it judges and runs the kinds
below ([the kinds](#the-kinds)). A run that fails with a store error waits
from 5 seconds doubling to a minute, holding back only its own workspace
and producer, and after 5 tries is answered `rate_limited` (`retry_after`
60) with an ERROR.

**The results poster** posts the results not delivered
(`POST /contract/v1/commands/results`), at most 100 a call under 256 KiB,
at the round's pace, after dropping those of an old generation's commands.
Each is checked as the platform reads it first (the kit's `ValidateFor`
with its command's kind, `Validate` alone for a row with none); one that
fails is parked `local_invalid`, never sent, with an ERROR. `accepted` and
`duplicate` deliver it; a rejection parks it (`invalid_request` with an
ERROR; `not_found` and `conflict` are logged). No answer backs off from 2
seconds doubling to a minute, and so does a park or answers the ledger
cannot store, before the rows are read again.

**A reset.** A signed `gone` on the command feed, or a page of another
generation, resets the account and command state in one transaction: the
feed from 0, the `wseq` memory forgotten, the results not delivered of the
old generation's commands dropped, every section due afresh; then the
account long-poll is cut and the round kicked. At most one reset a minute
starts from the command feed: a second within the minute waits it out,
logged at ERROR and recorded `command_reset_loop` for `--check` (the
platform's two feeds on two generations, or a `gone` that lasts, would
reset everything once a minute). A reset that finds the generation moved
under it (another came first) resets nothing and starts no wait. A reset
of the account side cuts the command long-poll the same way.

### The kinds

In the mode `on` the executor judges each row in this order, the first
check that fails answering it with the seq it was judged on (DS5, DS15):

1. its kind is one this binary runs for its section in this mode, and
   Wappie's producer's (`kind_not_accepted`);
2. its actor is followed with a document, and linked to a local account,
   and so is the person a flags kind's target names, whether or not
   `based_on.docs` names them (`not_held`; a person's kind with no seq);
3. every document it was drawn from is applied: `based_on.docs` at most the
   stored version of the current generation (`memberships_behind`,
   `retry_after` 5, the behind retry);
4. for a workspace's kind, the workspace is recorded, Wappie's, and open
   (`not_found`, `team_closed`; judged again in the act's transaction,
   which holds the record, so a closing stored in between, by the
   freshness below for one, is `team_closed` too); then, for
   `item.flags_raise`, a read-only look at its target: an active,
   unexpired membership here, an active local account, and a stored
   document `active` with no later disablement seen than its own, else a
   final `not_found` before the freshness, so a suspended person is never
   answered `memberships_unconfirmed` (the platform's Q6; the act checks
   the membership again);
5. the freshness the kind asks (only logged at observe;
   `memberships_unconfirmed` with enforce): `item.sync_stop` and
   `item.sync_resume` the actor's in a team, as the socket's stop asks it;
   `item.flags_raise` the actor's and the target's in a team, and the
   actor's own stored status in a personal workspace, as Wappie's screen
   asks a raise (`RequireWidening`); `item.flags_drop` of read and
   `item.access_remove`, when the target reads the number or holds its
   key, the minute rule for its other key holders, in a team
   (`RequireBackups`, as the screen asks withholding Read); a drop of
   send or manage asks nothing (DS23);
6. then the kind, in one transaction: its target first (a deleted number,
   another workspace's, or an id that is none of Wappie's: `not_found`, as
   on Wappie's own screens), then the actor's local role and the stored
   document's role, both (`not_authorized` where they differ), then
   `params.before` against the value Wappie publishes, then the act, its
   result at the act's seq, and the documents it shows in due at once.
   The flags kinds differ (DS19, DS21, DS22): `item.flags_raise` answers
   a deleted number of the workspace `state_changed`, and a target who is
   not an active member here `not_found`, before the roles;
   `item.flags_drop` and `item.access_remove` run on a deleted number of
   the workspace, never compare `params.before` with the stored flags (a
   drop takes `before \ after` from them), and answer `ran` for a person
   with no membership row, after the roles.

| Kind | Local rule (Wappie's screens) | Document's role | Refusals of its own | Runs as |
|---|---|---|---|---|
| `item.rename` | Manage (owner, admin, or the Manage flag) | owner or admin; member only with the Manage flag | `state_changed` (`before` is not the label the snapshot publishes), `not_authorized` (a label Wappie sets aside, as typed or as cleaned: a placeholder, an id, the number's own digits; nothing stored, DS10), `label_changed` (with the cleaned label) | `device.rename`, which stores a label set aside where the console's rename refuses it (DS10); the snapshot is due too |
| `item.sync_stop` | owner or admin by role | owner or admin | none: a paused number counts as done | `device.stop`: readers told, the event written, the pairing cancelled, the number stopped, its status broadcast, the notices pushed; `paused_by` names the actor |
| `item.sync_resume` | owner or admin by role | owner or admin | `state_changed` (not paused, or a number that cannot run: no identity, logged out, banned) | `device.start` on a paused number, a move's pause included; its pause notices marked resumed in the lifting transaction; a start that fails, or runs past the start bound, keeps the pause lifted, and the supervisor starts the number (DS9) |
| `item.registration_delete` | owner or admin | owner or admin | `state_changed` (it linked) | `device.delete` of a registration: its pairing cancelled and stopped first, the row deleted |
| `item.sync_now` | Read, for a person, as the socket's own sync now asks it (a key keeps Manage) | any role | `paused`, `storage_paused`, `not_linked`, `read_only`, `item_busy`, `connect_failed` (a start past the start bound too), `rate_limited` within the failed start wait (no start) | `device.start` on a number not paused (DS13): an owner or admin who does not read the number may not |
| `item.flags_raise` | owner or admin by role; an owner's flags only an owner's (Q58) | owner or admin; an owner's flags only an owner's | `state_changed` (`before` is not the stored flags, compared as a set; or the number was deleted since), `not_found` (the number gone or another workspace's; the target not an active member here) | `PUT …/permissions` with flags added: the flags written, never a key; `grant_needed` is never answered (send and manage need no seal, and the kit refuses a raise of read); the snapshot is due too |
| `item.flags_drop` | as the raise | as the raise | `last_reader` (the number, a deleted one included, would be left with no reader) | the flags `before` has and `after` has not are taken from the stored ones, so one raised since stays; a drop of read deletes every grant of the person on the number at every epoch, even when the flag was already gone; when Read goes or no flag is left (a drop of send or manage that takes the last one, with Read gone already, too: it deletes no grant), it ends whole (`access_lost`) every MCP connection of the person, metadata or content, and every AI integration they created that held the number, one holding other numbers too, and tells their readers after the commit (DS47, the platform's 0061); it runs on a deleted number of the workspace (DS21); a person with no membership row at all is `ran`, a suspended one's flags and grants go all the same (DS22) |
| `item.access_remove` | as the raise | as the raise | `last_reader` | every flag false with the row kept, so a key shared later gives no read or send; every grant of the person on the number deleted, a key holder's without read too; the person's own MCP connections and AI integrations that held the number end whole, as a drop of read's (DS47); the number and the membership as the drop's (DS20) |
| `person.sign_out_everywhere` | the actor | the actor | none | every session family of the actor begun before `issued_at` ends, its workspace sessions with it (the sockets close within a second), never a later one, an API key, an MCP or AI connection; `sessions_ended` counts the live sessions ended (DS11) |
| `person.notices_dismiss` | the actor's own notices | the actor | `state_changed` (a pause notice whose version rose stays; every other one is dismissed) | Wappie's own "seen", at the version shown |

**The flags kinds** (step 12b, DS18 to DS24, DS47) run on the write Wappie's
own permissions screen makes (`setDevicePermissionTx`), so the two agree
by construction, and `TestConsoleParityFlags` and
`TestConsoleParityOwnConnections` hold them to it. They
differ where the console's rules do: drop and remove run on a deleted
number, which the screen does not find (DS21), and a raise never touches
a key, where the screen's PUT without Read deletes a dormant one. Wappie
keeps no time per flag, so a drop retried late may undo a raise made
since on Wappie's screen (the owner's Q7), and its tightenings never
answer `state_changed`. Only an owner, by the local role and the
document's both, changes the flags of an owner (local, or named owner
by their document): an admin is `not_authorized` here and 403
`not_authorized` on Wappie's own screen (the owner's Q58); `grant.revoke`,
which changes no flag, keeps its own rule. When Read goes (the stored
row had it: a drop of read, a remove, the screen's PUT without Read) or
no flag is left (a remove, the screen's PUT with every flag false, a
drop of the last flag left, send or manage, which deletes no key),
every live MCP connection the person consented to (metadata or content)
and every AI integration they created in the workspace that held the
number ends whole, `access_lost`, in the same transaction, also one that
holds other numbers (the owner's Q8 and the platform's decision 0061,
DS47): its key revoked, its drafts still waiting revoked, its service
account removed with its permissions and grants on every number. Its
reader is told after the commit as a revoke tells it (best effort; the
reader's 30-second re-tell is the backstop), and the person consents
again for the numbers they still read. Another person's connections,
workspace API keys and legacy MCP tokens keep the number. A change that
keeps send or manage while Read was already gone (a raise, a drop of the
other) ends nothing, on the screen as in the acts, and nor does a
refusal (`last_reader`, an admin on an owner). A connection already live
whose person has no Read on a number it holds (given before 0061, or
left by a lost Read before F3 or a lone `grant.revoke` before F4) ends
once, at the upgrade, whole and `access_lost`, its readers told; a
person waiting for a rotated number's new key keeps theirs (DS48). That
sweep is built and tested, and no start runs it until its once-marker is
chosen; until then such a connection ends when their access there is
removed (a remove, or their last flag going), on the number's deletion
or move, on a revoke or at its expiry (DS47). Every consent, metadata
included, and every renewal must name only numbers its person reads at
that moment (the flag and a grant at the current epoch): one prepared
before their Read went and recorded after is refused (`key_unsuitable`,
HTTP 422). A `grant.revoke` alone, which leaves the Read flag, counts as
Read taken away when the person has the flag and it leaves them no
grant at the number's current epoch (0061): in its transaction it ends
their connections that held the number the same way, and their readers
are told after the commit. A rotation of the number's key, a grant
replaced in the same transaction and a dormant grant's revoke (no Read
flag) do not count (DS48). After a `ran` that wrote, this process's
sockets check their access at once; the others within their access
loop.

The runners live in `internal/numberacts`, beside the relink, and reach
the socket server through `internal/wsapi/console_hooks.go`; parity tests
hold each to its frame. Every kind reads its number by the command's
workspace as well as under the workspace's row-level security. A start
(a resume's, a sync now's) waits at most the start bound for its number
to connect: the executor runs one row at a time for every workspace, and
a connect that keeps failing would hold the others for a minute and a
half. A sync now is any reader's, so after its start of a number fails,
a sync now of that number within the failed start wait starts nothing:
it is answered `rate_limited`, `retry_after` the seconds left, and the
platform issues it again then. A store error that is no verdict backs the row off (the run
backoff), holding back only its workspace's and producer's later rows;
after 5 tries it is answered `rate_limited`. The results go as in the
read release.

**Delivered again.** A tightening delivered `again` (after Wappie's own
restore: `person.sign_out_everywhere`, `item.flags_drop` and
`item.access_remove` among the kinds this binary runs) is never answered
with a retry. The platform keeps its first result,
takes the same outcome and code as a duplicate and any other as a
conflict, and never issues it again, so a retry would leave undone what
the tightening took away. Where a check would answer it with one (a mode
that does not run it yet, a document not yet applied, a team closed) or a
store error keeps failing, it waits the run backoff instead, its class
`again_` and the code (or the store error's), and is judged again until it
runs: `--check` shows it among the commands retrying, and at the fifth try
WARN gives way to one ERROR ("contract: a command delivered again keeps
waiting", recorded `command_stuck`). A kind this binary never runs is
answered as any other.

**The person's document** (`PUT /contract/v1/accounts/{sub}/settings`,
the kit's `WappiePersonSettings`), for each sub Wappie follows with a
document that is not closed, sent by the section sender on the person's
own clock (`contract_persons.seq`), as a section is sent (DS12):

| Member | From |
|---|---|
| `accepts` | `[]` in `read`; in `on` the person's two kinds |
| `signed_out_everywhere_at` | the latest `issued_at` of a `person.sign_out_everywhere` that ran |
| `notices` | the person's unseen notices of the platform workspaces where Wappie lets them in (the membership, the account and the workspace active, the membership not expired), never a local-only workspace's, the newest 300, as Wappie's own page lists them; with more, the document is `truncated` (a list cut to fit, the spec's 14.2), with no ERROR |
| `notices[].id`, `version` | the row's id in decimal; the pauses folded in for `sync_paused`, else 1 |
| `notices[].label` | the label stored with it; one stored before the label cutover only when today's rule gives the same text of the number now, else `null` |
| `notices[].params` | `actor` the sub of who raised it, `null` for someone with none, never a name |

A notice the wire refuses is left out and the document marked
`truncated`, with an ERROR once. It is sent 2 seconds after one of the
person's notices changes (raised, seen, resumed or deleted), a change in a
workspace where they hold an unseen notice (a membership disabled hides
them all), or a change of an account's status (everyone's), at once after
one of their acts, at the leader's start and at a switch between `read`
and `on`, and 55 minutes after its last accepted one; `not_found` parks it
after the person not found time. An act makes the documents it shows in
due at once, a parked one too, for one try, or the console would never see
it shown. Before each, and in every process's hourly maintenance, a pause
notice whose number has been unpaused for the resume repair time is marked
resumed when its frame's mark was lost (DS17); a workspace with none to
mark takes no lock for it. The time is beyond the frame's own resume,
which may retry its connect for a minute and a half and then put the pause
back.

### contract settings status

Prints the mode, the command feed's cursor, first and last read and a
failing run's class, the results' failing run (while a result is not
delivered: only an answered post clears it), the last `invalid_command`,
the label cutover, the ledger's results over 30 days by outcome and code,
its open, retrying, undelivered and parked rows, each section: its
workspace's status, seq, last accepted, due time, failing run, `not_found`
run and park, and how many person documents are accepted and parked. `--check` adds the settings findings below, which
`contract status --check` reports too.

## Person invitations into platform teams

In a team a platform document names (a `contract_workspaces` row of kind
`team`), person invitations (owner, admin or member) are neither issued nor
redeemed (the owner's decision, 2026-10-14): its people join through The
Happie Co, and until Wappie applies the platform's members (enforce) an
invitation there would add someone the platform does not know.

- Refused with `409 invitations_paused`: `POST /v1/auth/workspaces/invites`
  for a person, `POST .../invites/{id}/regenerate`, accepting a pending
  invitation (`POST /v1/auth/workspaces/accept-invite`) and an invited
  sign-up, and the operator's `whatserverd invite` ("invite: this team's
  people join through The Happie Co; person invitations are paused here
  until Wappie applies the platform's members (a service invitation still
  works: -role service)"). A redemption is refused before anything is spent:
  the code stays valid.
- **Service invitations stay open**, provisional ones included: they are
  Wappie's own integrations.
- **The record is the key**, in every mode, with or without a transport:
  neither a configuration nor a return to `off` reopens them. Only the
  0051 down-step, which drops the record, does
  ([rolling back below 0051](deployment.md#rolling-back-below-0051)).
- Personal workspaces and teams no document names are unchanged.
- `contract status` prints the pending person invitations of each team
  here, `open` or `paused (a platform team)`.

## The owners' acts

Two acts tell the other owners, through the platform's mail, from the
events above (spec 9.1):

- **The strand override** ([workspaces](workspaces.md#phase-2-membership-management-and-live-revocation)):
  an owner may remove or disable the last key holder of a deleted number
  anyway (`strand_deleted`), only where the platform mails the other
  owners: while the contract is on, in a recorded team that is not closed.
  Anywhere else the flag changes nothing. Each number stranded writes an
  `item.stranded` event and the other owners' `number_stranded` notice.
- **A move to Personal** stays the team's only owner's, when nobody else
  has access to the number (decision 0043). Its `item.moved_out` mails the
  team's other owners, who are none unless one joined between the check
  and the event; they get a `number_moved_out` notice as well.

## contract status

```
whatserverd contract status [--check]
```

Reads the database, what the server published of its secrets and the
sealed files; never calls the platform. It prints:

- the mode and since when, the transport;
- `secrets (server)`: the server's published load (pid, `loaded_at`,
  reloads, fingerprints, error), beside `secrets (files)`: the state file
  and the files' fingerprints;
- the generation and whether it is confirmed, the cursor, the age of
  `published_through`, the feed's last page and a failing run's class;
- the subs held and followed, the subscriptions, the round (`done` or
  `pending`), a failing run of PUTs, and the last ERROR's class;
- each platform workspace: its kind and status, when it was named, the age
  of its last accepted snapshot, its events pending, parked and coalesced,
  and its parks and failing runs;
- the pending person invitations of each team here.

No name, no email, no label, no secret.

**`--check`** adds one `finding:` line per finding and exits 1 when there is
any (0 otherwise). The findings while the contract is on count each bound
from the later of its own time and the last switch of mode, so a switch is
clean until its bounds pass:

- `a contract ERROR in the last day: <class> at <time>`: one the leader
  recorded with an ERROR line (the `wappie` user cannot read the system
  journal). Its classes: `feed_silent`, `published_through_ahead`,
  `document_invalid`, `kind_changed`, `round_incomplete`, `snapshot_parked`,
  `snapshot_invalid`, `event_parked`, `events_refused`,
  `event_actor_unknown`, and the settings part's `command_invalid`,
  `command_stuck`, `command_reset_loop`, `section_invalid`, `section_parked`,
  `result_parked`, `person_invalid`;
- while the contract is on:
  - `the feed was last read … (the platform alerts after 10 minutes)`, past
    5 minutes;
  - `published_through is …`, past an hour;
  - `N held subs not followed: their PUTs have failed since …`, past
    15 minutes;
  - `workspace X has no snapshot accepted for over 60 minutes (the platform
    alerts after 90)`, for an open workspace named over 60 minutes ago;
  - `workspace X is parked since …: its snapshots are not sent`, and
    `workspace X has N events parked, the last at … (<codes>): they are not
    sent`: at once for a park since the switch, after 2 minutes for one from
    before it (the leader's start releases those);
  - `workspace X's events have had no verdict for over 60 minutes`, or
    `workspace X has N events pending for over 60 minutes, the oldest
    written at …: they are not delivered`;
- `the server's last secret load failed at step …`, `the server holds
  current=… other=…, the files are current=… other=…`, `a secret is
  installed but the server has published no load`, and `the server's
  published secrets cannot be read`;
- the settings part's ([settings and commands](#settings-and-commands)):
  - while settings are `read` or `on`: `settings are <mode> but the command
    feed was last read … (the console shows Wappie down after 2 minutes;
    the platform alerts after 10)`, past 2 minutes; `workspace X has no
    numbers section accepted for over 60 minutes (the console marks it
    stale after 90)`; and `workspace X's numbers section is parked since …:
    it is not sent (<class>)`, at once for a park since the switch, after 2
    minutes for one from before it;
  - `settings are off, but the platform has watched the command feed since
    …: it alerts contract_commands_silent`;
  - `an invalid_command was answered at … (the platform alerts for 24
    hours)`, within the day, at the take or by the executor;
  - `N results are parked (rejected invalid_request or local_invalid), the
    last at …: they are not delivered`;
  - `N results are not delivered, the oldest for over 5 minutes, since …
    (<class>)`;
  - `N commands have no result, the oldest taken over 10 minutes ago, at …`;
  - `N commands are retrying after store errors, the oldest taken at …
    (<class>)`, and `a command was answered rate_limited after 5 failed
    runs at …`, within the day;
  - while settings are `read` or `on`: `N person documents not accepted
    for over 60 minutes, the oldest since … (<class>)`, and `N person
    documents parked, the last at …: they are not sent`;
  - `the settings part's state could not be read: …`: the rest of the
    report goes on;
- `contract never observed but a secret is installed`: `events_from` is
  unset while the current secret file exists. A restore of Wappie's
  database from a backup taken before the first observe brings back `off`
  with homes of Wappie's choosing and nothing sent; only this finding says
  so, until `contract mode observe` runs again.

## The platform's two alerts, and Wappie's early warnings

The platform's hourly doctor mails the operator about an app that follows
accounts (from its first PUT until its DELETE):

| The platform's alert | When | Wappie's bound | Wappie's early warning (`--check`) |
|---|---|---|---|
| `contract_feed_silent` | the app has not read its feed (a signed feed request answered 200) for over 10 minutes | the follower long-polls continuously; a leader whose lock goes stops within 20 seconds, and another process tries the lock every 30 seconds; after a failure the feed is asked again within a minute | the feed's last page over 5 minutes ago |
| `contract_snapshots_stale` | an open workspace named in a followed account's document over 90 minutes ago, whose snapshot is missing or over 90 minutes old (personal and empty ones included) | every recorded workspace at the leader's start, 2 seconds after a change, at once when first named, and 55 minutes after its last accepted one | no accepted snapshot for 60 minutes |

An orphan subscription's workspaces are never recorded, so never sent a
snapshot: the sweep unsubscribes it within about 20 minutes of its last
PUT, well before 90.

## Logs

A contract log line holds subs, user ids, workspace ids, device ids, counts,
codes and classes: never an email, a name, a label, a hint, a phone number,
a secret, or an error's text that names an ARN. The ERRORs, each recorded
for `--check` where a class is given above: "contract: the socket failed its
peer checks; no request goes to it for a minute", "contract: secrets not
loaded; the contract is unavailable", "contract: secrets reload failed; the
secrets loaded before stay in use", "contract: no feed page for a long time",
"contract: published_through ahead of the clock; the last trusted one is
kept", "contract: a document cannot be stored", "contract: workspace kind
changed", "contract: held subs still have no document of this generation;
their PUTs fail", "contract: a workspace's snapshot is parked", "contract: a
workspace's snapshot is not sent: Wappie would not send it", and the
events' ([contract events](contract-events.md#outcomes-parks-and-releases)).
The settings part's: "contract: commands refused invalid_command" (one per
page, with counts by why: `mac`, `another_app`, `malformed`, `generation`,
`invalid`, `cseq`), "contract: a command of another generation than its
page; refused invalid_command", "contract: a command was answered
rate_limited after its runs kept failing", "contract: results are parked:
Wappie would not post them", "contract: results are parked: the platform
refused them", "contract: a workspace's numbers section is not sent: Wappie
would not send it", "contract: a workspace's numbers section leaves out
rows the wire refuses: it goes truncated", "contract: a workspace's numbers
section is parked", "contract: a second reset from the command feed
within a minute waits", "contract: a command taken could not be read;
refused invalid_command", "contract: a command delivered again keeps
waiting", "contract: a person's document is not sent:
Wappie would not send it", "contract: a person's notices are left out: the
wire refuses them" and "contract: a person's document is parked" (the last
with no class: its `--check` line says it).
Three more have no class of their own: "contract: could not publish the
loaded secrets; the installer will not see this load" (`--check`'s
fingerprint findings show it), "contract: a feed document cannot be read;
it is skipped" (its sub's version is forgotten, so the round asks again,
and `round_incomplete` if that keeps failing), and "contract: a new
account's document names no personal workspace" (the sign-up is refused
`503 platform_unavailable`).

**Lock order.** Every transaction that touches several of the contract's
rows takes them in one order: `contract_state`, then `contract_accounts`
by sub and `contract_workspaces` by id, then the workspace (`FOR KEY
SHARE`, behind a purge's `FOR UPDATE`), then its `item_events` rows in
`seq` order, with a retry on a deadlock.

## What enforce adds

Nothing below ships in this release:

- applying the documents: memberships and roles, a removal (a stranding
  one held until the platform's generation is confirmed), a disable
  (suspend, keys kept), a session or credential revocation, a team's closure
  and rename, an account's closing;
- `409 managed_elsewhere` for member changes, workspace creation and the
  last-owner checks in platform teams, in place of `invitations_paused`;
- the freshness refusals made binding, the hot paths given a synchronous
  GET, and the mover's owner count of 1 checked beside the local one;
- the reconciliation of the pilot's team and the retirement of the teams no
  document names.

## Timings

Each value below is the code's, and `TestContractDocsMatchTheCode` and
`TestContractTimingsMatchTheDocs` fail when one moves without this table.

| Timing | Value | What |
|---|---|---|
| fresh | 1 hour | a sub is fresh after its last document or a trusted `published_through` |
| backup fresh | 1 minute | a remaining key holder's stored document counts for the minute rule |
| clock skew | 5 minutes | the furthest a platform time may be past the database's clock |
| call bound | 5 seconds | each call made while a person waits: a sign-in's PUT, a hook's GETs, a refused sign-up's DELETE |
| call timeout | 15 seconds | the kit's bound on every other call |
| feed grace | 15 seconds | the kit's bound on a long-poll, past its wait |
| peer checks | 1 minute | a socket that failed its peer checks gets no request |
| hot path | 1 minute | a send's or a group act's background check, at most once per session, act and number (per connection and number for `mcp.send`) |
| hot path bound | 5 seconds | one such background check, which reads the stored freshness only |
| mode cache | 5 seconds | how long a process trusts the mode it read |
| pace | 100 milliseconds | between two of the leader's calls, whichever they are: the round's PUTs, the sweep's DELETEs and the senders' calls take turns |
| orphan | 15 minutes | a subscription of a sub Wappie does not hold, before the sweep |
| sweep | 5 minutes | how often the sweep runs |
| round | 1 minute | how often a round that is done is asked again |
| leader retry | 30 seconds | how often a process that does not lead tries the lock |
| heartbeat | 10 seconds | how often the lock's connection is checked |
| long-poll | 25 seconds | the feed's wait |
| feed backoff | 2 seconds to 1 minute | after a feed call that got no page, or a round that left subs |
| feed silent | 15 minutes | without a page, before the follower's ERROR |
| warn | 1 minute | the follower's and the senders' WARN for a run of failures, at most once |
| round failing | 15 minutes | the round's PUTs failing, before its ERROR |
| debounce | 2 seconds | a snapshot after the first change of a run |
| snapshot | 55 minutes | the next snapshot after one accepted |
| snapshot backoff | 5 seconds to 1 hour | after a snapshot that was not accepted |
| labels | 1 hour | a workspace's "contract: snapshot labels" line, at most once |
| snapshot not found | 24 hours | a workspace's snapshot refused `not_found`, before it parks |
| event backoff | 5 seconds to 1 hour | after a batch that got no verdict |
| event scan | 5 minutes | how often every queue is looked at, beside the notices |
| event not found | 24 hours | a queue refused `not_found`, before its rows park |
| event expiry | 29 days | after it occurred, an event not delivered is parked `expired` |
| load retry | 30 seconds | the lazy secret load's wait, at first |
| load retry for | 10 minutes | how long the lazy load waits only that |
| load retry late | 5 minutes | the lazy secret load's wait, after them |
| check feed | 5 minutes | `--check`: the feed's last page |
| check snapshot | 1 hour | `--check`: a workspace's last accepted snapshot |
| check published | 1 hour | `--check`: `published_through` |
| check errors | 24 hours | `--check`: a contract ERROR |
| check round | 15 minutes | `--check`: the round's PUTs failing |
| check parked | 2 minutes | `--check`: a park from before the switch |
| check events | 1 hour | `--check`: a queue with no verdict, or events pending |
| command long-poll | 25 seconds | the command feed's wait |
| command backoff | 2 seconds to 20 seconds | after a command feed call that got no page |
| reset floor | 1 minute | between two resets the command feed starts |
| section debounce | 2 seconds | a numbers section after the first change of a run |
| connection debounce | 30 seconds | a numbers section after a connection that only flipped between online and offline |
| section | 55 minutes | the next numbers section after one accepted |
| section backoff | 5 seconds to 1 hour | after a numbers section that was not accepted |
| section not found | 24 hours | a numbers section refused `not_found`, before it parks |
| pairing look | 10 seconds | how often the pending rows' pairing is compared with the last section sent |
| results backoff | 2 seconds to 1 minute | after a results post that got no answer |
| settings idle | 30 seconds | the longest the executor and the results poster wait without looking |
| run backoff | 5 seconds to 1 minute | after a command's run that failed with a store error; after 5 tries it is answered `rate_limited`, `retry_after` 60 |
| ledger | 30 days | a command's ledger row, from its take, never less and never more |
| ledger trim | 5 minutes | how often the leader trims the ledger (and every process's hourly maintenance) |
| check commands | 2 minutes | `--check`: the command feed's last page, while settings are read or on |
| check results | 5 minutes | `--check`: the oldest result not delivered |
| check taken | 10 minutes | `--check`: the oldest command with no result |
| check section | 1 hour | `--check`: a workspace's last accepted numbers section |
| behind retry | 5 seconds | `memberships_behind`'s `retry_after` |
| person not found | 24 hours | a person's document refused `not_found`, before it parks |
| resume repair | 10 minutes | a number unpaused this long, before a pause notice its frame left open is marked resumed |
| start bound | 15 seconds | a console resume's or sync now's start, before it is cut |
| failed start wait | 1 minute | after a console sync now's start of a number failed, before this process starts that number for a sync now again |
| check person | 1 hour | `--check`: a person's last accepted document |

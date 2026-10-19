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
snapshot of what Wappie's own tables say, measured in one read-only
snapshot of the database with its clock. A workspace Wappie has no
workspace for gets an empty one (`"items": []`): the console counts a
missing snapshot as unknown protection.

- **Items** are the workspace's numbers with a known identity or a past
  connection (a pending registration is none), deleted ones until their
  purge, by id, `kind: "number"`, with the contract's `label` and `hint`
  ([the label rule](contract-events.md#labels-and-hints)).
- **State and reason**, the first that holds: `deleted` (with `purge_at`,
  its `purge_after`); `sync_paused` with `needs_reauth` (logged out),
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
  the last one sent plus one, stored before the send, so it rises across
  leaders.

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
  `event_actor_unknown`;
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

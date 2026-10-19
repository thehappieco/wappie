# Contract events

The platform mails a number's owners and readers about what happened to it
(the platform's spec, sections 9 and 9.1; decisions 0038, 0040 and 0043):
a deletion, a pause of its sync, a recovery, a purge, a move to Personal,
and a stranding (its last key holder removed or disabled by an owner's
override). Wappie writes each act as a plain row of `item_events` in the
act's own transaction ([item events](item-events.md)), and the leader's
event sender ([the contract](contract.md#the-leader-and-the-follower))
renders the rows at send time with the kit's types, checks each, and sends
them to `POST /contract/v1/events`. No event is built inside a writer's
transaction, so no wire bug can roll back a deletion, a pause, a recovery,
a move, a purge or a stranding, and a change in the spec rewrites no stored
row.

## The shapes

| Row | `type` | `actor`, `actor_kind` | `readers` | Only on this type |
|---|---|---|---|---|
| `deleted` | `item.deleted` | the owner's sub, `person` | who read the number just before | `purge_at`: its `purge_after` |
| `recovered` | `item.recovered` | the owner's sub, `person` | who reads it after the recovery | |
| `sync_paused` | `item.sync_paused` | the person's sub, `person`; or an API key's creator's, `key` | the readers when it was paused, and those of every pause folded into it (below) | |
| `purged` | `item.purged` | null, `app` | `[]` | |
| `moved_out` | `item.moved_out` | the mover's sub, `person` | the team's readers before the move: at most the mover | `to`: `personal` |
| `stranded` | `item.stranded` | the owner's sub, `person` | who read it just before the change, the person stranded among them | `person`: the stranded person's sub (omitted when they have none); `cause`: `revoked` (a removal) or `disabled` (a disable) |

Every event carries `event_id` (the row's UUIDv7, the platform's
idempotency key), `workspace_id` (the row's workspace, which is the
platform's id), `occurred_at` (the database's clock at the act, in
microseconds), and `item`: `{id, kind: "number", label, hint}`. An example,
byte for byte the renderer's golden file
`internal/membership/testdata/events/deleted.json`:

```json
{
  "event_id": "0199d000-0000-7000-8000-000000000001",
  "workspace_id": "0199a000-0000-7000-8000-000000000001",
  "type": "item.deleted",
  "occurred_at": "2026-10-13T12:00:00Z",
  "item": {
    "id": "0199e000-0000-7000-8000-000000000004",
    "kind": "number",
    "label": "Vendas",
    "hint": "…5678"
  },
  "actor": "0199a0c2-0000-7000-8000-000000000001",
  "actor_kind": "person",
  "readers": [
    "0199a0c2-0000-7000-8000-000000000001",
    "0199c3d4-0000-7000-8000-000000000002"
  ],
  "purge_at": "2026-11-12T12:00:00Z"
}
```

- **Readers** are platform subs: a reader with no sub is left out (the row
  keeps their local ids for a self-hosted mailer, never sent). Wappie's
  choices where the spec leaves one: a recovery's readers are those after
  it, a purge has none, a stranding's are those just before the change
  (the spec's "the people who read the item just before"). Above 5000
  readers, `readers` is null and the platform takes its latest snapshot's.
- **The actor.** A person, or an API key's creator, is named by their sub:
  the row's, else (a replayed row keeps none) the sub their local account is
  linked to now. A person with no sub, or a key's known creator with none,
  is a fault where people sign in through the platform: the event goes with
  `actor: null` and its kind, ERROR "contract: an event's actor has no
  platform sub; it is sent with actor null" once per event and leader, and
  the class `event_actor_unknown`. A key with no creator, and a replayed row
  whose local account is gone, go as `actor: null` with no ERROR.
- **`cause`** is set for a stranding by a local act (`revoked` from a
  removal, `disabled` from a disable). A stranding the platform causes
  (enforce, a membership it ended) has none, and the platform fills it from
  its own log.
- Each event is checked with the kit's validation before it is sent; one
  that fails is parked `local_invalid` with an ERROR ("contract: an event is
  not sent: Wappie would not send it", naming the rule), and the queue goes
  on.

## Labels and hints

The `label` is the number's name for the contract: its label in Wappie,
else its WhatsApp push name; a placeholder, an id or the phone number
itself is skipped, every run of seven or more digits is masked, and a name
with `@` is dropped whole; null when nothing is left. The `hint` is `…`
and the last four digits of its phone number. Never the number itself or
its LID. A row's label and hint are those at the act; the purge sets them
to null in every row of the number, in its workspace and in any team it
moved out of, so an event sent after the purge carries none. A replayed row
(a restore's) keeps none: it takes its number's at send time, deleted
numbers included, until the purge; a replayed purge has none. The
snapshots use the same rule.

## Which rows are sent

A row is sent when its workspace is a platform workspace (a document has
named it), it is neither settled nor parked, and either:

- it was written (not replayed) at or after both the first switch to
  observe (`contract_state.events_from`) and the workspace's naming
  (`named_at`); and, for a pause, a stranding or a move, not while the
  contract was `off` after an observe (`events_off`, the off periods, and
  the current one);
- or it was replayed, a deletion, a recovery or a purge (the three a
  restore's replay writes, with the ledger's own `event_id` and time), and
  it occurred at or after both.

So nothing written before the transport is ever sent (the spec's "Before
the transport"), per workspace: a team the platform names later does not
mail weeks-old acts, and neither does a return to observe. Deletions,
recoveries and purges written while `off` after an observe **are** sent on
the return to observe: the spec always sends them, an off period after the
first observe is not "before the transport", and without them a purge
could arrive with no deletion. A late `item.deleted` can therefore mail the
owners after the fact. Pauses, strandings and moves written while `off` are
local only. `whatserverd contract mode observe` prints how many of each it
will send and hold back ([the mode](contract.md#the-mode)).

A replayed row the platform already holds comes back `duplicate`: its rule
compares the event id, the workspace, the type, the item and the time, and
the replay keeps the ledger's id and time.

## Coalescing pauses

One `item.sync_paused` per number, actor and hour (the spec's "Floods"):

- When a queue's next event is a pause, every later unsent pause of the
  same number by the same actor (the same kind and local account; a key's
  creator for a key) under an hour after it is folded into it, and it
  carries the union of their readers. The folded rows are settled
  `coalesced` only in the transaction that records its own signed answer,
  and parked with it when it is parked.
- A pause under an hour after one of the same number and actor that the
  platform already took is folded into that one and settled at once: no
  second mail.
- **Nobody to tell.** After folding, a pause whose readers less its actor
  are none (and whose readers are listed: 5000 or fewer) is not sent:
  settled `not_sent`, with its folded rows. Release A writes a pause when
  anyone but the actor reads, people with no sub included, so such rows
  exist (a pause whose other reader is a local account never linked to the
  platform).

Every pause still has its own row and its own in-app notice, so a reader
added within the hour is told in Wappie even when no second mail goes.

## Queues and batches

- **One queue per workspace**, in `seq` order, which is commit order within a
  workspace: never a high-water mark. A batch is the head of one queue: at
  most 100 events and under 248 KiB encoded (the call allows 256 KiB; one
  event with 5000 readers is about 195 KiB). Two workspaces' events never
  share a batch, so one workspace's fault stops only its own queue.
- A new row of a platform workspace, a queue made due again and a release
  of parked rows wake the sender at once (0051's notices); it also looks
  at every queue at the leader's start and every 5 minutes. Calls go at the
  round's pace, 10 a second.
- **Results are matched by position** (the spec's "one per event, in
  order"): a result whose `event_id` is neither the event sent at that
  place nor empty (the platform's, for an event it could not decode), or
  whose outcome or code the spec does not define, makes the whole answer
  unverified: nothing is settled, and the batch is sent again.

## Outcomes, parks and releases

| The platform's answer | What Wappie does |
|---|---|
| `accepted`, `duplicate` (signed) | delivered: settled with that outcome, with its folded rows |
| `rejected`, `conflict` | parked `conflict`, ERROR "contract: an event is parked: the platform refused it": the platform holds this id with other content, a Wappie bug (its duplicate rule ignores the label, which the purge nulls, and a replay keeps the ledger's id and time) |
| `rejected`, `invalid_request` | parked `invalid_request`, the same ERROR; the queue goes on |
| `rejected`, `not_found` | the queue's `not_found` run starts: retried with the backoff for 24 hours, then every unsent row of the queue is parked `not_found`, ERROR "contract: a workspace's events are parked: the platform has not known it for a day" |
| the whole call refused `invalid_request` (signed) | ERROR "contract: the platform refused a batch of events whole; sending them one by one", then one event per call: an event refused alone is parked `invalid_request`, so one bad row never stalls its workspace |
| a signed `unavailable` or `rate_limited`, an unverified answer, no answer | the same batch again, same ids, after 5 seconds doubled with each failure up to an hour; events kept before the fault come back `duplicate` |

**Releases.** The spec calls `not_found` a platform fault, so the rows
parked for it (still under their 29 days) are sent again, with their folded
rows: when a document names the workspace again, when the platform's
generation changes (the restart), and when an event of the workspace is
accepted (the platform knows it now). INFO "contract: events parked for
not_found are sent again". Every other park is final.

**The 29 days.** The platform recognises a duplicate only while it holds
the event, 30 days (the spec's 11), and a resend after that would mail
again, or mail a recovery date already past. So an unsent row whose
`occurred_at` is 29 days old is parked `expired` with its folded rows,
by the sender or by the hourly housekeeping, whichever meets it first, in
every mode: ERROR "contract: events never delivered in their 29 days are
parked". The housekeeping keeps a row past its 30 days only while it is
still owed, which the expiry bounds.

Every park records the class `event_parked` for
[`contract status --check`](contract.md#contract-status), which reports a
workspace's parked events while they last, a queue with no verdict for an
hour, and events pending for over an hour.

## What the purge is

The 30-day purge carries out the owner's own deletion, on Wappie's
database clock, 30 days after it ([device lifecycle](devices.md#the-purge)).
It is not a deletion order from the platform under its decisions 0005 or
0015: the platform is told of it (`item.purged`), as of every act above,
and orders nothing.

# Item events

Wappie keeps a local log of what happens to a number: `item_events`
(migration 0050). It records the acts of decisions 0038 and 0040 (a deletion,
a pause of its sync, a recovery, a purge and a move to Personal), one plain
row per act, in the same transaction as the act. Nothing sends these rows in
this release. A later release renders the platform contract's `item.*`
events from them and delivers them; it never sends a row written before it
ships. Its shapes will be documented in `docs/contract-events.md`, written
with that release.

In this release the rows feed the [deletion ledger](deployment.md#deleted-numbers-and-the-deletion-ledger),
which a restore replays; besides its export, only the replay's check and the
janitor's housekeeping read them.

## Columns

| Column | What it holds |
| --- | --- |
| `seq` | The workspace's order. Every writer holds the workspace's row lock from before its insert until its commit, so within a workspace `seq` order is commit order. |
| `event_id` | A UUIDv7, made once in Go: the contract's idempotency key later. A replayed row keeps its ledger line's id. |
| `tenant_id` | The workspace. For a workspace adopted from the platform it is the platform's id. |
| `type` | `deleted`, `sync_paused`, `recovered`, `purged` or `moved_out`. |
| `item_id` | The number's `devices.id`. No foreign key: the rows outlive the purge. |
| `dedupe_key` | Local only. `type:device:instant`, the instant in microseconds; a second write of the same event is a no-op. |
| `occurred_at` | When it happened, on the database's clock. |
| `actor_kind` | `person`, `key` (an API key, whose act is its creator's) or `app` (the purge). |
| `actor_sub` | The platform sub of the person, or of the key's creator. Null for the app, for a key with no creator, and for a person with no sub. |
| `actor_user_id` | Local only, never to be sent: the person, or the key's creator. |
| `reader_subs` | The platform subs of the number's readers, the actor included when they read it. A reader with no sub is left out. |
| `label`, `hint` | The number's name for the contract: its label, else its WhatsApp push name, with every run of seven or more digits masked, a placeholder, an id or the phone number itself skipped, and a name with `@` dropped whole (null when nothing is left); and `…` with the last four digits of its phone number. Never the number itself or its LID. Both are set to null in every row of the number at its purge. |
| `deleted_at`, `purge_after` | The deletion's dates on `deleted` and `purged`; `recovered` carries the `deleted_at` it reverses. |
| `to_tenant_id` | The Personal workspace a `moved_out` number went to. |
| `created_at` | When the row was written. |
| `ledgered_at` | When the row's line was synced to the deletion ledger. |
| `replayed_at` | Set on a row a restore's replay wrote from the ledger. Such a row is never sent. |

Only `actor_user_id` and `dedupe_key` are local; no column holds an API key
id or a phone number, and a later release names people only by platform
sub. In the cloud every person who can act has a sub, so a person (or a
key's creator) without one is a fault: the writer logs ERROR "an event's
actor has no platform sub" and writes the row with `actor_kind` kept and no
`actor_sub`. A self-hosted installation, with no platform identities, links
nobody and logs nothing.

## Types

| Type | Written by | Actor | Readers | Dedupe key | In the ledger |
| --- | --- | --- | --- | --- | --- |
| `deleted` | `device.delete`, by an owner | `person` | Who read the number just before | `deleted:<device>:<deleted_at>` | yes |
| `sync_paused` | `device.stop` by a person or an API key, when it turns a live number's sync off and someone other than the actor reads it | `person`, or `key` | The readers, the actor included | `sync_paused:<device>:<instant>` | no |
| `recovered` | `device.recover`, by an owner | `person` | Who reads the number after the recovery | `recovered:<device>:<deleted_at it reverses>` | yes |
| `purged` | The purge, at its end; or a restore's replay | `app` | None | `purged:<device>:<deleted_at>` | yes |
| `moved_out` | `device.transfer` to Personal, in the Team it leaves | `person` | The Team's readers before the move: at most the actor, since a move needs nobody else to have access | `moved_out:<device>:<completed_at>` | yes |

Pauses Wappie makes on its own (before a move, after a failed resume, at a
deletion, at a storage stop) write no row. A pause that tells nobody writes
none either: a repeated `device.stop`, a pause of a number nobody but the
actor reads, and, in a personal workspace, a pause by its owner or by a key
its owner created. A `sync_paused` row is written already marked ledgered:
the ledger keeps only what a restore must replay.

## Life

- **The ledger.** After each delete, recovery and move, after each purge, at
  every hourly janitor pass and from `whatserverd deletions export-ledger`,
  the rows of the four ledgered types that have no `ledgered_at` are appended
  to the ledger, synced, and only then marked. A failed write leaves them
  unmarked for the next export.
- **Thirty days.** The hourly janitor deletes a row 30 days after
  `created_at`, once it is marked ledgered. A row the ledger has not taken
  stays, however old, and each pass logs ERROR "event rows 30 days old are
  still not in the deletion ledger" with the count and the oldest row.
- **The purge** sets `label` and `hint` to null in every row of the number,
  in its workspace and in any team it moved out of, and then writes
  `purged`.
- **The down-step** of 0050 drops the table, and refuses while a row is not
  in the ledger yet ([Rolling back below 0050](deployment.md#rolling-back-below-0050)).
- A workspace's rows go with the workspace (`ON DELETE CASCADE`).

The table has forced row-level security: a query sees only the rows of the
workspace its transaction names.

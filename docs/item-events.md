# Item events

Wappie keeps a local log of what happens to a number: `item_events`
(migration 0050; 0051 added the stranding and the delivery columns). It
records the acts of decisions 0038 and 0040 (a deletion, a pause of its
sync, a recovery, a purge, a move to Personal and a stranding), one plain
row per act, in the same transaction as the act.

In the cloud, the platform contract's event sender renders the platform's
`item.*` events from these rows at send time and delivers them, from which
the platform mails the owners and the readers; it never sends a row written
before the contract was first observed, nor one of a workspace no platform
document names. The shapes and the sending rules are in
[contract events](contract-events.md). The four ledgered types also feed the
[deletion ledger](deployment.md#deleted-numbers-and-the-deletion-ledger),
which a restore replays.

## Columns

| Column | What it holds |
| --- | --- |
| `seq` | The workspace's order. Every writer holds the workspace's row lock from before its insert until its commit, so within a workspace `seq` order is commit order. |
| `event_id` | A UUIDv7, made once in Go: the contract's idempotency key later. A replayed row keeps its ledger line's id. |
| `tenant_id` | The workspace. For a workspace adopted from the platform it is the platform's id. |
| `type` | `deleted`, `sync_paused`, `recovered`, `purged`, `moved_out` or `stranded`. |
| `item_id` | The number's `devices.id`. No foreign key: the rows outlive the purge. |
| `dedupe_key` | Local only. `type:device:instant`, the instant in microseconds; a second write of the same event is a no-op. |
| `occurred_at` | When it happened, on the database's clock. |
| `actor_kind` | `person`, `key` (an API key, whose act is its creator's) or `app` (the purge). |
| `actor_sub` | The platform sub of the person, or of the key's creator. Null for the app, for a key with no creator, and for a person with no sub. |
| `actor_user_id` | Local only, never to be sent: the person, or the key's creator. |
| `reader_subs` | The platform subs of the number's readers, the actor included when they read it. A reader with no sub is left out. |
| `reader_user_ids` | Local only, never sent: the same readers' local ids, those with no sub included, for a self-hosted mailer. |
| `label`, `hint` | The number's name for the contract: its label, else its WhatsApp push name, with every run of seven or more digits masked, a placeholder, an id or the phone number itself skipped, and a name with `@` dropped whole (null when nothing is left); and `…` with the last four digits of its phone number. Never the number itself or its LID. Both are set to null in every row of the number at its purge. |
| `deleted_at`, `purge_after` | The deletion's dates on `deleted` and `purged`; `recovered` carries the `deleted_at` it reverses. |
| `to_tenant_id` | The Personal workspace a `moved_out` number went to. |
| `person_sub`, `cause` | A `stranded` row's: the sub of the person whose removal or disable stranded the number (null without one), and `revoked` (a removal) or `disabled` (a disable). Null on every other type. |
| `created_at` | When the row was written. |
| `ledgered_at` | When the row's line was synced to the deletion ledger. |
| `replayed_at` | Set on a row a restore's replay wrote from the ledger. Such a row is sent only if it is a deletion, a recovery or a purge that occurred at or after both the contract's first observe and the platform's first naming of its workspace; the platform answers `duplicate` for one it holds. |
| `settled_at`, `outcome` | The contract's sender is done with it: `accepted` or `duplicate` (delivered, on a signed answer), `coalesced` (folded into a pause of the same number and actor that was delivered), or `not_sent` (a pause nobody but its actor reads). |
| `coalesced_into` | The pause this one was folded into (one `item.sync_paused` per number, actor and hour). |
| `parked_at`, `reject_code` | A row that is not sent: `invalid_request`, `not_found` (a day of it; sent again when the platform knows the workspace), `conflict`, `local_invalid` (Wappie would not send it) or `expired` (29 days unsent). Never both settled and parked. |
| `mailed_at` | For a self-hosted mailer: when the row's recipients were queued. Nothing sets it in this release. |

Only `actor_user_id`, `reader_user_ids`, `dedupe_key` and the delivery
columns are local; no column holds an API key id or a phone number, and the
contract names people only by platform sub. In the cloud every person who can act has a sub, so a person (or a
key's creator) without one is a fault: the writer logs ERROR "an event's
actor has no platform sub" and writes the row with `actor_kind` kept and no
`actor_sub`. A self-hosted installation, with no platform identities, links
nobody and logs nothing.

## Types

| Type | Written by | Actor | Readers | Dedupe key | In the ledger |
| --- | --- | --- | --- | --- | --- |
| `deleted` | `device.delete`, by an owner; or a restore's replay | `person` | Who read the number just before | `deleted:<device>:<deleted_at>` | yes |
| `sync_paused` | `device.stop` by a person or an API key, when it turns a live number's sync off and someone other than the actor reads it | `person`, or `key` | The readers, the actor included | `sync_paused:<device>:<instant>` | no |
| `recovered` | `device.recover`, by an owner; or a restore's replay | `person` | Who reads the number after the recovery | `recovered:<device>:<deleted_at it reverses>` | yes |
| `purged` | The purge, at its end; or a restore's replay | `app` | None | `purged:<device>:<deleted_at>` | yes |
| `moved_out` | `device.transfer` to Personal, in the Team it leaves | `person` | The Team's readers before the move: at most the actor, since a move needs nobody else to have access | `moved_out:<device>:<completed_at>` | yes |
| `stranded` | An owner's removal or disable of a deleted number's last key holder, with `strand_deleted` ([workspaces](workspaces.md#phase-2-membership-management-and-live-revocation)), one row per number | `person` (the owner) | Who read it just before the change, the person stranded included | `stranded:<device>:<target user>:<instant>` | no |

A row the replay writes has no readers. Its actor is the ledger's
`deleted_by` on a `deleted` row, when that person still exists, and nobody on
a `recovered` row.

Pauses Wappie makes on its own (before a move, after a failed resume, at a
deletion, at a storage stop) write no row. A pause that tells nobody writes
none either: a repeated `device.stop`, a pause of a number nobody but the
actor reads, and, in a personal workspace, a pause by its owner or by a key
its owner created. A `sync_paused` or `stranded` row is written already
marked ledgered: the ledger keeps only what a restore must replay, and a
restore replays deletions, not strandings.

## Life

- **The ledger.** After each delete, recovery and move, after each purge, at
  every hourly janitor pass and from `whatserverd deletions export-ledger`,
  the rows of the four ledgered types that have no `ledgered_at` are appended
  to the ledger, synced, and only then marked. A failed write leaves them
  unmarked for the next export.
- **The contract.** A row of a platform workspace is delivered once, on the
  platform's signed answer, or parked with a reason. One still unsent when
  its `occurred_at` is 29 days old is parked `expired`, by the sender or by
  the hourly janitor, in every mode, with ERROR "contract: events never
  delivered in their 29 days are parked"
  ([contract events](contract-events.md#outcomes-parks-and-releases)).
- **Thirty days.** The hourly janitor deletes a row 30 days after
  `created_at`, once it is marked ledgered, unless the contract still owes
  it to the platform (which the 29 days bound). A row the ledger has not
  taken stays, however old, and each pass logs ERROR "event rows 30 days old
  are still not in the deletion ledger" with the count and the oldest row.
- **The purge** sets `label` and `hint` to null in every row of the number,
  in its workspace and in any team it moved out of, and then writes
  `purged`.
- **The down-step** of 0051 deletes the `stranded` rows and drops the
  delivery columns, counting the rows not sent yet, which stay
  ([Rolling back below 0051](deployment.md#rolling-back-below-0051)); 0050's
  drops the table, and refuses while a row is not in the ledger yet
  ([Rolling back below 0050](deployment.md#rolling-back-below-0050)).
- A workspace's rows go with the workspace (`ON DELETE CASCADE`).

The table has forced row-level security: a query sees only the rows of the
workspace its transaction names.

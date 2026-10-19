# Device lifecycle

A device is a WhatsApp number linked to a workspace. Internal labels are independent of the WhatsApp profile. Profile pictures use the existing encrypted contact/avatar path and require read permission plus a usable device key.

All commands below use WebSocket v1 frames (`t`, `r`, `p`). The session and device must belong to the same workspace. `device.rename`, `device.stop`, `device.start` and retries require the device's **manage** permission and an API token scope that permits management, when a token is used. Deleting a linked number requires an owner's person session, in every workspace, a personal one included; removing a registration that never linked requires an owner or administrator.

A number's **readers** are the people with an active membership, Read permission and a key grant at its current archive epoch. Service accounts are never readers.

## Rename

`device.rename` with `{ "device_id": "UUID", "label": "Support" }` returns `device.detail`. The trimmed label must contain 1–100 characters. It changes neither the WhatsApp profile nor the device's encryption key, grants or history.

## Pause and resume

`device.stop` with `{ "device_id": "UUID" }` pauses synchronization and sending through Wappie. The pause is durable and survives automatic supervision and server restarts. The linked session remains on WhatsApp, and existing encrypted history can still be read.

Every paused number records why (`devices.pause_cause`, migration 0051): `person` for a person's or an API key's stop, and for an owner's recovery, which leaves the number paused; `move` for Wappie's own pause around a move to Personal (a person's stop during a move makes it `person`, and the move keeps a person's pause); `deletion` for a deleted number. A failed resume puts back the cause it found. The platform's access snapshot reports a paused number by it ([the contract](contract.md#access-snapshots)): `by_person` only for `person`.

Turning a live number's sync off tells its readers, in Wappie's own pages, until the platform's mails start (decision 0039). Every reader but the one who paused it gets a `sync_paused` notice: in `devices.list`, and pushed as `device.notice` to their open sessions on the same server. A person has at most one unseen notice per number: a later pause folds into it (`pauses`, `last_raised_at`, `several_actors` when someone else paused it before). An API key's pause is its creator's act: the creator is told nothing and is named in the others' notice (`raised_by_kind: "key"`). Only a key with no creator tells every reader. A repeated `device.stop` tells nobody, and so does a pause of a number nobody else reads, which in a personal workspace is every pause by its owner or the owner's key. The pauses Wappie makes on its own (before a move, at a deletion, after a failed resume, at a storage stop) tell nobody. Each pause that tells someone is also an [item event](item-events.md).

`device.start` with the same payload resumes an existing stored WhatsApp session. Both commands return `device.status`. A number that has never paired cannot be resumed this way. A logged-out or banned session cannot be resumed. A resume marks the open pause notices resumed (`resumed_at`); they stay until each reader sees them.

`devices.list` and `device.info` expose `paused` (durable operator preference), `running` (authenticated, online transport on this instance), `can_manage` (effective management authorization), and `profile_key` (the device's own contact identifier). A registry reservation alone is not a running connection. Connecting, paused and logged-out devices report `running: false`.

## Unlinking from the phone

Removing Wappie under WhatsApp's linked devices deletes its WhatsApp session and
eventually reports `logged_out`. The supervisor stops without reconnecting that
invalid session. A paused or disconnected instance may only detect the removal
on its next connection attempt. Sending and new synchronization stop, while
authorized readers retain the history and attachments already archived by
Wappie. Pending downloads may finish while their media URLs remain valid.

This does not remove the Wappie device, free its plan slot or cancel a
subscription. Resume and pending-pairing retry do not support reconnecting an
already linked, logged-out record. A workflow for pairing that record again
while preserving history remains unimplemented. Deleting the number (below)
ends its history after 30 days, and is not a way to link it again: a
recovered number whose logout WhatsApp confirmed comes back read-only.

## Pending pairing

A new `pair` still requires a client-generated archive public key and encrypted grants. Its provisional row is removed when the attempt times out, fails or is cancelled before pairing completes. Cleanup never removes an identity that has already paired or connected.

To retry an existing incomplete row, send `pair` with `{ "device_id": "UUID", "resume": true, "method": "qr" }`. Code pairing also accepts `method: "code"` and `phone`. The existing encryption key, grants and receipt mode are preserved. Supplying replacement `archive_public_key`, `grants` or `orphan` with a retry is rejected. A retry cannot replace an already linked number. An incomplete legacy row without an archive key must be deleted and recreated.

`pair.cancel` cancels the caller's pending attempt. Deleting a number also cancels a pending attempt from another browser in the same workspace.

## Deletion and recovery

`device.delete` requires `{ "device_id": "UUID", "confirm": "UUID", "acknowledged_readers": ["UUID", ...] }`, repeating the exact full identifier. Ask `device.delete.check` first: it lists who reads the number now, the standing service accounts, the assistant connections and API keys that lose it, and the keys for every number that stop reaching it. Every reader in that list must be acknowledged, or the deletion is refused with `device_has_readers` and the current list in the error's `readers`. The deletion asks for a recent sign-in (`step_up_required`). An API key cannot delete a number, and anyone but an owner gets `owner_only` for a live number and `not_found` for a deleted one, so nobody learns by probing an id that a number is deleted.

A deletion always asks WhatsApp to log the session out, which cannot be undone: `unlink` may be omitted, and `unlink: false` is refused for a linked number. The logout runs after the deletion has committed, with a bounded wait. `device.deleted.unlinked` is true when no WhatsApp session is left, and `note_code` is `unlink_unconfirmed` when WhatsApp did not confirm (remove the session under Linked devices on the phone; the hourly maintenance tries the logout again until three attempts have been made, the deletion's own included, and the purge removes the session it left, by its fingerprint, without logging it out) or `already_disconnected` when there was no session. A retry of a deleted number answers `already: true` with the stored state. A client that lost the reply should ask `devices.deleted` rather than send `device.delete` again: had an owner recovered the number meanwhile, the retry would delete it again, and log it out.

A deleted number is kept 30 days with its data, readable by nobody, then purged. `deleted_at` and `recoverable_until` are the database's clock. Its plan slot is freed at once; its bytes stay counted until the purge ([storage](storage.md#consistent-totals-by-number)). Assistant connections and AI authorizations whose key names it end with `access_lost`. No API key is revoked: a key restricted to chosen numbers loses this one and keeps working for the others (one left with none reaches nothing), and a key for every number reaches it again after a recovery.

Owners list deleted numbers with `devices.deleted` (replying `devices.deleted.list`: each one's dates, who deleted it, its bytes, `recoverable`, `purging`, the stored WhatsApp note and how it would come back) and recover one with `device.recover` (`{ "device_id", "confirm" }`, after a recent sign-in; `device.recover.check` lists who regains access). A recovered number comes back paused, and read-only when WhatsApp confirmed its logout, the normal case (`logged_out: true`, `can_resume: false`): syncing that phone again means linking it as a new number. Only a logout WhatsApp did not confirm leaves a session that can sync again. People who left or were disabled meanwhile get nothing back, assistant connections do not return, and restricted keys need the number given again. Refusals: `recovery_closed` after the 30 days or once the purge has started, `capacity_reached`, `identity_in_use` when the phone was linked again as another number, and `device_busy` while the logout is still running.

Removing or disabling the last key holder of a deleted number is refused with `last_reader_of_deleted` until its purge: recover it and share its key first ([workspaces](workspaces.md)). An owner may do it anyway with `strand_deleted` and a recent sign-in, only where the platform mails the other owners: in a team the platform names that is not closed, while the contract is on ([the strand override](workspaces.md#the-strand-override)); the number then keeps its purge date with nobody able to read it. A live number's last key holder is never removable. Disabling a person also revokes the API keys they created, as a removal does.

A registration that never linked has no data and is still removed at once (`device.deleted.pending`), with no 30 days, no notice and no event.

### Who is told

- **The deleting owner's session** gets the reply and stays open. After the reply, every session on that server that could see the number, the owner's included, gets `device.removed` (`{ "device_id" }`), and anyone else who held a grant or a permission on it reconnects without it. A subscription whose last number was deleted ends with `subscription.ended` (`{ "reason": "device_removed" }`, with the subscribe's request id); the client may subscribe again. After a move to Personal, the other sessions that saw the number get `device.removed` with `reason: "moved"`; the mover's does not.
- **Its readers and the workspace's other owners** get a `number_deleted` notice, in every edition, with the number's label and the last four digits of its phone (`hint`) as they were, and `until`, its purge date. A pause notice for the number gives way to it. A recovery deletes the deletion notices.
- **The workspace's other owners**, never the actor, get a `number_stranded` notice when an owner's override takes a deleted number's last key holder (below; `until` is its purge, cleared when it is recovered), and a `number_moved_out` notice when a number moves to its owner's Personal workspace. Neither is pushed: both come with `devices.list`.
- **Notices** come with every `devices.list` reply, for a person, in `notices`. A person acknowledges their own with `device.notice.seen`: `{ "notices": [{ "id": 1, "pauses": 2 }] }` names each notice as it was shown, since a pause notice keeps its id when a later pause folds into it and is marked seen only at the version shown; bare `notice_ids` acknowledge every kind but `sync_paused`. The reply, `device.notices`, is what is left unseen, a fold that came after included.
- **Their life.** A seen notice goes 30 days after it was seen; an unseen pause notice 30 days after its pause ended, or once its person no longer reads the number; an unseen deletion notice survives the purge with its label and hint nulled and `purged_at` set, and goes 30 days after it.

In the cloud, Wappie sends no email about any of this: the platform mails the owners and the readers from Wappie's [events](contract-events.md), for the acts after the contract was first observed, in the workspaces the platform names. A self-hosted installation tells them only in its pages in this release.

### The purge

The hourly maintenance of every server process purges each deleted number once its `purge_after` has passed on the database's clock: its rows, keys, grants and permissions, its WhatsApp session left by an unconfirmed logout, and its attachment objects (one whose delete fails stays, still charged, for the next orphan pass). It runs in every workspace whatever its status: a suspended workspace's numbers are purged on their date although nobody can recover them while it is suspended (decided by the owner, 2026-10-13), and so are a closed team's. Nothing moves a number's date. `WS_DELETED_NUMBER_PURGE=hold` stops every purge for an incident only; it is not a way to hold a suspended workspace's purges. A number more than 2 hours past its date is warned about at every pass. The operator's commands and the details are in [deployment](deployment.md#deleted-numbers-and-the-deletion-ledger).

What the purge leaves: the pairs of contacts' phone numbers and WhatsApp LIDs that the number taught whatsmeow. whatsmeow keeps them in one cache shared by every number of the server (`whatsmeow_lid_map`), with no link to the session that learned them, so a pair cannot be told apart from the same pair learned by another number. The owner accepted this residual on 2026-10-13; a later release prunes, at each purge, the pairs no remaining number references.

A workspace with deleted numbers refuses `reset-archive` until each is recovered or purged. A move to Personal never takes a deleted number: it cannot be found.

No platform call runs inside the store transaction of a deletion, a recovery, a stop or a move to Personal. In a team the platform names, each asks the contract's freshness hook before its transaction, never inside it: a deletion, a recovery and a person's stop for the actor (a GET when their document is over an hour old), a move for the mover always ([freshness](contract.md#freshness)). In this release the hook only logs what it would refuse; nothing waits on it but its GET, bounded to 5 seconds.

### Moving a number to Personal

See [moving a number from Team to Personal](device-personal-transfer.md): a number moves only while nobody else has access to it.

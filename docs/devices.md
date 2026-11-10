# Device lifecycle

A device is a WhatsApp number linked to a workspace. Internal labels are independent of the WhatsApp profile. Profile pictures use the existing encrypted contact/avatar path and require read permission plus a usable device key.

All commands below use WebSocket v1 frames (`t`, `r`, `p`). The session and device must belong to the same workspace. `device.rename`, retries and `device.start` on a number that is not paused require the device's **manage** permission and an API token scope that permits management, when a token is used. `device.stop`, and `device.start` on a paused number, go by role, not by **manage** ([who pauses and resumes](#who-pauses-and-resumes)). Deleting a linked number requires an owner's person session, in every workspace, a personal one included; removing a registration that never linked requires an owner or administrator.

A number's **readers** are the people with an active membership, Read permission and a key grant at its current archive epoch. Service accounts are never readers.

## Rename

`device.rename` with `{ "device_id": "UUID", "label": "Support" }` returns `device.detail`. The trimmed label must contain 1–100 characters. It changes neither the WhatsApp profile nor the device's encryption key, grants or history.

## Pause and resume

`device.stop` with `{ "device_id": "UUID" }` pauses synchronization and sending through Wappie. The pause is durable and survives automatic supervision and server restarts. The linked session remains on WhatsApp, and existing encrypted history can still be read.

Every paused number records why (`devices.pause_cause`, migration 0051): `person` for a person's or an API key's stop, and for an owner's recovery, which leaves the number paused; `move` for Wappie's own pause around a move to Personal (a person's stop during a move makes it `person`, and the move keeps a person's pause); `deletion` for a deleted number. A failed resume puts back the cause it found. The platform's access snapshot reports a paused number by it ([the contract](contract.md#access-snapshots)): `by_person` only for `person`.

Turning a live number's sync off tells its readers, in Wappie's own pages, until the platform's mails start (decision 0039). Every reader but the one who paused it gets a `sync_paused` notice: in `devices.list`, and pushed as `device.notice` to their open sessions on the same server. A person has at most one unseen notice per number: a later pause folds into it (`pauses`, `last_raised_at`, `several_actors` when someone else paused it before). An API key's pause is its creator's act: the creator is told nothing and is named in the others' notice (`raised_by_kind: "key"`). Only a key with no creator tells every reader. A repeated `device.stop` tells nobody, and so does a pause of a number nobody else reads, which in a personal workspace is every pause by its owner or the owner's key. The pauses Wappie makes on its own (before a move, at a deletion, after a failed resume, at a storage stop) tell nobody. Each pause that tells someone is also an [item event](item-events.md).

`device.start` with the same payload resumes an existing stored WhatsApp session. On a number that is not paused it is Wappie's sync now: it connects the number now, lifts no pause, and a failure leaves the number unpaused, since there was no pause to put back. Both commands return `device.status`. A number that has never paired cannot be resumed this way. A logged-out or banned session cannot be resumed. A stop keeps a logged-out or banned status (it answers and broadcasts that status); a paused, logged-out number is [linked again](#linking-a-number-again), not resumed, and its relink lifts the pause. A resume marks the open pause notices resumed (`resumed_at`); they stay until each reader sees them.

### Who pauses and resumes

Pausing and resuming a number's sync is by role, not by the **manage** permission (the owner's answer of 2026-10-26 to the platform's design of that day, question 1):

- **A person**: in a personal workspace, its person; in a team, its owners and admins. A member never does, whatever their stored flags: **manage** keeps renaming, the receipt mode, pairing retries, groups, backfill and every other act it covered, but not pausing and resuming. Sync now follows **read**, not **manage** or the role (below).
- **An API key**: under its scope, as before: `full`, with the number in its list (a key for every number reaches every one). A `read` or `send` key never does. Only an owner or an admin creates a key.
- **A key that acts as a service account**: the key's `full` scope and the service account's own **manage** permission on the number, as before. A service account acts as itself, not as the person who made it.
- **An assistant connection's key** never does, whatever its scope, like every frame that sends or manages.

Anyone else gets `not_authorized`, before anything about the number changes, and its message names the rule: for a person, that only an owner or an admin of the workspace pauses or resumes a number's sync and that the **manage** permission does not include it; for a key, the scope it needs. `devices.list`, `device.info` and `GET /v1/devices` say who may in `can_pause`. `device.start` on a number that is not paused, which connects it now (sync now), is a reader's: a person needs **read** and the number's key at its current epoch, so an owner or an admin who does not read the number may not, and a member with **manage** but no **read** may not either; a key needs `full` scope with the number in its list, and a service account its own **manage** permission, as for managing (the platform's answer 4 to the design of 2026-10-26, [DS13](decisions.md); the console's `item.sync_now` asks the same). Neither `can_manage` nor `can_pause` says it: a person's client offers it where it reads the number, its grant at the number's current epoch opening, as it decides reading. A `device.start` that finds the number paused is a resume, and is checked on the row whose pause it lifts. Wappie's own pauses (a storage stop, around a move, at a deletion) follow their own rules. A pairing retry of a registration that never linked stays under **manage**, except when the registration is paused: the retry lifts that pause, so it needs the role too, and a member with **manage** gets the same `not_authorized`.

`devices.list` and `device.info` expose `paused` (durable operator preference), `running` (authenticated, online transport on this instance), `can_manage` (effective management authorization), `can_pause` (whether this caller may pause and resume it, [by role](#who-pauses-and-resumes)), and `profile_key` (the device's own contact identifier). A registry reservation alone is not a running connection. Connecting, paused and logged-out devices report `running: false`.

## Unlinking from the phone

Removing Wappie under WhatsApp's linked devices deletes its WhatsApp session and
eventually reports `logged_out`. The supervisor stops without reconnecting that
invalid session. A paused or disconnected instance may only detect the removal
on its next connection attempt. Sending and new synchronization stop, while
authorized readers retain the history and attachments already archived by
Wappie. Pending downloads may finish while their media URLs remain valid.

This does not remove the Wappie device, free its plan slot or cancel a
subscription. Resume and pending-pairing retry do not reconnect an already
linked, logged-out record. The number stays read-only until an owner or an
admin [links it again](#linking-a-number-again), into the same record, with
its history kept. Deleting the number (below) ends its history after 30
days, and is not a way to link it again.

## Linking a number again

A number logged out from its phone, or recovered read-only after a deletion,
is linked again with a new QR into the same device (decision 0057; the
contract's 14.13). Its id, archive key and epoch, grants, readers, label,
receipt mode, messages, attachments, assistant connections and API key
restrictions stay. Only the scanning account decides whether the link is
kept: it must be the number's own.

The request is the `pair` frame's relink branch:

```json
{ "device_id": "UUID", "relink": true, "method": "qr" }
```

`method` may be left out. Anything a new number's pairing carries (`phone`,
`display_name`, `label`, `receipt_mode`, `archive_public_key`, `grants`,
`orphan`, `resume`), `method: "code"` and a `device_id` that is not a UUID
are `bad_request`: a relink pairs by QR only. The
answers, on the request's id: `pair.qr` for each QR, as for a new number;
then `pair.success` (`{ "device_id" }`) once the number names the new link,
or one `error`. A relink never sends `pair.code` or `pair.timeout`. The
build announces it as `pair.relink` in the welcome's `features`; a client
offers it only then, since an older build reads `relink` as a new number.

**Who.** A signed-in owner or admin. An API key of any scope, a service
account and a member are `not_authorized`; a person whose sign-in is older
than 10 minutes gets `step_up_required`; in a team, the person's memberships
must be fresh, as for any pairing.

**Codes**, named as the contract's 14.9 names them, each with a fixed
English message that names no phone number, account or QR. Before any QR, in
this order:

- `storage_paused`: the workspace's storage is paused;
- then the request's own checks: `bad_request`, then who asks
  (`not_authorized`, `step_up_required`, `memberships_unconfirmed` and the
  other freshness codes), then `internal` when this build cannot relink or
  the database fails;
- `not_found`: no live number with that id here;
- `item_busy`, with `retry_after` in whole seconds: another pairing of the
  number runs (the seconds left in WhatsApp's window), or another process
  holds it, or a move's pause holds it (160);
- `state_changed`: the number is not logged out (online, offline, new,
  pairing or banned);
- `read_only`: Wappie does not hold both halves of the number's identity,
  its phone number and its LID, to compare the scan with. A missing half is
  first taken from whatsmeow's map of LIDs and phone numbers;
- `no_reader`: nobody holds the number's key at its current epoch (a
  suspended person still does);
- `number_held`: another live number of this workspace, not logged out and
  not banned, holds the same account.

After the QR: `other_account` (the scan came from another WhatsApp account,
or from the number's own account under another phone number; nothing was
stored), `link_timeout` (WhatsApp's window, about 160 seconds from the first QR,
closed with no scan), `connect_failed` (the link did not start or did not finish: a socket
drop, a passkey step, a client WhatsApp refuses), `number_held`,
`storage_paused` and `state_changed` (the number was paused, deleted or moved
meanwhile, or its workspace stopped being active). `capacity_reached` is
named but never answered today: the logged-out number keeps its place.

**The same account, before anything is stored.** Wappie compares the user
parts of the scanned link's phone number and LID with the number's, never
the device numbers, since a new link has a new one. The phone is checked in
whatsmeow's pre-pair callback. Both halves are checked again in the session
store's first write of the new link: a mismatch refuses that write, and
whatsmeow then stores nothing (no session, no LID pair, no identity key) and
never confirms the link to WhatsApp.

**Until the attach** the number's row does not change: it stays logged out,
and paused if it was. The pairing's client does not reconnect after the
pairing, and nothing of the new link reaches the archive, the status or the
calls handler. Once WhatsApp confirmed the link, one transaction attaches it,
only if the number is still what the relink saw: live, logged out, not
paused since, not held by a move, its workspace active with its storage
running, and the account held by no other live number. It names the new
link (phone number, LID, push name), marks the number offline, and lifts its
pause and marks its open `sync_paused` notices resumed. Then the client
connects and the number goes online. A refused attach logs the new link out
again (the phone may keep an entry under Linked devices when WhatsApp does
not confirm the logout).

The attach deletes no session. whatsmeow deleted the old link's own when the
phone logged it out. A session under the old link's JID now may be another
workspace's live link, since WhatsApp can give the account's freed device
number to a new link and `number_held` asks this workspace only. A dead one
left behind is named by no number, so nothing loads it; `relink attached`
logs it as `old_session_left`. The old link's privacy tokens go unless a
session under its JID exists.

**A cancel or the window's end after the scan.** Once the account passed
the check, whatsmeow stores the link and confirms it to WhatsApp on its own.
A cancel (`pair.cancel`, the page closing, a pause) or the window's end that
lands in that moment waits for whatsmeow's own end: a link WhatsApp
confirmed is attached as on a success, under the same compare-and-set, so a
pause or a deletion meanwhile still refuses it and logs it out; a link
whatsmeow gave up on was already deleted by whatsmeow and ends as
`connect_failed`. A relink's own deadline is a few seconds past WhatsApp's
window, so the last QR shown stays good until it expires.

**After the link**, WhatsApp sends its history again, as for a first link:
the recent window, with what arrived while the number was unlinked, as far
as the phone's history reaches. A direct message already stored under the
conversation's other key (its LID or its phone number) is dropped as a
duplicate, and a reaction, edit or delete that arrives after its target
finds it under either key; one that arrives before its target is matched
later under its own key only. Message secrets of older messages went with
the old session, so a later edit or poll vote on them stays unopened.

Readers and assistants are not told: the key and epoch do not change, and an
assistant allowed to send from the number can send again once it is online.
A relink is not a new link: no `linked` event, no new plan place, no trial
check, and no item event. The log names the device, never the phone, the
account or the QR: `relink started`, `relink refused` (with `code`, `stage`,
and `half` for a scan by another account), `relink attached`, and the first
QR's length as `pairing QR`.

A pairing ends only its own hold of the number, and the supervisor releases
only the hold it decided on, so neither stops a later pairing of the same
number.

**A new number with an account the workspace holds.** A new number's
pairing ("Adicionar número") does not yet compare the scanned account with
the workspace's other numbers. Linking a logged-out number's phone as a new
number makes a second live number of the same account, which captures
everything twice, and while it is live the first number's relink is
`number_held`. Link a logged-out number again instead of adding it.

## Pending pairing

A new `pair` still requires a client-generated archive public key and encrypted grants. Its provisional row is removed when the attempt times out, fails or is cancelled before pairing completes. Cleanup never removes an identity that has already paired or connected.

To retry an existing incomplete row, send `pair` with `{ "device_id": "UUID", "resume": true, "method": "qr" }`. Code pairing also accepts `method: "code"` and `phone`. The existing encryption key, grants and receipt mode are preserved. Supplying replacement `archive_public_key`, `grants` or `orphan` with a retry is rejected. A retry cannot replace an already linked number. An incomplete legacy row without an archive key must be deleted and recreated.

A relink is not a retry: `resume` together with `relink` is refused ([linking a number again](#linking-a-number-again)).

`pair.cancel` cancels the caller's pending attempt. Deleting a number also cancels a pending attempt from another browser in the same workspace.

## Deletion and recovery

`device.delete` requires `{ "device_id": "UUID", "confirm": "UUID", "acknowledged_readers": ["UUID", ...] }`, repeating the exact full identifier. Ask `device.delete.check` first: it lists who reads the number now, the standing service accounts, the assistant connections and API keys that lose it, and the keys for every number that stop reaching it. Every reader in that list must be acknowledged, or the deletion is refused with `device_has_readers` and the current list in the error's `readers`. The deletion asks for a recent sign-in (`step_up_required`). An API key cannot delete a number, and anyone but an owner gets `owner_only` for a live number and `not_found` for a deleted one, so nobody learns by probing an id that a number is deleted.

A deletion always asks WhatsApp to log the session out, which cannot be undone: `unlink` may be omitted, and `unlink: false` is refused for a linked number. The logout runs after the deletion has committed, with a bounded wait. `device.deleted.unlinked` is true when no WhatsApp session is left, and `note_code` is `unlink_unconfirmed` when WhatsApp did not confirm (remove the session under Linked devices on the phone; the hourly maintenance tries the logout again until three attempts have been made, the deletion's own included, and the purge removes the session it left, by its fingerprint, without logging it out) or `already_disconnected` when there was no session. A retry of a deleted number answers `already: true` with the stored state. A client that lost the reply should ask `devices.deleted` rather than send `device.delete` again: had an owner recovered the number meanwhile, the retry would delete it again, and log it out.

A deleted number is kept 30 days with its data, readable by nobody, then purged. `deleted_at` and `recoverable_until` are the database's clock. Its plan slot is freed at once; its bytes stay counted until the purge ([storage](storage.md#consistent-totals-by-number)). Assistant connections and AI authorizations whose key names it end with `access_lost`. No API key is revoked: a key restricted to chosen numbers loses this one and keeps working for the others (one left with none reaches nothing), and a key for every number reaches it again after a recovery.

Owners list deleted numbers with `devices.deleted` (replying `devices.deleted.list`: each one's dates, who deleted it, its bytes, `recoverable`, `purging`, the stored WhatsApp note and how it would come back) and recover one with `device.recover` (`{ "device_id", "confirm" }`, after a recent sign-in; `device.recover.check` lists who regains access). A recovered number comes back paused, and read-only when WhatsApp confirmed its logout, the normal case (`logged_out: true`, `can_resume: false`): an owner or an admin then [links it again](#linking-a-number-again). Only a logout WhatsApp did not confirm leaves a session that can sync again. People who left or were disabled meanwhile get nothing back, assistant connections do not return, and restricted keys need the number given again. Refusals: `recovery_closed` after the 30 days or once the purge has started, `capacity_reached`, `identity_in_use` when the phone was linked again as another number, and `device_busy` while the logout is still running.

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

A workspace with deleted numbers refuses `reset-archive` until each is recovered or purged. A reset takes everyone's Read, so before its deletes it ends every live assistant connection and AI integration of the workspace, `access_lost` ([DS48](decisions.md)). A move to Personal never takes a deleted number: it cannot be found.

No platform call runs inside the store transaction of a deletion, a recovery, a stop or a move to Personal. In a team the platform names, each asks the contract's freshness hook before its transaction, never inside it: a deletion, a recovery and a person's stop for the actor (a GET when their document is over an hour old), a move for the mover always ([freshness](contract.md#freshness)). In this release the hook only logs what it would refuse; nothing waits on it but its GET, bounded to 5 seconds.

### Moving a number to Personal

See [moving a number from Team to Personal](device-personal-transfer.md): a number moves only while nobody else has access to it.

## Resetting the archive

`whatserverd reset-archive -tenant <id> -yes-destroy-everything` removes everything sealed for a workspace: messages, chats, contacts, attachments, archive keys and grants. There is no undo. It refuses while a deleted number waits for its purge ([the purge](#the-purge)). Before its deletes it ends every live assistant connection and AI integration of the workspace, `access_lost` ([DS48](decisions.md)); people connect them again afterwards, and `wappie-api` tells their readers.

A running `wappie-api` needs no restart. The reset and each `device-key` tell every process at their commit, and a running server drops what it loaded for those numbers, so it seals to the number's new key from the next message on ([DS49](decisions.md)). Each new content key is also checked against the number's key. Before DS49 a running server kept sealing to the old key until it restarted, so this runbook stopped `wappie-api` for every reset; that is no longer needed.

The reset holds the workspace's lock to its end, and ingest needs that lock for every message, so the workspace's ingest waits while the reset runs. On a large archive, stop `wappie-api` before the reset and start it after; the steps do not change.

Without `-keep-devices` the reset removes the numbers too. Pair each number again, which makes its new key.

With `-keep-devices` the numbers stay paired, with no archive key, until `device-key` gives each a new one. A message that arrives in between is not stored: the number has no key. Run, in this order:

1. `whatserverd reset-archive -tenant <id> -keep-devices -yes-destroy-everything`.
2. `whatserverd device-key -device <id> -grant <email>` for each number.

`device-key` refuses an assistant connection's own account, before it makes the key. The reset prints these steps.

The new key takes epoch 1 again, so a grant names its key by a fingerprint, not by the epoch alone. A browser that read its grants before the reset has its next grant refused with `conflict`, and reads them again ([DS49](decisions.md)).

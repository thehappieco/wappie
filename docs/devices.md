# Device lifecycle

A device is a WhatsApp number linked to a workspace. Internal labels are independent of the WhatsApp profile. Profile pictures use the existing encrypted contact/avatar path and require read permission plus a usable device key.

All commands below use WebSocket v1 frames (`t`, `r`, `p`). The session and device must belong to the same workspace. `device.rename`, `device.stop`, `device.start` and retries require the device's **manage** permission and an API token scope that permits management, when a token is used. Deleting a linked number requires an owner's person session, in every workspace, a personal one included; removing a registration that never linked requires an owner or administrator.

## Rename

`device.rename` with `{ "device_id": "UUID", "label": "Support" }` returns `device.detail`. The trimmed label must contain 1–100 characters. It changes neither the WhatsApp profile nor the device's encryption key, grants or history.

## Pause and resume

`device.stop` with `{ "device_id": "UUID" }` pauses synchronization and sending through Wappie. The pause is durable and survives automatic supervision and server restarts. The linked session remains on WhatsApp, and existing encrypted history can still be read.

`device.start` with the same payload resumes an existing stored WhatsApp session. Both commands return `device.status`. A number that has never paired cannot be resumed this way. A logged-out or banned session cannot be resumed.

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
while preserving history remains unimplemented; permanent deletion below
erases history and is not an equivalent recovery operation.

## Pending pairing

A new `pair` still requires a client-generated archive public key and encrypted grants. Its provisional row is removed when the attempt times out, fails or is cancelled before pairing completes. Cleanup never removes an identity that has already paired or connected.

To retry an existing incomplete row, send `pair` with `{ "device_id": "UUID", "resume": true, "method": "qr" }`. Code pairing also accepts `method: "code"` and `phone`. The existing encryption key, grants and receipt mode are preserved. Supplying replacement `archive_public_key`, `grants` or `orphan` with a retry is rejected. A retry cannot replace an already linked number. An incomplete legacy row without an archive key must be deleted and recreated.

`pair.cancel` cancels the caller's pending attempt. Deleting a number also cancels a pending attempt from another browser in the same workspace.

## Deletion and recovery

`device.delete` requires `{ "device_id": "UUID", "confirm": "UUID", "acknowledged_readers": ["UUID", ...] }`, repeating the exact full identifier. Ask `device.delete.check` first: it lists who reads the number now, the standing service accounts, the assistant connections and API keys that lose it, and the keys for every number that stop reaching it. Every reader in that list must be acknowledged, or the deletion is refused with `device_has_readers` and the current list. The deletion asks for a recent sign-in (`step_up_required`).

A deletion always asks WhatsApp to log the session out, which cannot be undone: `unlink` may be omitted, and `unlink: false` is refused for a linked number. The logout runs after the deletion has committed, with a bounded wait. `device.deleted.unlinked` is true when no WhatsApp session is left, and `note_code` is `unlink_unconfirmed` when WhatsApp did not confirm (remove the session under Linked devices on the phone; the hourly maintenance retries the logout, at most three times) or `already_disconnected` when there was no session. A retry of a deleted number answers `already: true` with the stored state.

A deleted number is kept 30 days with its data, readable by nobody, then purged. Its plan slot is freed at once; its bytes stay counted until the purge. Assistant connections whose key names it end with `access_lost`. No API key is revoked: a key restricted to chosen numbers loses this one and keeps working for the others (one left with none reaches nothing), and a key for every number reaches it again after a recovery. Readers and the workspace's other owners get a notice in `devices.list`, acknowledged with `device.notice.seen`.

Owners list deleted numbers with `devices.deleted` and recover one with `device.recover` (`{ "device_id", "confirm" }`, after a recent sign-in; `device.recover.check` lists who regains access). A recovered number comes back paused, and read-only when WhatsApp confirmed its logout. People who left or were disabled meanwhile get nothing back, assistant connections do not return, and restricted keys need the number given again. Refusals: `recovery_closed` after the 30 days, `capacity_reached`, `identity_in_use` when the phone was linked again as another number, and `device_busy` while the logout is still running.

Removing or disabling the last key holder of a deleted number is refused with `last_reader_of_deleted` until its purge: recover it and share its key first. Disabling a person also revokes the API keys they created.

A registration that never linked has no data and is still removed at once (`device.deleted.pending`).

No platform call runs inside the deletion's or the recovery's store transaction.

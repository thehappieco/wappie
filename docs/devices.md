# Device lifecycle

A device is a WhatsApp number linked to a workspace. Internal labels are independent of the WhatsApp profile. Profile pictures use the existing encrypted contact/avatar path and require read permission plus a usable device key.

All commands below use WebSocket v1 frames (`t`, `r`, `p`). The session and device must belong to the same workspace. `device.rename`, `device.stop`, `device.start` and retries require the device's **manage** permission and an API token scope that permits management, when a token is used. Permanent deletion requires an owner or administrator's person session.

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

## Permanent removal

`device.delete` requires `{ "device_id": "UUID", "confirm": "UUID" }`, repeating the exact full identifier. Disconnecting from WhatsApp is the default when `unlink` is omitted; API clients may explicitly send `unlink: false` to retain the old optional behavior. The console always requests unlinking.

For a paused device, the server briefly reconnects the stored session in passive mode to request logout. WhatsApp disconnection is bounded and best effort. `device.deleted.unlinked` reports WhatsApp acknowledgement, and `note` explains if the user must remove the linked session manually on the phone. The Wappie device, history, key grants and media references are deleted even when WhatsApp is unreachable; unreferenced attachment objects are removed afterward.

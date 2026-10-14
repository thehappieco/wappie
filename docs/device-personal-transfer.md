# Move a number from Team to Personal

In the console, open the number's details and choose **Move to Personal**. The preview shows the destination and required space; **Confirm transfer** performs the move.

## Requirements and outcome

- You must be the Team's sole owner and hold the keys to the number's complete history.
- Nobody else may have access to the number (decision 0040), so a move never ends anyone's reading, sending or integration. Otherwise it is refused with `others_have_access`, naming who still has access (below).
- The destination is your own active Personal workspace, with an available number binding and storage capacity.
- History, attachments, WhatsApp identity and keys are preserved. The Team's API keys for every number, and your own keys limited to chosen numbers, stop reaching it; another member's key limited to it blocks the move until it is revoked.
- Your own assistants and AI authorizations connected to the number end, with `access_lost`.
- The number is paused when the transfer completes. Select **Open Personal workspace**, check the history, then choose **Resume synchronization** in the number's details.
- The Team's subscription is not transferred: the operation uses capacity already available in Personal. There is no automatic purchase.
- For an external installation, the app attempts to replace the commercial binding with the same number in the remote Personal workspace. If the license update fails, the operational transfer remains complete; use **Retry license update** or replace the binding under **Installations and licenses**.

The move does not erase content someone has already exported or keys they have already obtained. It ends future access through the Team.

## Who has access

These block a move:

- a person or a standing service account with Read, Send, or a key grant at any archive epoch that is not retired, whatever their membership's status (a disabled member keeps rows the move would delete);
- a member's Manage permission (not an owner's or an administrator's: their role manages every number, and the permission adds nothing);
- another person's live assistant connection or AI authorization whose key names the number, or whose service account holds a grant or a permission for it;
- another person's Integrations key restricted to the number, acting as nobody and behind no connection.

A key or a connection whose creator is gone still counts. These do not: keys for every number, your own restricted keys and connections (the move narrows and ends them), keys acting as a service account (the account itself is what counts), and an owner's or administrator's role.

`device.transfer.preview` answers `eligible: false`, `reason_code: "others_have_access"` and `others`, and `device.transfer` answers the error `others_have_access` with the same list in `others`. Each entry has a `kind` (`person`, `service`, `assistant`, `ai` or `key`), `why` (`read`, `send`, `manage`, `key`, or `old_key` for a grant only at an older epoch, which still opens older history), and, as they apply, `status`, `user_id`, `name`, `email`, `connection_id`, `client_name`, `key_id`, `key_name` and `created_by_name`. The preview also lists what the move would narrow and end (`keys`, `all_number_keys`, `assistants_ended`); the reply says what it did (`keys_narrowed`, `assistants_ended`).

The console gives each entry its way out: remove a person's or service account's access to the number (a disabled member can only be removed from the workspace), end the assistant or AI authorization under MCP or AI, or revoke the key under Integrations (and create another one without this number if it is still in use). Then **Check again**.

A server announces this rule with `device.transfer.access` in the welcome's features. An older server moves the number anyway and removes everyone else's access, so a console must not tell an owner that nobody else has access unless the server announces it.

## Server guarantees

The transfer runs in a transaction that locks both workspaces and WhatsApp supervision. Owner, access, capacity and key checks are repeated within that transaction: every change that gives access takes the Team's lock first, and one that waits for it finds the number gone. A refusal or any failure leaves the number as it was, its sync included: the server pauses the number just before the move, and takes that pause back when the move does not happen, unless someone paused or resumed the number in the meantime. A move that committed but whose answer was lost answers `not_found`; the number is then in Personal, paused.

`devices.archive_tenant_id` preserves the original cryptographic namespace. Authorization and billing continue to use `tenant_id`. Clients must use the namespace advertised in devices, grants and keys; this release's SDKs and CLIs already do so. Update older clients before opening a transferred number's archive.

Objects are not rewritten. Each workspace has its own usage ledger; an internal physical-owner index prevents an object from being deleted while another workspace still depends on it. Transfer history records the actor, source, destination and time. Message and event sequences are reassigned without changing identifiers or encrypted envelopes.

The Team records a `moved_out` [event](item-events.md), with its readers before the move (at most you). The deletion ledger keeps it, so a restore from a snapshot taken before the move never puts the number back in the Team ([restoring a backup](deployment.md#restoring-a-backup)). Once the platform contract's transport exists, the platform tells the Team's other owners from it; while only the Team's sole owner may move a number, there is nobody to tell. Other sessions that saw the number get `device.removed` with `reason: "moved"`. A deleted number cannot be moved.

## Upgrade and rollback

Stop old API, capture and maintenance processes before applying migrations 36 and 37. An older object collector does not know about shared physical owners.

Keep backups of the database, objects and previous artifacts. After a transfer, a frontend rollback can keep the current backend; do not run a backend from before these migrations against this database or bypass the version check. A full restore must be coordinated to preserve messages received since the backup as well.

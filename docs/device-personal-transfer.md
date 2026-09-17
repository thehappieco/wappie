# Move a number from Team to Personal

In the console, open the number's details and choose **Move to Personal**. The preview shows the destination and required space; **Confirm transfer** performs the move.

## Requirements and outcome

- You must be the Team's sole owner and hold the keys to the number's complete history.
- The destination is your own active Personal workspace, with an available number binding and storage capacity.
- History, attachments, WhatsApp identity and keys are preserved. Other members' permissions and the Team's API key permissions are removed.
- The number is paused when the transfer completes. Select **Open Personal workspace**, check the history, then choose **Resume synchronization** in the number's details.
- The Team's subscription is not transferred: the operation uses capacity already available in Personal. There is no automatic purchase.
- For an external installation, the app attempts to replace the commercial binding with the same number in the remote Personal workspace. If the license update fails, the operational transfer remains complete; use **Retry license update** or replace the binding under **Installations and licenses**.

The move does not erase content someone has already exported or keys they have already obtained. It ends future access through the Team.

## Server guarantees

The transfer runs in a transaction that locks both workspaces and WhatsApp supervision. Owner, capacity and key checks are repeated within that transaction. A failure leaves the archive in the Team; the number may remain paused so you can retry or resume it.

`devices.archive_tenant_id` preserves the original cryptographic namespace. Authorization and billing continue to use `tenant_id`. Clients must use the namespace advertised in devices, grants and keys; this release's SDKs and CLIs already do so. Update older clients before opening a transferred number's archive.

Objects are not rewritten. Each workspace has its own usage ledger; an internal physical-owner index prevents an object from being deleted while another workspace still depends on it. Transfer history records the actor, source, destination and time. Message and event sequences are reassigned without changing identifiers or encrypted envelopes.

## Upgrade and rollback

Stop old API, capture and maintenance processes before applying migrations 36 and 37. An older object collector does not know about shared physical owners.

Keep backups of the database, objects and previous artifacts. After a transfer, a frontend rollback can keep the current backend; do not run a backend from before these migrations against this database or bypass the version check. A full restore must be coordinated to preserve messages received since the backup as well.

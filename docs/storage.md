# Workspace storage — accounting rule 1

Storage capacity belongs to a workspace, shared by its hosted numbers. It is a
separate commercial package from app bindings. The standalone server defaults
to unlimited; a hosting operator can explicitly configure its local policy.
External archive bytes are never added to central Wappie storage consumption.

## Billable usage

Rule 1 counts canonical persisted archive fields: UTF-8 field names/scalars and
actual binary byte lengths. Canonical sealed message raw content takes priority;
its rebuildable body/payload/attachment projections are not charged again.
Without raw content, those sealed fields are the canonical source. Contacts,
receipts, independent chat metadata, group members and group changes count.

Confirmed stored ciphertext object bytes count once per object key within the
workspace, even when several messages reference that object. Backups, replicas,
indexes, database free space, sessions, journal/replay copies, read badges and
latest-message projections are included in the service. This is a documented
logical archive measure, not physical database file size or message size hints.

Inventory deltas and reservations use workspace locks and commit with archive
writes. Object uploads reserve before writing and serialize completion against
deletion. An uncertain upload or deletion conservatively retains its charge
until confirmed cleanup. Retention and authorized deletion lower logical data
usage; object usage falls only after the last reference and successful physical
deletion. Maintenance retries orphan cleanup. Reconciliation rebuilds inventory
from persisted data and preserves unresolved object reservations.

## Consistent totals by number

The administrative storage response and private storage summary include a
`breakdown` measured in the same transaction as the workspace total. Each
`devices` row includes identity, label, `archive_bytes`, `object_bytes` and
`used_bytes`. It uses the canonical archive inventory, including contacts,
receipts and group data, plus actual object bytes. It never uses WhatsApp's
reported `file_length` as occupied storage.

Files referenced by more than one number appear once under `shared`. Object
reservations without a current number reference and files awaiting confirmed
physical deletion appear under `unassigned`. All device rows plus these two
buckets sum to the workspace total, separately for archive, objects and overall
usage. Deleting a number can move a shared file to the remaining number or to
pending deletion; it does not count the file twice or free bytes prematurely.

`devices.stats` and `device.info` expose the same per-number categories.
`media_bytes` now reports the exclusive object bytes, matching `object_bytes`;
older servers returned a sum of reported media lengths. Clients should use
`used_bytes` for the number's storage total and the administrative breakdown to
understand shared and pending files. A detailed read scans the inventory only
on administration requests; ingestion quota checks remain lightweight.

## Limits and recovery

Warnings occur at 80%, 90% and 100%. At 100%, a free grace period lasts up to
72 hours or 5% additional capacity, whichever ends first. After that the
workspace records a durable capture suspension. Transactions that would exceed
the hard cap roll back; concurrent writers cannot spend the same allowance.

Suspension blocks new capture, sends, archive writes, pairing/reconnection,
backfill, upload and attachment retrieval into storage. The supervisor detaches
active WhatsApp connections within its next 30-second check. Existing archive
queries, attachment reads, export and authorized deletion/administration remain
available. Device manual pause is separate from workspace storage suspension.

Purchasing capacity or deleting data does not automatically reconnect devices.
An administrator explicitly resumes after usage is below the limit. No automatic
purchase or history deletion occurs. Durable pause/resume events identify the
interrupted interval. Recovery of missing messages/media is only an attempt;
WhatsApp may no longer have them available.

## Public administration

Owner/admin session endpoints:

- `GET /v1/auth/workspaces/storage`: categories, capacity, warnings and grace/pause.
- `GET /v1/auth/workspaces/storage/history`: recent durable policy/warning/pause events.
- `POST /v1/auth/workspaces/storage/reconcile`: rebuild measurement.
- `POST /v1/auth/workspaces/storage/resume`: explicit resume when capacity permits.

The browser cannot grant itself capacity. Operators with database configuration
can inspect/set policy using the server CLI:

```
whatserverd storage -tenant UUID
whatserverd storage -tenant UUID -reconcile
whatserverd storage -tenant UUID -limit-bytes 10737418240
whatserverd storage -tenant UUID -resume
whatserverd storage -tenant UUID -unlimited
```

Migration 0035 requires an explicit baseline for existing workspaces before applying limits. The response exposes `measurement_ready`; run reconciliation while unlimited before selling/applying a hosted package.

Hourly samples retain 90 days of usage. After at least 24 hours, net growth over up to seven days produces `daily_growth_bytes` and, when growth is positive, `estimated_full_at`. This is an estimate, affected by retention/deletion and changing capture rates. No date is invented for missing history or paused capture.

Measure existing workspaces before applying limits. The private catalog defines
package sizes/prices; frontend extraction does not require those values. Stripe
sandbox subscriptions remain separate from operational pilot capacity. Explicit
simulated purchases can exercise quota changes in the test installation.


### Moving numbers between workspaces

Migration 0037 mirrors logical object reservations into an internal physical
ownership index. A transferred number can keep its existing ciphertext keys;
no download, decryption or re-upload is needed. Each workspace counts only its
own retained reservations. Cleanup of a source reservation cannot delete an
object still protected by another workspace. Only the last owner performs the
physical deletion, and failures retain its charge for retry.

All ownership insertion/deletion and physical cleanup serialize on an advisory
lock per object key, after workspace locks. A transfer must hold both source
and destination workspace locks until the destination reservations and archive
references commit, and acquire multiple new object keys in sorted order.
Byte-only updates of existing reservations retain ownership without collecting
new physical locks. The ownership index has no public endpoint and contains
no message content or encryption keys.

# Presence and message deletion

`presence.subscribe` observes the peer in a direct conversation. Send a WebSocket request with `device_id` and `chat` (a phone or LID JID). The reply uses the same frame type with `subscribed` and, when unavailable, `reason`: `incognito`, `disconnected` or `unavailable`. Device read permission and an archive grant are required. Groups, channels and broadcast lists are rejected.

Live `presence` events now also carry `state: "available"` or `"unavailable"`; `"composing"` and `"paused"` retain their typing meaning. A reported last-seen timestamp may appear as `last_seen`. Events are ephemeral: they are never archived, replayed or assigned an archive cursor. Missing or stale information means unknown, not offline. The web client only subscribes for the visible direct conversation and expires old observations.

Subscribing never announces the account online or changes its receipt mode. Incognito suppresses the request, since obtaining presence must not silently undo privacy settings. Upstream availability also depends on WhatsApp and the contact's privacy settings. See [whatsmeow's presence implementation](https://github.com/tulir/whatsmeow/blob/main/presence.go).

For user sessions, `reader.mode` changes only the authenticated person's preference for one number. Send `{ "device_id": "…", "receipt_mode": "passive" }` (or `"active"`); the response has the same type and fields. Read access and the current archive-key grant are required. New preferences default to `passive`, regardless of the number's transport setting. `devices.list` and `device.info` expose this preference as `reader_receipt_mode`; updates are also pushed to that person's other sessions in the same workspace. The web app uses this preference for its incognito switch.

The server suppresses a discreet user's `message.read` before changing unread counters or sending read/played receipts. Their typing and presence-subscription requests are suppressed too. An active user's explicit read/typing actions are permitted without changing another member's preference. `device.mode` remains the shared transport control for existing operators, CLI and API integrations; personal preference changes never invoke it or announce the number online.

For a user session, `message.read` (including `played`) requires read access; typing and sending content require send access. Machine/API credentials keep the existing send scope and device permission for `message.read`.

WhatsApp presence and conversation badges belong to the number: another teammate, an API integration, or the phone can still announce presence and confirm reads. Incognito governs the current user's actions; it cannot undo those independent actions. It does not create separate per-user unread counts.

`message.history` deletion attribution now includes optional `by_admin`. The server compares the original author with the revocation sender, including known phone/LID aliases. Direct-chat revocations are attributed to the sender; administrator attribution requires evidence of a different sender in a group. When neither `by_author` nor `by_admin` is established, clients should display a neutral deletion label. Existing messages benefit without rewriting their stored content.

The web client preserves deleted content with reduced opacity and strikethrough. Edited, disappearing and deleted indicators are compact icons; their accessible descriptions remain in message actions and history.

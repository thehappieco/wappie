# Presence and message deletion

`presence.subscribe` observes the peer in a direct conversation. Send a WebSocket request with `device_id` and `chat` (a phone or LID JID). The reply uses the same frame type with `subscribed` and, when unavailable, `reason`: `incognito`, `disconnected` or `unavailable`. Device read permission and an archive grant are required. Groups, channels and broadcast lists are rejected.

Live `presence` events now also carry `state: "available"` or `"unavailable"`; `"composing"` and `"paused"` retain their typing meaning. A reported last-seen timestamp may appear as `last_seen`. Events are ephemeral: they are never archived, replayed or assigned an archive cursor. Missing or stale information means unknown, not offline. The web client only subscribes for the visible direct conversation and expires old observations.

Subscribing never announces the account online or changes its receipt mode. Incognito suppresses the request, since obtaining presence must not silently undo privacy settings. Upstream availability also depends on WhatsApp and the contact's privacy settings. See [whatsmeow's presence implementation](https://github.com/tulir/whatsmeow/blob/main/presence.go).

`message.history` deletion attribution now includes optional `by_admin`. The server compares the original author with the revocation sender, including known phone/LID aliases. Direct-chat revocations are attributed to the sender; administrator attribution requires evidence of a different sender in a group. When neither `by_author` nor `by_admin` is established, clients should display a neutral deletion label. Existing messages benefit without rewriting their stored content.

The web client preserves deleted content with reduced opacity and strikethrough. Edited, disappearing and deleted indicators are compact icons; their accessible descriptions remain in message actions and history.

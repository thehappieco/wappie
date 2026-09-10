# Conversations, groups, and polls

Use these commands after the WebSocket `hello` handshake. Every request includes
`device_id`; authorization is checked for that device and workspace on every
command. `welcome.features` advertises support. The device must be connected to
WhatsApp. A `send` token cannot administer groups; administration requires both
`full` token scope and the device's management permission.

## Start a conversation

```json
{"t":"chat.start","r":"new-chat-1","p":{"device_id":"DEVICE_UUID","phone":"+5511999999999"}}
```

Checks whether the international number is registered and opens a conversation
without sending a message. No country code is guessed. Returns `chat.started`
with `{ "chat": "CANONICAL_WHATSAPP_JID" }`. Use that exact address in
`message.send`, then request `chats.list` or `chat.page` as usual. Requires send
permission. A number not registered returns `not_found`.

## Create and manage groups

```json
{"t":"group.create","r":"create-group-1","p":{"device_id":"DEVICE_UUID","name":"Support team","participants":["+5511999999999","123456@lid"]}}
{"t":"group.participants.update","r":"add-1","p":{"device_id":"DEVICE_UUID","chat":"120363123@g.us","action":"add","participants":["+5511888888888"]}}
{"t":"group.participants.update","r":"remove-1","p":{"device_id":"DEVICE_UUID","chat":"120363123@g.us","action":"remove","participants":["123456@lid"]}}
{"t":"group.leave","r":"leave-1","p":{"device_id":"DEVICE_UUID","chat":"120363123@g.us"}}
```

Group names accept 1–100 characters. Creation and participant changes accept
1–32 individual accounts per operation, as international numbers, phone JIDs,
or LIDs. Creation includes the connected WhatsApp account automatically.
Adding/removing participants requires that account to be a current WhatsApp
group administrator. Leaving requires current membership. The server checks
WhatsApp immediately before the action; workspace ownership alone does not
make someone an administrator of a WhatsApp group.

These commands return `group.changed` with `chat`, `action`, `refreshed`, and
when applicable `participants: [{jid, error?}]`. WhatsApp can create a group yet
refuse individual additions because of privacy or membership restrictions.
A nonzero participant `error` is a refusal, not a successful addition. Reload
`group.info` with `refresh:true` for current membership. Its
`permissions_known`, `is_member`, and `can_manage` describe the connected
WhatsApp account from a fresh response. Check the device's `can_manage` too.
`refreshed:false` means the action completed but a current local snapshot was
not confirmed. No unavailable membership or timestamp is inferred.

Creation, removal and leaving are explicit actions visible on WhatsApp. Never
retry them automatically after a timeout or connection loss: the remote action
may already have completed. Inspect the group in WhatsApp before retrying.
Leaving keeps the stored conversation history.

## Create a poll

```json
{"t":"message.poll.create","r":"poll-1","p":{"device_id":"DEVICE_UUID","chat":"120363123@g.us","id":"CLIENT_MESSAGE_ID","question":"Which day?","options":["Monday","Tuesday","Friday"],"selectable_count":1}}
```

Requires send permission. Works in individual conversations and groups. The
question accepts 1–255 characters and there must be 2–12 distinct, nonempty
options of up to 100 characters. Leading/trailing spaces are trimmed.
`selectable_count:1` permits one answer; `0` permits multiple answers. Returns
`message.sent`, and the sealed poll arrives through the normal event stream.
The chat's disappearing timer applies. Existing `message.poll.vote` handles
voting and withdrawing a vote. A timeout does not imply delivery failed; check
for the message before attempting another send.

The implementation uses the [whatsmeow APIs for the pinned version](https://pkg.go.dev/go.mau.fi/whatsmeow@v0.0.0-20260821141805-33cfac511629).

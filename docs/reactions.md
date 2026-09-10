# Message reactions

Send `message.react` over the authenticated WebSocket with send permission
for the selected device:

```json
{"t":"message.react","r":"react-1","p":{"device_id":"DEVICE_UUID","chat":"CHAT_JID","target_id":"ORIGINAL_MESSAGE_ID","sender":"ORIGINAL_AUTHOR_JID","emoji":"👩🏽‍💻"}}
```

`emoji` must be one complete emoji from Unicode 17. A complete emoji can
contain multiple code points: families, skin tones, flags and keycaps are
valid. Official presentation aliases such as `❤` normalize to `❤️`. Text,
multiple emoji and standalone tone/hair components return `bad_request`.
Send `"emoji":""` to remove your reaction. The server acknowledges a
successful operation with `message.sent`; do not automatically repeat an
operation whose acknowledgement was lost.

The web client offers quick reactions, a categorized picker and an input
for the device's emoji keyboard or pasted emoji. Selecting your current
reaction again removes it; the picker also has an explicit removal button.
Blank input does not submit or remove a reaction by itself.

Current reactions are grouped by emoji and sorted by count, highest first.
Presentation aliases share a group; skin tones and composed sequences remain
distinct. Four groups appear over the bubble, with `+N` for additional groups.
Message information shows all current groups and users, followed by the
existing reaction history. Historical received emoji are preserved even if
they are outside the current outbound catalogue.

The shared browser/server catalogue is generated from the pinned
[Unicode 17 emoji data](https://www.unicode.org/Public/17.0.0/emoji/emoji-test.txt).
See `internal/emoji/generate.py` and `internal/emoji/LICENSE-UNICODE.txt`.

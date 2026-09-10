# Sending a fixed location

`message.send.location` requires send permission for the device and accepts
an individual or group chat. Both coordinates must be present and numeric;
latitude must be between −90 and 90 and longitude between −180 and 180.
Explicit zero is valid.

```json
{"t":"message.send.location","r":"position-1","p":{"device_id":"DEVICE_UUID","chat":"CHAT_JID","id":"UNIQUE_MESSAGE_ID","lat":59.437,"lon":24.7536,"name":"Meeting point","address":"Tallinn","accuracy_m":15}}
```

The optional `name` allows 100 Unicode characters, `address` allows 500 and
`accuracy_m` is an unsigned integer in metres. `id` is optional; provide a
unique ID when correlating an outbound message. The chat's disappearing
timer applies. A successful send returns `message.sent` and follows the
ordinary encrypted archive and projection pipeline. Validation failures
return `bad_request`; missing permission returns `not_authorized`.

A missing acknowledgement does not prove the send failed. Check the chat
before manually retrying; the web dialog prevents repeating an uncertain
submission automatically.

The web app provides an explicit **Use my current position** button and
manual coordinates. Obtaining a position does not send it. The user reviews
the coordinates and confirms the send. Browser location permission is only
requested after pressing the button, with a ten-second timeout; denial still
allows manual entry. There is no movement watcher. Map links open only after
the user chooses them; no map tiles or geocoding service load automatically.

Geolocation is allowed for the application origin, with the browser's usual
permission prompt; the session bridge keeps geolocation disabled. See
[getCurrentPosition](https://developer.mozilla.org/en-US/docs/Web/API/Geolocation/getCurrentPosition).

## Live locations

This command sends a **fixed point**, including when that point comes from
GPS. Sending another point creates another message, not an update to the
previous card. It does not claim to share a live location.

The pinned WhatsApp integration has protobuf types for live locations and
the archive can normalize incoming live-location cards. The application
does not yet implement or verify the full start/update/stop lifecycle needed
for outbound live sharing. That feature is deferred; changing coordinates
in a fixed-location message is not a substitute for that lifecycle.

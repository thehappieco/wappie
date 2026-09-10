# Native WhatsApp events

`message.event.create` creates a native WhatsApp event in an individual chat or a group. The welcome frame advertises this command when available. The caller needs send scope, send permission for the selected device and a connected device; ordinary workspace membership alone does not grant permission to send.

```json
{
  "t": "message.event.create",
  "r": "event-1",
  "p": {
    "device_id": "DEVICE_UUID",
    "chat": "120363123@g.us",
    "id": "OPTIONAL_CLIENT_MESSAGE_ID",
    "name": "Planning session",
    "description": "Review the next release together.",
    "start_time": "2027-04-12T10:00:00+03:00",
    "end_time": "2027-04-12T11:00:00+03:00",
    "location_name": "Tallinn office",
    "join_link": "https://call.whatsapp.com/video/YOUR_CALL_LINK"
  }
}
```

- `name`: required, 1–100 Unicode characters after trimming.
- `description`: optional, up to 2,048 Unicode characters.
- `start_time`: required RFC3339 timestamp with a time zone, strictly in the future.
- `end_time`: optional RFC3339 timestamp, strictly later than the start.
- Both dates must be before 2200 and are stored and sent in UTC with whole-second precision. A missing end time stays absent.
- `location_name`: optional venue label, up to 500 Unicode characters. A venue name does not invent geographic coordinates.
- `join_link`: optional HTTPS call link on `call.whatsapp.com`, up to 2,048 bytes, without credentials, whitespace or backslashes. The default HTTPS port is allowed. Put other meeting URLs in the description.
- `id`: optional client-selected WhatsApp message ID, with the same behavior as other send commands.

The response uses the existing `message.sent` frame:

```json
{
  "t": "message.sent",
  "r": "event-1",
  "p": {
    "id": "OPTIONAL_CLIENT_MESSAGE_ID",
    "timestamp": "2027-04-01T09:00:00Z",
    "uid": "ARCHIVED_MESSAGE_UUID",
    "seq": 42
  }
}
```

`uid` and `seq` are only present when archiving succeeds. Archived rows have `type: "event"`; decrypt `payload_sealed` with the message's content key and read the structured payload's `event` field. The server archives the exact normalized title, dates, description, location and call link it sent. It honors the chat's disappearing timer and retains the protocol message secret required for encrypted event responses.

Validation errors return `bad_request`; access failures use the existing authorization errors. A transport failure is reported without automatically retrying. If WhatsApp accepted a message but local archiving failed, the normal send result is returned and the archive error is logged, avoiding duplicate events on retry. This operation creates an event only: it does not schedule future delivery, create a WhatsApp call link, synchronize a calendar account, edit/cancel existing events or send RSVP responses. Exporting an event to a calendar remains a separate client action.

See [WhatsApp's guide to creating events](https://faq.whatsapp.com/3313983622238973/?cms_platform=web) for the native feature. The bounds above describe this application's API. Protocol references for the pinned integration: [native EventMessage fields](https://github.com/tulir/whatsmeow/blob/33cfac511629/proto/waE2E/WAWebProtobufsE2E.proto) and [outbound message secret storage](https://github.com/tulir/whatsmeow/blob/33cfac511629/send.go#L390).

# Sending videos and forwarding messages

Videos use the existing encrypted-media pipeline. Upload the prepared bytes
with `POST /v1/upload?device=DEVICE_UUID&type=video`, then send a WebSocket
`message.send.media` frame with the returned `upload` object. The upload and
message must use compatible media key classes; `video` and `ptv` share theirs.
Both operations require send permission on the selected device.

```json
{"t":"message.send.media","r":"video-1","p":{"device_id":"DEVICE_UUID","chat":"RECIPIENT_JID","type":"video","upload":{"type":"video","url":"UPLOAD_URL","direct_path":"UPLOAD_PATH","media_key":"BASE64_KEY","file_sha256":"BASE64_HASH","file_enc_sha256":"BASE64_HASH","file_length":12345},"mimetype":"video/mp4","width":1280,"height":720,"seconds":18,"caption":"Hello"}}
```

Use the exact values from the upload response, not the placeholders above.
Supply the actual MIME type, dimensions, duration and optional JPEG thumbnail.
A successful response is `message.sent`; never automatically repeat a send
whose response was lost. The message may already have reached WhatsApp.

## Normal video, HD and round video notes

Normal and HD both use `type:"video"`. Quality comes from the encoded bytes,
not a fabricated `hd` flag. The browser prepares the requested quality and
shows the resulting resolution. This does not promise the official WhatsApp
HD badge, whose paired-media protocol is separate. Higher-quality source
video is never invented by enlarging a small source. MP4/H.264/AAC is the
browser's compatibility target; a filename or MIME change is not conversion.

Conversion decodes the soundtrack locally and preserves it through the final
encoder flush. Decoded audio is bounded to 96 MiB; oversized conversions report
an error with an original/HD or document alternative. Compatible MP4 passthrough
does not decode audio and keeps supporting longer ordinary videos. Local
conversion is cancelled if the page is hidden, since background canvas
throttling could otherwise freeze frames while the soundtrack keeps playing.

Round notes use `type:"ptv"`, a dedicated WhatsApp field rendered circularly.
The web client records/prepares a square frame and caps recording at 60
seconds. A round note cannot carry a caption or the GIF-loop flag. Declared
durations above 60 seconds are rejected as `bad_request`; unknown duration
from older API clients remains accepted. This checks metadata, not the
duration inside encrypted media. Ordinary videos do not inherit that limit.

The browser asks for camera/microphone access only when recording is opened.
Local preparation does not send the video; the user reviews and confirms it.
Camera and microphone permission remain disabled on the session bridge.

## Forwarding labels

Text (`message.send`) and media (`message.send.media`) accept the same options:

| Requested label | `forwarded` | `forwarding_score` |
| --- | --- | --- |
| None | `false` | `0` |
| Forwarded | `true` | `1` |
| Forwarded many times | `true` | `5` or greater |

Forwarding creates a new message for the chosen recipient. It does not edit
the source. The browser downloads and decrypts supported media under the
source access grant, then uploads it for the new send; it does not transplant
the archive's sealed envelope. Source replies, mentions, view-once flags and
disappearing timers are not copied blindly into a different conversation.
The target conversation's ordinary timer applies. Content types without a
supported send operation are not silently flattened into text.

The web client scopes every asynchronous forwarding stage to the same
account, workspace, connection and device, and asks for confirmation before
the send. A lost acknowledgement is reported as uncertain, never as a reason
to resend automatically.

References: [WhatsApp video notes](https://faq.whatsapp.com/993629751672762/),
[MediaRecorder format detection](https://developer.mozilla.org/en-US/docs/Web/API/MediaRecorder/isTypeSupported_static),
and the pinned [whatsmeow message schema](https://github.com/tulir/whatsmeow/tree/33cfac511629/proto/waE2E).

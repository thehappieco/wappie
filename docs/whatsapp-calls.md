# Native WhatsApp calls

Wappie supports WhatsApp audio and video calls using the number
already linked by QR or pairing code. The other person receives an ordinary
WhatsApp call. Calling uses the existing device session; it does not require
Cloud API registration or a second pairing.

## Use

Open an individual conversation and choose the audio or video call button.
Incoming calls appear in a global panel while the messaging client is open,
even when another conversation is selected. Answering and placing calls request
microphone access; video also requests camera access. The panel provides mute,
camera and hangup controls. Closing the controlling connection, signing out,
switching workspace, or losing the media connection ends the call and releases
capture devices. Calls are never answered automatically.

The peer's video follows the display orientation sent by their WhatsApp client,
including changes during a call. The local camera offers **Automatic**, **Portrait**,
and **Landscape** layouts. Automatic follows the camera's current aspect ratio;
the fixed layouts crop the image around its center without stretching it. The
local preview shows the same framing that is sent to the other person.

During an active call started by Wappie, choose **Add participants**, select
contacts, and send the invitations. This experimental feature supports up to
**eight people including you**. The participant list distinguishes invited,
connected, departed and failed invitations. Each connected remote participant
has a separate video tile; audio is mixed by the WhatsApp calling library.
An unsuccessful invitation does not end the existing call. Only its controlling
browser connection can invite, and it must use the updated media client.

Calls require the number's **send** permission. Only one call can be active per
number, and only the browser connection that started or answered it can attach
media or end an answered call. Another operator can see that the number is busy.

## Configuration and deployment

`WS_CALLS_ENABLED` defaults to `true`. Set it to `false` and restart the server
to disable the calling adapter. A restart attaches the adapter when existing
devices resume; previously linked devices do not need to be paired again.

Serve the client over HTTPS, or localhost for development, so the browser can
request microphone and camera access. Video requires browser support for
WebCodecs H.264 encoding and decoding; unsupported browsers can still use audio
when microphone and AudioWorklet support are available. Video capture is
limited to a modest resolution and frame rate to bound bandwidth and latency.

The reverse proxy must forward WebSocket upgrades for both `/v1/ws` and
`/v1/calls/media`. The supplied Nginx and Vite configurations already forward
these paths. Both connections must reach the same server process, which must
also supervise the WhatsApp device. Multi-instance deployments need appropriate
routing; calls and media tickets are not shared through PostgreSQL.

The server requires outbound connectivity to WhatsApp and its media relays.
No new public UDP listener is introduced by the browser media bridge.

## API

Calling commands use the authenticated control WebSocket. All commands require
`device_id` and send permission on that device.

| Command | Additional fields | Reply |
| --- | --- | --- |
| `calls.list` | None | `calls.list.result`: `{available, calls}` |
| `call.start` | `chat` (individual PN/LID JID), `video` (boolean) | `call.result`: snapshot |
| `call.answer` | `call_id` | `call.result`: snapshot |
| `call.reject` | `call_id` | `call.result` |
| `call.hangup` | `call_id` | `call.result` |
| `call.media` | `call_id` | `call.media.result`: `{ticket, path}` |
| `call.invite` | `call_id`, `participants` (1–7 individual PN/LID JIDs) | `call.invite.result`: `{call, results: [{peer, ok, error?}]}` |

A snapshot contains `id`, `device_id`, `peer`, `direction`, `state`, `video`,
`owned`, and optionally `reason`. `owned` is relative to the requesting control
connection. States are `ringing`, `connecting`, `active`, and `ended`. The client
polls for incoming calls while connected. This is an in-memory view, not a
persistent call history.

Updated snapshots include `group`, `can_invite`, `participant_limit` (8), and
`participants`: `{id, pn?, self, state}` entries. Participant state is `invited`,
`connected`, `left`, or `failed`. IDs are individual JIDs; PN/LID aliases are
resolved before inviting to prevent inviting yourself or the same person twice.
The server validates the batch before sending invitations and reports partial
results independently. Per-person errors are stable codes: `invalid`, `duplicate`,
`self`, `limit`, `unavailable`, and `interrupted`. `call.invite` is an optional
welcome feature; older clients retain individual calling support.

`call.media` issues a short-lived, single-use ticket for an owned call. Open the
returned media path as a same-origin WebSocket and send `{ "ticket": "…" }` as
the first text frame. Wait for `{ "ready": true }` before sending binary frames.
Tickets are never put in URL query strings. Both directions use:

| First byte | Remaining bytes |
| --- | --- |
| `1` | Exactly 960 signed 16-bit little-endian PCM samples: 16 kHz mono, 60 ms |
| `2` | A 32-bit little-endian duration in microseconds, then one H.264 Annex B access unit |

Clients that render video orientation send `{ "ticket": "…", "video_orientation": true }`
and wait for `{ "ready": true, "video_orientation": true }`. For these clients,
received video uses type `3`: one byte with clockwise quarter turns (`0`–`3`),
four bytes with the little-endian duration in microseconds, then the Annex B
access unit. Orientation is attached to each frame and retained until that
frame is decoded. Clients without this option continue receiving type `2`.
Browser-to-server video remains type `2`, with upright pixels and the selected
portrait or landscape dimensions already encoded into the frame.

Group-capable clients also send `participants: true` in their initial media
message. The server echoes it in the ready response. Attributed group video
then uses type `4`: a quarter-turn byte, a 32-bit little-endian duration, a
32-bit little-endian SSRC, a 16-bit little-endian participant ID length, that
many ASCII JID bytes (1–100), then the H.264 Annex B access unit (at most 512 KiB).
The browser keeps at most seven separate remote decoders, resets a decoder when
its SSRC changes, and releases it when the participant leaves. Direct video is
not interleaved with group video. An individual participant's bad video stream
does not interrupt the group's audio. Browser-to-server video remains type `2`.

Queues and frame sizes are bounded. Slow connections discard excess media
rather than growing an unbounded backlog. A media ticket expires after 30
seconds, and cannot outlive its owning control connection. Owned calls also
end if no media socket attaches within 30 seconds. Outgoing microphone frames
are discarded until the remote party accepts.

## Privacy and limitations

Audio and video are forwarded live and are not recorded or added to the sealed
archive. HTTPS/WSS protects browser-to-server transport; the calling library
handles WhatsApp media encryption. The server decodes/encodes audio and handles
video frames in memory, so this is not browser-to-recipient end-to-end
encryption with respect to the Wappie server. Media and tickets must not be
logged, and diagnostic recording is not enabled.

The integration pins meowcaller to
`v0.0.0-20260811012811-27a3c6b18657`, which uses upstream whatsmeow and compiles
against Wappie's existing pinned version. Later meowcaller revisions switched
to a different WhatsApp client dependency, so upgrades require compatibility
review. Its protocol adapter accesses private whatsmeow handlers; successful
compilation alone does not establish interoperability with every WhatsApp
client version or network.

Adding participants is supported only in **calls started by Wappie**. Receiving
and joining group calls started elsewhere remains unsupported: the upstream
experimental group implementation has a reported incoming-group-call gap on
companion devices. It also provides no operation to remove an already connected
participant. A call must be tested with real WhatsApp clients before claiming
live interoperability; synthetic browser tests verify Wappie's media and controls.

References: [meowcaller](https://github.com/purpshell/meowcaller),
[pinned revision](https://github.com/purpshell/meowcaller/tree/27a3c6b18657614c9ec2ed16dfc497eff11de6ec),
[incoming group call issue](https://github.com/purpshell/meowcaller/issues/34).

## Local validation

Run `go test -race ./internal/calling ./internal/wsapi ./internal/wa` and the web
test/build commands from the README. Setting `WS_TEST_POSTGRES_REQUIRED=1`
ensures database-backed authorization tests cannot silently skip.

With the Vite development server running, the browser regressions under
`wappie-cloud/web/test/browser/call-media.mjs`, `wappie-cloud/web/test/browser/call-orientation.mjs`, and
`wappie-cloud/web/test/browser/call-panel.mjs`, `wappie-cloud/web/test/browser/call-group.mjs`, and
`wappie-cloud/web/test/browser/call-group-panel.mjs` exercise
real Chromium audio/video processing and the desktop/mobile interface. They
use synthetic identities, fake camera/microphone devices, and an intercepted
media connection; they do not contact WhatsApp. Set `QA_ORIGIN` to the Vite
origin, `QA_PLAYWRIGHT_MODULE` to an installed Playwright module if it is not
locally resolvable, and optionally `QA_BROWSER_EXECUTABLE` to Chromium/Chrome.
`QA_SCREENSHOTS` saves light/dark screenshots for the panel test.
The orientation regression checks all four rotations, local framing, aspect
ratio changes during capture, and that a reference square is not stretched.

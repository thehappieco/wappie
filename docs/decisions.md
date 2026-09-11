# Decisions and state

The plan lives at `~/.claude/plans/meu-objetivo-criar-playful-conway.md`. This
file is the part that must not live only in a chat transcript: what was decided
while building, why, and where the work stands.

Read this first when picking the project back up.

---

## Phases

| # | Objective | State |
|---|---|---|
| 0 | Skeleton, migrations, media crypto, RLS, CI | done |
| 1 | Pair a device (QR and 8-character code), supervise it, resume on boot | done |
| 2 | The canonical ingest pipeline, real sealing, live delivery, text send | done |
| 3 | Edit and delete history: the projection that reveals what WhatsApp hides | done |
| 4 | Media **inbound**: object storage, downloads, structured payloads | done |
| 4b | Media **outbound**: upload and send. View-once now works | done |
| 5 | History sync ingest | done |
| 5b | Media retry: recovering attachments with expired urls | done |
| 6 | Contacts, names and profile pictures | done |
| 5c | On-demand backfill | done |
| 8 | Web client (Vue 3): reading the archive in a browser | done |
| 9 | Per-device archive keys, accounts, key grants, recovery | done |
| 10 | Admin console: devices, pairing, tokens, grants | next |
| 8b | Web client: sending, editing, reacting, marking read | done |
| 12 | Conversation layer: unread, ticks, presence, groups, polls, incognito | done |
| 11 | Incognito per chat, quotas, hardening | |

Phase 8 is where the archive stops being an abstraction: the browser holds the
private key and opens everything locally, so the guarantee the whole design is
built on becomes something you can watch happen.

Phase 3 was the one that justifies the product: the chain of versions of an
edited message including who read which version, and the content of deleted
messages. Everything before it was the machinery that makes it possible.
`wsctl history` is where it surfaces.

---

## Decisions taken during the build

Four were chosen explicitly by the owner and shape everything downstream.

**Real HPKE before any data.** The alternative was a pass-through sealer to see
the pipeline sooner, which would have put a personal WhatsApp history in
plaintext in a development database and then required a retroactive re-sealing
job. Sealing landed before the first message was ingested.

**Disappearing messages are kept and marked.** The archive does not honour the
sender's timer, but it records `expires_at` so a reader can be told plainly that
a message was meant to be ephemeral. Storing it silently as an ordinary message
would misrepresent what was received. There is a legal dimension to this in some
jurisdictions; the choice was deliberate.

**Groups are stored from the start, metadata later.** Group messages are
messages. Names, participants and admin state come in phase 6, so until then a
group shows as a numeric id — which was the ugly state of v1, but no message is
lost in the meantime, and lost ones do not come back.

**Re-pair to capture the full history — but only now.** The bootstrap sync from
the first pairing was discarded because no sink was wired. Phase 2 then wrote
`normalize.FromHistory` and never called it, so through phases 3 and 4 a
re-pair would have spent WhatsApp's single delivery on a counter labelled
"ignored". The consumer landed in phase 5; re-pairing is worth doing now.

Pairing creates a new `devices` row and never overwrites one. Nothing needs
deleting first — and deleting the old device would cascade its messages away.
While two devices are linked, every new message is archived twice, once per
device, so the old one should be unlinked once the new sync has landed.

**Receipts are stored, and they are readable.** Answering "who saw which
version" needs the acknowledgements kept, and there is nothing in one to seal:
a party, a message id, a time. So a database dump reveals who read what and
when — the sharpest edge of the routing metadata that was already readable. It
is listed under the honest limits rather than glossed over.

**A reader's revision is proof or it is inference, and the difference is
reported.** Every version is a stanza with a WhatsApp id of its own, so a
delivery receipt naming an edit's id is the reader's own device confirming that
text arrived; that is a floor nothing can argue with. The ceiling comes from
comparing our clock with WhatsApp's. When they agree there is nothing to
caveat, and when they do not the caller gets both numbers and a false. A single
confident answer would have been a UI telling someone that a correction was
read when it may never have been delivered.

**The server does not say whether a reaction was withdrawn.** WhatsApp removes
a reaction by sending one with an empty emoji, and emptiness is a property of
the sealed body. A `was_removal` column would have been the server reporting
something about content it is not supposed to be able to read. The projection
returns the reaction rows per party in order and marks the older ones
superseded; the client, which can open them, sees that the newest is empty.
Same reasoning as replies needing the quoted text resent.

**Sending an attachment passes its plaintext through the server, and that is
not fixable without a fork.** whatsmeow's upload takes cleartext and encrypts
on the way out; there is no exported way to hand it ciphertext somebody else
produced, and the raw upload path needs an authorisation token the library
keeps to itself. So outbound media is exposed exactly as outbound text already
is, and is sealed the moment it is archived. Inbound has no such compromise.

This is worth restating because the earlier draft of the README implied
otherwise. A client-side encrypting upload is possible and would be strictly
better; it costs a fork and a standing maintenance burden, and the original
requirement was about messages and files *received*.

**The archive fetches back what it just sent.** An outbound attachment is
stored by the ordinary download worker, from the CDN, as ciphertext — rather
than by uploading the bytes that were just in hand. One path into object
storage instead of two, and the archive then holds byte for byte what the
recipient can fetch.

**Media is never decrypted on this server.** whatsmeow's download helpers
decrypt on the way past, which would put every photograph and voice note
through this process in the clear. The CDN serves the ciphertext to a plain
HTTP client — the URL in the message is a capability — so `internal/media`
fetches with its own client and stores what it gets, byte for byte. Verified
empirically before the code was written: a 120,976-byte image came back as
121,002 bytes of ciphertext, which is the plaintext padded to a block boundary
plus the ten-byte MAC.

**A download is verified without a key.** `fileEncSHA256` is a hash of the
*ciphertext*, so the fetcher can prove it got the right bytes while remaining
unable to read them. That is the property that makes the previous decision
practical rather than an act of faith.

**Structured content is sealed as one payload, not as columns.** Locations,
polls, contact cards, events, link previews and the mention list are JSON under
`KindPayload`. The alternative — latitude, longitude, poll_options, vcard,
event_start spreading across the message table — would have meant a fresh
decision about what stays readable each time a type was added, made in passing.
It also keeps the browser client from needing WhatsApp's protobuf definitions
just to draw a map pin.

**Link previews are supplied by the client, never built here.** Generating one
means fetching the URL. A server that fetches the links its users send learns
them, which contradicts the sealed archive, and it becomes a machine that
issues requests to addresses chosen by whoever is messaging. The sender's
client already loaded the page; it can describe it.

**HPKE in the browser is WebCrypto and nothing else.** The alternatives were a
crypto library from npm or the Go `seal` package compiled to WASM. Both put the
archive key behind code harder to audit than the sixty lines that RFC 9180 base
mode actually takes, and an npm dependency that can read every message is a
supply-chain target worth avoiding on its own. X25519 is native in WebCrypto
now; HKDF had to be split into Extract and Expand by hand, because WebCrypto
only exposes the two fused and HPKE feeds one PRK into several Expands.

**The archive key is wrapped with PBKDF2, not Argon2id.** PBKDF2-HMAC-SHA256 at
600,000 iterations is what WebCrypto offers. Argon2id is materially better
against a GPU and would mean shipping WASM — which is exactly the dependency the
decision above refuses. Stated in the README rather than hidden: a weak
passphrase is weak.

**The client is served from disk, not embedded.** `//go:embed web/dist` would
make `go build` depend on a JavaScript toolchain, and CI has no Node. A missing
build logs once and the server carries on serving the API.

**The chat list carries the newest message.** Added while building the client:
without it a sidebar shows five hundred rows saying nothing, and filling them
means one request per row. The preview is sealed like any other body and bound
to the *message*, not the chat.

**The archive key belongs to a device, not to a tenant.** Chosen after the
first archive was lost, and for a reason that is not about that: with one key
per tenant, "this operator may read that WhatsApp account and not this one" is a
rule the server enforces, and the whole premise is that server-enforced rules do
not survive a compromised server. Per device it is arithmetic. The cost is a key
per account, which grants make invisible.

**A key grant replaces keeping 32 bytes in a file.** The device key is sealed to
each account's public key. Signing in opens it. The schema has had the tables
for this since phase 0 and nothing filled them; the archive lost on 2026-08-25
is what that omission cost.

**Argon2id, and only for the password.** The rest of the client refuses crypto
dependencies. The password is the one place where that is wrong: WebCrypto has
nothing memory-hard, and the wrapped key sits in the database — the exact threat
this system is built against. One dependency, one file, in a worker so the tab
does not freeze for the seconds it deliberately takes.

**Pairing chooses the device id.** A grant binds to the device, so the grants
have to be sealed before the row exists. Asking the server for an id first would
leave a device with no key for the length of a round trip, and the first message
can arrive inside it.

**One kind, used three times.** The `?type=` on an upload picks the HKDF label
the media key is derived from; the `type` on the send frame picks the protobuf
field; the `media_type` stored in the archive is what a client later derives its
decryption keys from. Nothing cross-checks them, and across the image/document
boundary — which is "enviar a foto como arquivo", the one case a person thinks
of as the same file — a mismatch produces an attachment that answers 200 at
every step and then opens for nobody, including us. The browser derives all
three from one `plan.kind`.

**HD is which bytes you upload.** There is no HD field in the protobuf this
build compiles against; the nearest are the mid-quality and progressive-scan
sets, and `send.Media` writes none of them. So the choice in the composer is a
resolution bound and a quality, and nothing else. This has a consequence worth
stating: the archive fetches back from the CDN exactly what was sent, so
choosing the compressed form makes the compressed form permanent — there is no
second full-resolution copy anywhere in this design.

**No streaming sidecar, deliberately.** Without one a video cannot be played
until it has downloaded whole. The sidecar is per-chunk MACs over the
ciphertext, whatsmeow does not produce one, and nothing in reach specifies the
chunking, the truncation length, or whether the MAC covers the IV. A malformed
sidecar is worse than none: it breaks streaming playback on a file the recipient
could otherwise have downloaded. Left out until it can be checked against
something rather than guessed.

**A voice note is repackaged, not converted.** WhatsApp renders a voice note
from Opus in an Ogg container. Chrome's MediaRecorder writes the same Opus
inside a WebM container, so `web/src/media/oggopus.ts` lifts the packets out of
one and writes them into the other — nothing is decoded and nothing is
re-encoded. Verified against ffmpeg rather than against itself: a real libopus
recording repackaged this way decodes to PCM byte-identical to decoding the
original, passes strict CRC checking, and reports the same duration as ffmpeg's
own Ogg muxer. Safari records AAC and cannot be asked otherwise; that is
reported and offered as an audio file rather than sent as a voice note some
phones will not play.

**The tab keeps the attachment it just sent.** An outbound attachment is
uploaded to WhatsApp and fetched back from the CDN by the download worker, so
`/v1/media` answers 409 for it until that finishes. The file is in the tab the
whole time. A bounded map of object URLs keyed by WhatsApp id survives the
moment the archived row replaces the optimistic line, which is otherwise where a
photograph turns into a placeholder.

**Editing an attachment is not offered.** `SendEdit` builds the replacement as a
text message with no media fields, and what a recipient's WhatsApp does when one
arrives to replace a photograph is not something this system decides. Our own
archive would look right either way — the picture with the new caption and an
"editada" tag — which is exactly why it is refused rather than attempted: the
archive would not be evidence that anything reached the other side.

**A reader asks who an identifier is; the list is not reloaded.** The contact
directory is fetched once when the archive is unlocked, so every conversation
that started afterwards had nothing behind its identifier and the sidebar drew a
LID at somebody whose push name the server had recorded seconds earlier. It went
on drawing it until the tab was reloaded. `contacts.resolve` names the handful
of identifiers a client is about to draw, looks in whatsmeow's own contact cache
for the ones this archive cannot name, and nudges the picture worker so a face
somebody is looking at now does not wait behind a paced sweep of five thousand
contacts. Reloading the whole directory on every unknown key was the obvious
alternative and is the wrong shape by two orders of magnitude.

Answering it also writes a contacts row for a key that has none. The bulk import
deliberately refuses to do that — a row per identifier anything ever mentioned
is a table of keys and no information — but the picture worker walks contact
rows, so without one an identifier nobody can name also never gets a face. A key
a reader explicitly asked about is the opposite case: somebody is looking at it.

**The client asks for identities more strictly than `ParseJID` accepts.**
`types.ParseJID` takes a string with no `@` at all and returns it as a user on
the default server, so `"not a jid"` parses cleanly. Harmless where the input
came from WhatsApp; not harmless on a frame whose keys reach a row-creating
path, where a caller could otherwise name its own rows into existence.

**A changed profile picture is queued, not fetched.** `events.Picture` arrives on
the goroutine reading the socket, so downloading a face there stops the device
receiving anything until it finishes — the same reason history sync is ingested
off it, and a stall nothing reports because the device looks connected
throughout. The handler clears `avatar_checked_at` and leaves the work to the
paced worker. It clears the check time and **not** the stored picture: blanking
it would put a placeholder on screen for as long as the refetch takes, which is
a visible regression caused by learning that a better picture exists.

**Our own messages have an author.** Outbound rows went in with `sender_key`
NULL, because the send package holds a whatsmeow client rather than the device's
identity. Anything grouping a conversation by author, counting participants, or
resolving a name found nothing for exactly the messages the archive's owner
sent. `IngestOutbound` fills it from the lookup that already carries the
identity, and only when the envelope did not state one — nothing here rewrites
an identifier.

**Mentions and link cards are archived, not only sent.** `buildContext` put both
on the wire and `outboundEnvelope` built the row from the body alone, so our own
copy of a message was strictly poorer than the copy every recipient received: no
mentions to highlight, no card to draw. Same content, sealed the same way the
inbound path seals it.

**"Temporária" reads three fields, because one of them is not enough.**
`ephemeral` records that a message travelled inside the disappearing envelope;
`expiration` records the timer it declared. `send.wrap` keeps them in step on the
way out, and rows from a history sync — or from a client that wrote the timer
without the wrapper — carry one and not the other. Reading only the flag is why
the marker appeared on some disappearing messages and not on others that all had
an expiry date. Past `expires_at` the chip becomes "expirada", which is
deliberately not "apagada": nothing was deleted, and the message is still here.
It says the text is gone everywhere else in the conversation.

**Mentions are highlighted in the sentence, and the directory is still not
reactive.** They used to be a "menciona Fulano" footnote because the body renders
as plain text runs — no `v-html`, since the premise is that nothing untrusted
becomes markup. The tokenizer matches `@digits` against the JIDs the message
actually carried, so an `@11` meaning eleven o'clock stays text; mentions whose
number is not in the body at all keep the footnote, because an edit can replace
a text and leave its mention list behind.

The redraw is the half that is easy to miss. The directory is a plain `Map` on
purpose — making five thousand people reactive to catch the handful that change
is a poor trade — so a name learned after a row was drawn changes nothing until
the rows are told. Without `applyNames` the entire resolve path works perfectly
and the reader still sees a LID until the tab is reloaded.

**A tick counts people, and refuses to count when it cannot.** The rule the
owner asked for is "two grey means EVERYONE received it", and the word doing the
work is everyone: two acknowledgements mean everything between two people and
almost nothing in a group of forty. So the denominator is first-class and its
absence is an answer — a group whose size nobody has asked WhatsApp about shows
one grey tick and says why in the tooltip. Falling through to one would paint a
message sent to forty people blue the moment one of them read it, with nothing
on screen to suggest the number was invented.

Two more refusals earn their place. A count that EXCEEDS the denominator does
not promote: either somebody left the group or one person was counted as two,
and both mean the denominator is not describing that message. And `retry` and
`error` are carried in fields no tick rule reads, because a message stuck in
retry looks delivered from every angle except the one that matters.

**Our own delivery receipt was drawing two grey ticks on everything.**
`ReceiptTypeSender` is our own handset confirming it received a message *we*
sent, and normalize stores it as a delivery with `is_from_me`. The client
counted it, and in a direct conversation — denominator one — that is every
message, the instant our own phone acknowledges, with the recipient's phone
possibly switched off. Excluded at the source now, with a read from one of our
own devices reported apart, because the message genuinely was read: just not
here.

**Receipts live outside the timeline.** `state.timeline` is reassigned wholesale
on every live frame, because an arriving row can be an edit, a deletion or a
reaction against a line already on screen. Anything hung on a message therefore
survives until the next frame and no longer, which is why a conversation opened
cold showed one grey tick on everything including messages read months ago. The
page now carries its own acknowledgements, folded server-side where the whole
set is in hand — fifty messages in a group of two hundred is ten thousand rows
that would otherwise cross the wire to be folded again in a browser.

**A person's devices are attributed separately and folded afterwards.** The
revision somebody had on screen is decided by what *that handset* had received,
so a person reading on a phone whose laptop is three edits ahead is ordinary.
Merging a person's deliveries before attributing lets the laptop vouch for the
phone, and the answer comes back `Confirmed` with nothing on the wire saying so.
It is the one mistake in this area that produces a *stronger* claim than the
truth, which is exactly what the edit-history projection exists to avoid.

**One person, two conversations, one row.** WhatsApp addressed the same contact
by phone number for years and by LID since, so a conversation spanning the
change is stored under both keys — measured here: 47 people, 94 conversations,
38 with messages on both sides. Nothing is merged on disk. The rows record how
WhatsApp actually addressed each message, which is a fact about what happened
and the reason a receipt can be matched to a message at all. The fold is a
projection, the same shape as folding a person's several devices into one
reader, and the join is the phone number because the older row predates LIDs and
has none.

**The badge is a watermark, not a counter.** Three independent things clear it —
a reader marking, a read receipt from one of our own devices, the phone
replaying app state — and none knows what the others have done. Decrementing
would need exactly that knowledge. Moving a position forward is idempotent by
construction. Two traps sit either side of it: the increment lives inside
`upsertChat` because that is unreachable on the duplicate path, and
`counts_unread` excludes `source='history'` because a sync writes its own
absolute count *before* ingesting the messages it counted.

**A read receipt needs dwell, focus, and somebody else's message.** It is the
only path in the client that emits a signal about what a person is looking at,
and it cannot be taken back. Scrolling past something is not reading it; a
window behind another window is not being read. Losing focus discards the dwell
clock rather than pausing it.

**Presence is the one event with no sequence number, and the bus had to learn
that.** Everything else here is delivered by reading back the row that was
stored, so a live frame and a replayed one are byte for byte the same. Typing
has no row and never will — it is true for a few seconds and then it is not — so
it carries its own content and a `Seq` of zero. That zero is the danger: the bus
tells a slow consumer where its view stopped being continuous, taking the
position from the event it had to drop, and an ephemeral event would hand back
zero. A client would refetch the entire archive because a typing notification
did not fit in a queue. `Event.Ephemeral` makes such an event droppable in
silence, and `TestADroppedTypingNotificationDoesNotRewindTheClient` fails
loudly without it.

**Reading a conversation is no longer an explicit request, so MarkRead stopped
sending in both modes.** It used to, on the grounds that nothing on the ingest
path called it — asking for a read receipt was somebody deliberately asking. The
browser now marks messages read as they appear on screen, which means the
request is produced by looking, and a posture that promises silence cannot have
reading count as an exception to it. Typing is gated the same way and is the
sharper case: it names a conversation somebody has open, at this exact moment,
several times a minute.

**The mode is a switch now, not a decision taken at pairing.** It was fixed when
a device was linked, which made "go quiet" something you could only choose
before you had anything to be quiet about. The order of the two upstream calls
is not interchangeable and the asymmetry is upstream's:
`SetForceActiveDeliveryReceipts(true)` stores 2 while presence `unavailable`
only moves 1 to 0, so going quiet needs the setter explicitly or a device that
had ever been forced active keeps sending real delivery receipts while reporting
itself silent.

**Going quiet costs seeing other people type.** WhatsApp only sends chat
presence to a client that has announced itself available, and announcing
presence is exactly what the quiet posture refuses. That is the protocol, not
this implementation, and the switch says so rather than leaving somebody to
discover it.

**Presence expires on the client, because nothing promises it will be
withdrawn.** WhatsApp does not guarantee a `paused` for every `composing` — a
phone that goes into a tunnel mid-sentence sends nothing more — so a client that
waited for one shows somebody typing forever, in a conversation they left an
hour ago. The timeout is the entire reliability model, and it is read on demand
rather than swept by a timer so a conversation nobody is looking at costs
nothing.

**A group's history starts when this archive does, and the panel says so.**
WhatsApp delivers a group's current composition and its live changes, never its
past, so "who removed Fulano" is answerable from the moment we began listening
and not before. An empty history is not a peaceful one and a reader cannot tell
the two apart by looking, so the first snapshot writes a marker and the panel
prints the date the record begins.

**An empty snapshot is not everybody leaving.** A membership answer with nobody
in it is a request that failed, a group this account was removed from, or an
answer WhatsApp declined to give. Diffing against it writes a "removed" for
every member, with no author and a timestamp of now — and the table whose entire
purpose is to say what happened would be saying something that did not. The
guard is the first line of `Snapshot`.

**The first snapshot is a marker, not a hundred arrivals.** A group this archive
has only just looked at did not form at that moment, and an "add" per member
would open its history with a fiction.

**A change with no author is recorded with none.** WhatsApp often omits it — a
join through an invite link has no actor — and attributing it to a guess would
be the archive inventing a fact about a person.

**Participants are readable, names are not.** A participant is routing in
exactly the sense `sender_key` and `reader_key` already are: a dump already
reveals who spoke in which group. Sealing the composition as a blob was
considered and rejected for a specific reason — the server could then not count
participants, so the tick denominator would have to be reassembled in every
client, and a claim as consequential as "everyone read this" would rest on
arithmetic nobody could check server-side.

**A poll is counted by the client, because nothing else can count it.** The
server holds the poll and every vote and can match neither to the other: the
question and its options are sealed content, and a vote on the wire is nothing
but SHA-256 of the option text. So the browser opens the poll, hashes each
option and looks for the result among the selections. This is not a workaround
around a missing feature — it is the only arrangement in which a sealed archive
shows poll results at all, and it keeps the property the product rests on: a
database dump reveals neither the question nor anybody's answer.

**A vote's plaintext travels beside the protobuf, not inside it.** A
`PollUpdateMessage`'s `Vote` field is a `PollEncValue` and stays one — there is
no field to write the opened answer back into. Edits and reactions could be
rewritten in place; this one cannot, so `openSecrets` returns a
`normalize.OpenedPollVote` pairing the two and the router unpairs it. Anything
else would have meant a private classifier or a schema change, and both are
worse than a wrapper that says what it is.

**"Nobody chose anything" and "nobody could read this" are different facts.**
WhatsApp withdraws a vote by sending one with no selections, so an empty
selection means somebody changed their mind. A vote that would not decrypt means
this archive missed an answer. They arrive looking identical, so the record
carries the distinction explicitly: `Content.PollVote` present with nothing in
it is a withdrawal, absent is unreadable. A reader that collapsed them would
report a poll as half-unread when in truth people had taken their votes back.

**A vote is stored with kind `message` and folded onto its poll by the client.**
The four kinds are a CHECK constraint from the first migration and a vote is not
an edit, a deletion or a reaction. But it is not a line in a conversation
either, so the projection puts it on the poll's entry — which also means a vote
whose poll is on an older page becomes an orphan rather than a stray bubble, and
paging back resolves it.

**An album is a header and is archived as one.** `AlbumMessage` declares how
many pictures and videos follow and carries none of them; the pictures arrive as
ordinary messages, and nothing in the protobuf links a child back to the header.
So the row records what the message says and no more. Grouping them by a
heuristic was considered and left out: the rule would be a guess, and a wrong
grouping is worse than none.

**A template's three texts are one body.** Title, content and footer are
separate fields and one message, and a classifier that took only the content
would archive the offer without the price. The buttons are kept as labels, not
as controls: pressing one sends a reply this archive has no way to compose.

**The `.ics` and the `.vcf` are built in the browser and never leave it.** An
event's name and location and a contact's card are sealed content; handing
either to a service that renders calendars or vCards would undo the whole
arrangement for the sake of a nicer button. Both are generated from what the
browser already opened and offered as a blob.

**A contact card's `waid` is the only actionable thing in it.** The printed
number is written however the sender's phone felt like writing it; the `waid`
parameter is the account. So "abrir conversa" appears only where the card names
one, and the value is checked as digits before it becomes a JID — the card is
text a stranger wrote.

**The per-message timer is offered on the way out and stated afterwards.** The
disappearing timer travels in every message's context info, so it genuinely is
per message and can be set when sending. Nothing in the protocol changes it
afterwards — `KeepInChatMessage` preserves a message rather than rescheduling it
— so the message menu says "expira em X" and does not offer to edit it.

**Receipts belong to a version, and there is no longer a general list beside
them.** A reader's flat `delivered` is the earliest across every version — the
answer to "did this reach them at all" — and it was being drawn under a heading
about one revision, where it says the correction arrived on the strength of the
original having done so. The panel now offers only per-version lists, and each
carries recebido / lido / tocado for that version alone.

**A receipt's id names the revision, and that is the strongest evidence here.**
Editing a message makes it unread again on the recipient's phone; reading it
afresh sends a read receipt naming the EDIT's own stanza. So a read receipt is
not a vague "they had the conversation open around then" — it names the version
they read. Delivery works the same way and always did.

An earlier build ignored the id and inferred the revision by comparing the read's
timestamp against what that device had been delivered. That inference was not
merely weaker, it was wrong in a specific way: a reader whose phone had only ever
received the original, acknowledging the original, was reported as having read
the correction because the correction happened to be current by the clock.

**The one reader whose ids cannot be trusted is us.** This client folds every
version into one line and marks that line read under the ORIGINAL's id, whatever
text is on screen. So our own devices keep the older treatment — attributed from
what they had been delivered — and are reported as inferred. Reading our own ids
literally would be reading our own simplification back as a fact about what
somebody looked at.

**Each receipt is placed separately, not just the earliest.** Somebody who read
before a correction and again after it belongs on two revisions, and the
unread-again behaviour is exactly what produces that: two receipts naming two
stanzas, kept as two rows because the receipts table is keyed on
(device, wa_id, reader, kind).

**A poll's `selectableOptionsCount` of zero means "no limit", not "one".** One
is what a single-answer poll carries — that is what the field is for — and
whatsmeow normalises anything out of range to zero, so zero is what a poll
carries when it stated no bound at all. That is what "allow multiple answers"
produces on a phone. An earlier build read zero as one, which refused the second
tick on every multiple-choice poll in the archive while the same poll on a phone
accepted it, and drew a round indicator on all of them — the same wrong claim
made twice. Round now means pick one and square means pick several, and options
past the limit are disabled before the press rather than refused after it.

That reading is an inference and is recorded as one. The protobuf carries no
default and no comment, whatsmeow never reads the field inbound, and the only
signal is that its `BuildPollCreation` normalises an out-of-range count to zero.
It is believed because zero cannot be a literal maximum without making the poll
unanswerable, and because the alternative was observed to be wrong. Being wrong
the other way is possible: a genuinely single-answer poll arriving with zero
would let somebody tick several here.

It is also cheaply settleable, and the way to settle it is worth writing down.
The raw protobuf keeps the difference between zero and an absent field, because
the field has explicit presence — but nothing can reach it today, since a poll
row is never `unsupported` and reprojection only reopens rows that are. Widening
reprojection, or storing the count as a pointer, would let a future disagreement
be settled from the archive instead of from argument.

**A "Tocado" section appears when the type allows it OR when a receipt exists.**
The type rule is voice notes and view-once media and nothing else, because a
photograph never earns a third tick. But this client reports played when any
sound finishes, ordinary audio included, and other clients are under no
obligation to match either rule. An archived receipt therefore overrides the
type: a receipt that exists must never be hidden by a predicate saying it should
not, and the type rule only decides what to do when there is nothing to show.

**The discreet palette is one flag away from the gates, on purpose.** The
switch turns off everything this account emits, and none of that is visible from
inside the app — a posture you cannot see is a posture you forget you are in,
and the failure is sending a read receipt you meant to withhold. So the whole
surface goes grey with it: eleven token redefinitions under
`:root[data-theme='quiet']`, which outranks both `:root` and the dark media
query on specificity rather than on source order. It reads `state.quiet`, the
same value that opens and closes the read-receipt and typing gates, so the
colour and the behaviour cannot disagree — a grey window while receipts still go
out would be worse than no colour change at all.

The switch reads the same flag, and that was a second lesson. It used to derive
its icon from the device row, and the flag begins true so that a device whose
posture is not yet known emits nothing; `start()` chose a device and never
corrected the flag, so a loud device booted with a dark palette, a bell in the
corner, and gates that agreed with neither until somebody toggled. Three
readers of one fact, and the fact is set from the server's answer at the
moment the device is chosen — on start, on selection, and on every fresh
listing, since another browser may have changed it.

Two colours in the stylesheet were not tokens and had to become ones: the white
on a filled accent or danger surface, and the per-person avatar hue, which is
computed rather than named and is desaturated rather than replaced.

**A badge is a fact about the reader; a receipt is a fact told to the other
side.** They were one call behind one switch, and the consequence was that a
device in the default discreet mode could never clear a badge at all: nothing
went out, so nothing came back through ingest to clear it, and reading every
word of a conversation left the number exactly where it was. The client now
always reports what it read to its own server, and the server decides
separately whether a receipt reaches WhatsApp — `ReceiptPolicy.MarkRead`
refuses in passive mode, which is the gate that matters and the one place it
can be audited. Nothing is disclosed by reporting locally: the archive already
holds every message it is about.

**There was no way to tell a client that a conversation changed.** Both the
unread count and the disappearing timer were computed correctly, written
correctly, and carried by exactly one frame — the reply to a `chats.list`
request. So a badge moved when the sidebar happened to be refetched and at no
other moment, and a timer the other side changed stayed invisible until a
reload. `chat.update` is that missing frame. It is a patch, not a snapshot, and
every field is a pointer for a reason: zero is a real value for both, and an
absent field has to mean "this event says nothing about that" or an event about
one would clear the other. Ephemeral on the bus, like presence, because it has
no row and no sequence behind it and must never move a client's replay cursor.

**A conversation's timer belongs to every row it is spread across.** One person
can hold a LID row and a phone-number row; the sidebar folds them and takes the
first non-zero. Writing an explicit change to only the row the caller named left
the other half disagreeing, so a timer turned off was resurrected from the
sibling and the setting appeared to revert on its own. The quieter half of the
same defect never reached the screen: `ChatTimer`, which decides whether an
outbound message travels in the disappearing envelope, read one row by the
advertised key — so a timer learned from traffic on the other half answered
zero, and a message went out permanent into a chat the composer was calling
temporary. Writes now reach every sibling and reads span them.

**A timer the other side changed is a fact about the chat, not a row in it.** In
a one-to-one conversation it arrives as an `EPHEMERAL_SETTING` protocol message
and was skipped as housekeeping, which it is — but skipping it meant the only
way the setting ever arrived was sideways, through the per-message ratchet that
raises the timer from any message carrying one. That ratchet only ever raises,
by design, so turning a timer ON showed up late and turning one OFF never showed
up at all. It is applied in the router, before classification, because the
classifier's job is rows and this is not one. For groups the same change arrives
as `GroupInfo`, where "off" was being dropped by a guard that only recorded a
timer it considered real.

**Reprojection runs on its own when the archive opens, and the panel is a
count, not a queue.** The button had become a chore that never ended, for a
reason that was a defect and not the owner's misreading: a row the classifier
still could not name was left untouched, so it was offered again on every press
— an archive whose real backlog was long done went on reporting a hundred and
thirty rows of work, most of them protocol traffic an older build had stored
before it knew to drop it. Two changes. Machinery is retyped as `protocol` and
leaves the list for good. And the pass runs in the browser each time the
archive opens — the server cannot, since the raw protobuf is sealed and the key
is in the tab — converting what the current build now reads and counting what
it cannot by the field each row carried, which is the name of the next thing to
implement. The exposure is the one the button already had (the still-unknown
rows shown in the clear to a server that watched them arrive); what changed is
that it is no longer bounded to a press, and that is written down rather than
glossed.

**The trickle was real, and it was five business formats.** Measured before
deciding: 0.35% of a week's traffic, one to six rows a day — `interactive`,
`buttons`, `list`, `button_reply`, and `placeholder`. The first four all open to
the same shape, some text and the labels of what was offered, and are classified
like a template. The fifth is a message the phone masked from linked devices: it
exists on the handset and never will here. It gets its own type and a sentence
in the bubble rather than an "unsupported" label, because there is nothing a
later build could do about it and an archive that promises completeness owes
the reader the hole.

**Incognito gates only what leaves.** Nothing on the inbound path reads the
receipt mode, so a quiet device still receives every delivery, read and played
receipt other people send about our messages. What it costs is presence — and
therefore seeing other people type — and the fact that receipts arrive only
while the device is connected, because nothing backfills them.

---

## Invariants that are not obvious

These were discovered while building and would be easy to break in a refactor.
Each has a test.

**Sequence allocation order equals commit order.** `UPDATE tenants SET last_seq
= last_seq + 1 RETURNING` takes a row lock held until commit, so a transaction
cannot allocate until the previous one has committed. A reader that sees
sequence N has therefore seen everything below it.

The replay handover in `internal/bus` depends on this. A client resuming reads
history up to a watermark and discards buffered live events at or below it. If
sequences could commit out of order, a watermark of N would discard an N-1 still
in flight and the client would lose a message with nothing to indicate it.
Replacing this with a Postgres `SEQUENCE`, which allocates without blocking,
would reintroduce exactly that.

**Identity is a `(lid, pn)` pair with LID primary.** WhatsApp routes direct
messages over LID now, and LID exists to withhold the phone number, so for many
contacts a phone number never becomes known. v1 rewrote every LID to a phone
number on ingest; that is no longer possible. Nothing rewrites an identifier,
and a known half is never overwritten with an empty one.

**History sync must not go through `ParseWebMessage`.** It calls `UnwrapRaw` and
then, for an edit, overwrites `Info.ID` with the target's id and replaces
`Message` with the edited content. Convenient for a client that wants the final
text; fatal for an archive that exists to show the history, because afterwards
an edit is indistinguishable from an ordinary message.
`normalize.FromHistory` rebuilds the message info itself and stops at
`UnwrapRaw`.

**A revoke's target relation is resolved during ingest, not at render.**
Removing a reaction produces a delete whose target is the reaction, not the
message. v1 recomputed this at render time in two places that disagreed, and the
symptom was showing "message deleted" where someone had merely taken back a
thumbs-up. It is now a stored column, decided once by looking at the target.

**Outbound text is always `ExtendedTextMessage`, never `Conversation`.**
`Conversation` is a bare string with nowhere to attach `ContextInfo`, so a
message sent that way cannot express a reply, a mention, an expiry or the
forwarded flag.

**A forwarded message with score zero shows no badge.** One is the minimum that
renders on the recipient's phone.

**`Participant` belongs on a group reply and not on a direct one.** Without it,
a group quote renders stripped of its author.

**whatsmeow's plaintext buffers must stay off.** `EnableDecryptedEventBuffer`
and `UseRetryMessageStore` write decrypted protobufs to
`whatsmeow_event_buffer` and `whatsmeow_retry_buffer`. Either one puts message
plaintext on disk and voids the sealed archive. Both default to false; the risk
is someone enabling one to fix a retry bug. `TestPlaintextBuffersStayOff` is the
guard.

**One acknowledgement takes one sequence number, and replay never splits it.**
A read receipt names every message the reader just saw, so allocating a
sequence per id would take the tenant row lock two hundred times for one
message in a two hundred person group, and would tear every connected client's
cursor forward by the same amount. The read limit counts rows, so a batch can
straddle it; the half-batch is dropped and refetched rather than handed over
looking complete, because a client cannot tell a two-id acknowledgement from
the first half of a three-id one.

**Replay merges two streams and must not run past the horizon.** Messages and
receipts share the cursor, so both are read per round and emitted in sequence
order. Either read can have been cut short by its page limit, and emitting the
other stream past that point leaves the client's cursor above rows it was never
sent — which nothing later would ever mention again. `mergeReplay` stops at the
highest sequence both reads actually cover.

**A receipt is linked to its message by id alone, never by chat.** Found with
real traffic on the first run: a message sent to a phone number was stored with
`chat_key` `5511999999999@s.whatsapp.net`, and its delivery receipt came back
addressed `224437861388494@lid`. Same conversation, same message id, two
different chat keys — so a join including the chat found nothing and every
acknowledgement was invisible to the projection that exists to use them. This
is the `(lid, pn)` problem crossing a table boundary, and nothing can reconcile
the two halves until contacts arrive in phase 6. The message id is what
WhatsApp itself resolves a receipt by, so that is the key: `(device_id, wa_id,
reader_key, kind)`. The receipt's own `chat_key` is kept and never rewritten to
match — it records how the acknowledgement was actually addressed, which is a
fact about what WhatsApp sent.

**An expiration always brings the disappearing envelope.** Reported from the
field: `-expires 3600`, and the message was still there an hour later. The
timer was written into the context and the message was not wrapped in
`EphemeralMessage`, so every client read the number and kept the message. The
two are not independent settings, and the rule now lives in `send.wrap` so no
caller can get it half right. `outboundEnvelope` derives the archived flag from
the same function, or the row would say a message was ordinary while the
recipient's client made it vanish.

**Disappearing messages are a chat setting, not a message option.** WhatsApp
has no way to make one message vanish and leave the next alone, so a per-send
`-expires` was the wrong shape from the start — the same class of mistake as
view-once on text. `chat.timer` calls `SetDisappearingTimer`, the setting is
recorded on the chat, and every outbound message in that chat picks it up
automatically. The timer is also learned from inbound messages, because that is
the only way a linked device finds out about one set on the phone.

**View-once is marked twice, on the wrapper and on the media message.**
Reported from the field: WhatsApp Web recognised a message as view-once and an
iPhone rendered the same message as an ordinary photograph. The wrapper is what
libraries unwrap to set IsViewOnce; the field on the media message is what
several official clients read when deciding to draw a one-time bubble. Sending
one without the other is how clients end up disagreeing about the same message.

**The handover is tested as a client meets it, not only in pieces.** The bus
covers the replay race and the lag path, and `mergeReplay` covers two streams
becoming one. None of them covers the frames arriving over a real websocket in
order, with nothing missing and nothing twice — which is the contract every
client rests on and the one a harmless-looking refactor would break. The
failure it guards against is silent: a client never told about a message has
nothing to notice.

**A backfill anchors on the oldest message, not the newest.** WhatsApp is asked
for what came *before* a message it can identify, so anchoring on the newest
returns what is already stored. The anchor is chosen by sequence rather than by
timestamp: a phone with a wrong clock would otherwise nominate something from
the middle of the conversation. The answer arrives minutes later as an
ON_DEMAND sync and goes through the same consumer as a bootstrap, so nothing
about it is special — which is why the request returns as soon as it has left
rather than pretending to report a result it cannot have.

**Names are three different claims and all three are kept.** A push name is
what someone calls themselves, the address book name is what this account saved
them as, and a business name is what WhatsApp verified. The server does not
choose between them, because the right choice depends on what the client is
for: an archive reader wants the saved name, an operator triaging an inbox
often wants the one the sender chose. All three are sealed — a dump that
revealed who the identifiers belong to would hand over most of what a social
graph is.

**The names had to be imported, not waited for.** They arrive in a single
PUSH_NAME chunk during a history sync and go straight into whatsmeow's own
store. An archive that only listened for events would wait for each of five
thousand people to send something before learning who they are.
`ImportContacts` runs at every boot and is idempotent. Reaching whatsmeow's
cache is a type assertion in `contactSourceOf` rather than a method on the
Client interface, so the contract test can still assert that
`*whatsmeow.Client` satisfies it directly.

**Profile pictures are the one thing here that arrives unencrypted.** WhatsApp
serves them over plain HTTP to anyone with the URL — no media key, no
ciphertext to preserve. So unlike message media, which is stored exactly as the
CDN served it and never opened, a profile picture is necessarily seen by this
process and is sealed on the way in. The asymmetry is real and is named rather
than smoothed over. They live in the contact row rather than object storage:
tens of kilobytes each, and a second blob path for that would be machinery with
nothing to buy.

**A group is an identity too.** Groups never appear in whatsmeow's contact
cache — that is people — and a group's name lives on the chat, so nothing put
them in the contacts table and the avatar worker never reached them. A group
has a profile picture like anyone else, and the picture belongs with the
identity rather than with the conversation, so a group gets a contacts row
carrying no name of its own. Seeded at boot for the ones stored before that was
true.

**The avatar worker is paced on purpose.** Each question is a query over the
same socket that carries messages, and a thousand of them as fast as they will
go is a good way to be rate limited — or to make the device look like something
other than a chat client. A contact with no picture, or whose privacy settings
hide one, has its check recorded: without that the same few are asked on every
pass and the ones never asked never get a turn.

**Media urls expire, and the direct path expires with them.** Found by
re-pairing: a bootstrap sync brought 19,573 messages and 7,340 attachments, and
4,555 of them answered 403 with the body "URL signature expired". The signature
is the `oe` parameter, and it is on the direct path too — so there is no second
address to try, no header that helps, and whatsmeow cannot do better: its
download path sends exactly the same three headers, and the `auth` token from
the media connection is used only for uploads.

The recovery is to ask the sender's device to upload the file again. It needs
the media key, both to authenticate the request and to read the answer, and
this server cannot open its sealed copy. So the client opens it and passes it
in for one exchange, held in memory with a ten-minute expiry and never written
down. That is a real exposure, taken deliberately, for attachments the owner
explicitly asked to recover.

A 403 is an expiry and a 404 is a deletion. Only the first is worth a retry,
which is why they are listed apart rather than both being "gone". Measured on
the first sweep: 7 of 15 recovered.

**History sync is ingested off the event goroutine.** whatsmeow dispatches
events synchronously on the goroutine reading the socket, so ingesting a
ten-thousand message bootstrap inline stops that device receiving anything —
live messages, receipts, connection events — for as long as it takes. Chunks go
to a bounded queue and one worker. When the queue fills the enqueue blocks
rather than dropping: a delayed receipt is recoverable, and history WhatsApp
delivers once is not.

**One worker, not several.** Sequence allocation serialises per tenant anyway,
so concurrent history ingest would buy lock contention rather than throughput.

**Chat names come only from the history sync, and are sealed.** Nothing on the
live path carries one, which is why a group showed as a numeric id. A name is
content — for a direct chat it is a person's name — so it is sealed like a
body, bound to a chat identity derived as uuidv5 over the device and chat key.
Derived rather than generated so both sides can compute it without a round trip
and it survives a re-import; predictability is fine, because associated data is
a binding and not a secret. `BackfillChatUIDs` runs at boot rather than in SQL,
so the derivation has exactly one implementation.

**Status updates are stored on both paths or neither.** They arrive live as
ordinary messages and in a sync in their own field. Reading only the first
would mean the same broadcast is in the archive or not depending on whether the
device happened to be connected when it was posted.

**A version's own WhatsApp id is what makes proof possible.** An edit is a
stanza in its own right and collects its own delivery receipt. Folding edits
into the original's row, or keying receipts on the root id alone, would leave
version attribution with nothing but clock comparison.

**The attachment queue is the database, not a channel.** A row in `pending` is
the whole work item, so a restart loses nothing and a dropped nudge costs a
wait rather than an attachment. Claims are `FOR UPDATE SKIP LOCKED`, and a
worker that dies holding one is swept by `claimed_at` — not `created_at`, which
for a backfilled attachment is weeks old and would return every in-flight
download to the queue instantly.

**Object keys are content-addressed and tenant-prefixed.** The same image
forwarded into twenty chats is one object; the same image in two tenants is
two. Sharing across tenants would mean one tenant's deletion could empty
another's attachment, and that the presence of a key would answer "does anyone
else here have this exact file".

**A media ceiling is not optional.** `file_length` is the sender's claim, not a
measured fact. Without `WS_MEDIA_MAX_BYTES` a message announcing eight
kilobytes can serve until the disk is full.

**Every test needs its own Postgres schema.** `go test ./...` runs packages in
parallel, and a shared schema means one package drops tables out from under
another. Tests that pass alone and fail together are worse than no tests.

**RLS is per session, so the scope and the query must share a connection.**
Setting `app.tenant_id` on a connection taken from the pool and then querying
through the pool gets a different connection and returns nothing. Always go
through `pg.InTenantTx`.

**A migration cannot write to a table under row-level security.** It runs with
no `app.tenant_id`, so a DELETE or UPDATE matches nothing — silently, reporting
success — and the next statement fails on rows the migration believed it had
removed. Empty test databases never notice. Disable the policy for the length of
the change and turn it back on; `TestMigrationsDoNotWriteThroughRowLevelSecurity`
checks the files for it, and found a second instance in 0004 the first time it
ran.

**A second implementation of the archive format cannot be trusted to agree with
itself.** The browser client reimplements HPKE, the envelope layout and the
WhatsApp media scheme in TypeScript. A reimplementation that is subtly wrong
opens everything it sealed itself and fails only against real data. So the
format is pinned as checked-in fixtures that Go writes and both sides read —
`internal/crypto/seal/testdata/vectors.json`,
`internal/crypto/wamedia/testdata/vectors.json` — including values that **must
not** open. An implementation missing the AAD binding passes every positive test
and fails all the negative ones.

**Knowing the crypto is right is not knowing the client asks for the right
row.** A message body binds to the message uid, a chat name to the chat uid, a
contact name to the contact uid, and a file name to the *message* uid under
`KindContactName` — which reads like a mistake and is the format. Point the
opener at the wrong one and every field comes back as tampered with the correct
key in hand, which looks like an attack rather than a bug.
`internal/wsapi/testdata/frames.json` holds whole frames sealed the way the
pipeline seals them, so that failure surfaces in a test instead.

**A fake that holds a request must survive being released too early.** Found as a
one-in-three hang in the browser suite, at twenty seconds, on a different socket
test each run. The upload fake parks the request and the test releases it after
watching the optimistic bubble appear — but that bubble is drawn from the file
already in hand and does not wait for the request to reach the server, so
`release()` regularly finds nothing to let go, the request lands a moment later,
and the send never settles. A released-early flag closes it. The symptom looks
exactly like a slow machine, which is what makes it expensive: the first three
explanations are all about load.

**The chat preview must follow the newest row, not `last_seq`.** `last_seq` is
what the history sync last reported and can lag a live insert. The lateral join
in `Messages.Chats` orders by sequence within the conversation, so a list never
shows the second-newest message — which reads as a client that has stopped
updating rather than as a bug.

---

## Phase 13: the audit

Findings from a privacy and security review of the whole server, and what was
decided about each. The report is [security-audit-2026-09.md](security-audit-2026-09.md).

**The recovery code has to prove itself.** It was written by every signup and
read by nothing; there was no endpoint, so a forgotten password lost the
archive — the failure the column existed to prevent. Handing the wrap to
anyone who asks would be safe against 150 random bits and careless against a
database leak, so the code is split like the password: one HKDF branch opens
the wrap in the page, the other is sent and stored as an Argon2id hash. Two
proofs, one per step, rather than a token between them: the code is in the
browser's memory for the whole exchange anyway. A recovery spends the code —
it was just typed into a browser — and issues a new one. Accounts from before
hold a wrap nothing can redeem; they are told, and generate a new code while
signed in.

**Rate limits live in the process.** Token buckets per address and per
subject, on the HTTP auth endpoints and on the websocket hello, because each
attempt costs an Argon2id derivation and a script can alternate between the
two. In memory, not in Postgres: a shared store on the sign-in path is one
more thing that can be down at the moment somebody needs to sign in, and a
deployment with several processes has a small number to divide by. The
proxy's address is trusted only when named in `WS_TRUSTED_PROXIES`; trusting
`X-Forwarded-For` from anywhere would let a caller pick a fresh address per
request.

**An API key has a scope, and the default for old keys is the widest.** Every
key could send as the paired number, join groups and stop devices; the
comment on the table said "read". Three levels — read, send, full — checked
on the server per frame. Existing keys became `full` because that is what
they had, and a migration that narrows a credential is how a monitoring job
stops at three in the morning. The browser defaults to `read` and makes the
choice explicit; the CLI defaults to `full` because it is the operator.

**Operator acts need an operator.** Pairing, flipping the receipt mode and
listing accounts were open to any actor in the tenant, including a read key:
pairing links a phone number; the mode switch turns a discreet device loud for
everyone it talks to. `requireOperator` is "an owner or admin, or a full key",
which keeps `wsctl` working. A pairing with no grants is refused unless the
request says `orphan`, for the same reason `wsctl` already refused it.

**A member reaches a device through a grant.** `resolveDevice` checked the
tenant and nothing else, so any account saw every device's envelope — chats,
numbers, group rosters, who read what at which minute — with a key for none
of it. The envelope was never sealed, and a grant is now the rule for it too.
Admins are exempt: they hold the tenant.

**Attachment URLs are the sender's.** The fetcher took `media.url` from the
message protobuf and issued a GET, following redirects, from inside the
network. Three checks, each for what the others miss: the host must be under
`.whatsapp.net` over TLS; every redirect is checked the same way; and the
dialer resolves the name itself and refuses private, loopback and link-local
addresses, which is what a DNS answer pointing inward would otherwise get.
Profile pictures go through the same door.

**The wire log is a separate logger, not a level.** whatsmeow's debug output
is every protocol node in both directions, which is every message in the
clear. `WS_LOG_LEVEL=debug` used to put that in the log; now debug from
whatsmeow is dropped unless `WS_LOG_WIRE` asks for it, and prod refuses the
ask. A log level is a knob somebody turns during an incident.

**Identifiers are masked in every log line.** Numbers and JIDs reached the log
at INFO on boot and on every error path, and the account's email on every
line of a session — the social graph, without the row-level security. The
handler masks on the way out, on every string attribute, so the list of keys
cannot drift. A JID keeps its server and last four digits, enough to match a
line to a row for somebody with the database.

**The account wrap is bound to the address.** Every other seal carries its row
as additional data; this one did not, so whoever could write the users table
could swap one person's wrapped key for another's without the tag objecting.
Version 2 prefixes a byte and binds to the email. Version 1 blobs still open
and are re-wrapped on the next sign-in, quietly, without ending sessions.

**Retention is a tenant setting, off by default.** Nothing expired, for third
parties who never agreed to be archived. A window in days, applied hourly,
takes messages, receipts, group events and attachment objects; chats and
contacts stay. `erase` removes one person across every device. Disappearing
messages are still kept until the window, because that was a product decision
and is documented as one. Object storage is now cleaned by deletes: only the
objects nothing else in the tenant names, because a forwarded attachment is
one object under several rows.

**The database role is checked at boot.** Row-level security is the whole of
tenant isolation and a superuser reads through it. Prod refuses; dev warns,
because the tests would keep passing and nothing else would ever mention it.

**Sessions end when they should.** A disabled account's tokens kept working
for fourteen days, because the session lookup never looked at the account.
`ActiveSession` does, everywhere a token is accepted. A password change or a
recovery revokes every session and issues a fresh one to the caller.

**A system is an account, not a courier's envelope.** The first idea for
giving a third party the archive was the obvious one: the owner exports the
device key and sends it. That makes a plaintext secret with no trail, no
revocation and one copy per device to redistribute — the failure the grant
scheme exists to avoid. So a service account is a `users` row with a keypair
and no password (`role = 'service'`, the password columns nullable and
tied to the role by a check), registered under a service invite with a name
and a public key. An owner grants it devices with the same button as for a
person, and an API key can act as it (`api_keys.acts_as`): the key then
carries the account's grants over `grants.list` and is refused every device
the account was not granted, like a member. The system opens grants with the
private half it kept. A key that acts as a person is refused; that would be a
person's grants with none of the person's password behind them.

**A refused signup does not spend the invite.** The body is validated before
the invite is redeemed; a typo in a base64 field used to cost somebody their
only way in.

---

## The honest limits

Worth restating because "encrypted at rest" is read as more than it is.

- An attacker running code on a live server sees plaintext in flight. At-rest
  sealing protects a stolen disk, a leaked backup and a database dump.
- The whatsmeow session store must stay readable by the process. Whoever steals
  it can impersonate the device and read *new* messages, but not the archive.
- Outbound **text** passes through in the clear: the Signal session lives here
  and needs it. Outbound *media* need not, since the browser can produce the
  ciphertext and hashes itself (phase 4).
- Routing metadata is readable so the server can paginate. A dump reveals who
  talks to whom, when, how often, and the type and size of attachments.
- Receipts are readable, which is the same category but sharper: who read what,
  at what minute. Nothing in them can be sealed and the edit-history projection
  depends on them.
- "Saw revision N" is proof only when the reader's device acknowledged that
  version; otherwise it is two unsynchronised clocks agreeing, and it is
  reported as inferred.
- Replies need the quoted text resent by the client, because the server cannot
  read the archive to rebuild a quote. That is design, not a workaround.
- Attachment metadata is readable: type, size, dimensions, duration, and the
  hashes. The bytes and the file name are not.
- Routing metadata reaches the logs too, masked: enough to match a line to a
  row with the database in hand, not enough to name anyone without it.
- The browser holds the key while the tab is open. Anything executing script in
  that origin can ask the unlocked session for plaintext; the content security
  policy and the absence of any third-party JavaScript are the mitigation, not
  immunity.
- Argon2id at 64 MiB is what protects an account's wrapped key on the server;
  PBKDF2 at 600k iterations is what protects a pasted key in a browser's
  IndexedDB, on the escape-hatch path only. Both are slow; neither makes a
  weak passphrase strong.
- Lose every access path and the archive is unreadable. Permanently, by anyone.

---

## Operating notes

The archive private key is printed once by `whatserverd archive-key` and exists
nowhere else. Losing it loses everything already stored.

`bootstrap` creates a **new** tenant. To get a key for an existing one:

```
./bin/whatserverd tenants
./bin/whatserverd key -tenant <ID>
```

Device ids may be given as a unique prefix, so the short form in
`wsctl devices` works everywhere.

Development runs against local PostgreSQL 18 on 5432 with a non-superuser role
(`whatserver2_app`); superusers bypass RLS and would make the isolation tests
pass regardless of the policies. The HTTP port is 8090 in `.env` because 8080 is
taken on this machine.


## Public presence stays unavailable (2026-09-11)

This supersedes the earlier coupling between active receipt mode and public
online presence. All connected Wappie numbers now announce `unavailable` on
connection/reconnection, while the connection, ingestion and outbound messaging
remain active. Existing receipt modes and personal reading preferences are kept.
Normal read/played/typing actions remain explicit and independent; observing
other contacts’ presence may be limited by WhatsApp. The active-to-passive
transition must apply unavailable directly instead of changing the policy first
and then calling a passive no-op disconnect handler. Phone notification behavior
is validated by the user; an unavailable connection cannot undo explicit read
confirmations from the Wappie reader or another linked client.

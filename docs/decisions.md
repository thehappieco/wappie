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

**Sending an attachment passes its plaintext through server memory.** The
browser sends prepared bytes over HTTPS. The current whatsmeow `UploadReader`
call encrypts them into a temporary ciphertext file, then uploads to WhatsApp.
Outbound media therefore has the same live-server plaintext boundary as text.
A client-encrypted upload would require a separately reviewed integration; the
browser's current media preparation and conversion do not implement one.

**The archive fetches back what it just sent.** An outbound attachment is
stored by the ordinary download worker, from the CDN, as ciphertext — rather
than by uploading the bytes that were just in hand. One path into object
storage instead of two, and the archive then holds byte for byte what the
recipient can fetch.

**The attachment downloader does not decrypt the bytes it fetches.** For
ordinary encrypted WhatsApp attachments the CDN supplies ciphertext, which
`internal/media` fetches over HTTPS and preserves byte for byte. This describes
the normal path, not every media source: keyless/unhashed input is currently
accepted. The [media security follow-up](media-security.md) records the gap.

**A supplied encrypted-file hash verifies download integrity without a key.**
`fileEncSHA256` is checked against the received bytes when present. A matching
hash verifies integrity; it does not by itself prove that bytes are encrypted.
The current fetcher skips this check when the hash is absent.

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
boundary — which is "send the photo as a file", the one case a person thinks
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
"editada" ("edited") tag — which is exactly why it is refused rather than
attempted: the archive would not be evidence that anything reached the other
side.

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

**"Temporary" reads three fields, because one of them is not enough.**
`ephemeral` records that a message travelled inside the disappearing envelope;
`expiration` records the timer it declared. `send.wrap` keeps them in step on the
way out, and rows from a history sync — or from a client that wrote the timer
without the wrapper — carry one and not the other. Reading only the flag is why
the marker appeared on some disappearing messages and not on others that all had
an expiry date. Past `expires_at` the chip becomes "expirada" ("expired"), which
is deliberately not "apagada" ("deleted"): nothing was deleted, and the message
is still here. It says the text is gone everywhere else in the conversation.

**Mentions are highlighted in the sentence, and the directory is still not
reactive.** They used to be a "menciona Fulano" ("mentions so-and-so") footnote
because the body renders as plain text runs — no `v-html`, since the premise is
that nothing untrusted becomes markup. The tokenizer matches `@digits` against
the JIDs the message actually carried, so an `@11` meaning eleven o'clock stays
text; mentions whose number is not in the body at all keep the footnote, because
an edit can replace a text and leave its mention list behind.

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
past, so "who removed Fulano" (so-and-so) is answerable from the moment we began
listening and not before. An empty history is not a peaceful one and a reader
cannot tell the two apart by looking, so the first snapshot writes a marker and
the panel prints the date the record begins.

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
parameter is the account. So "open chat" appears only where the card names
one, and the value is checked as digits before it becomes a JID — the card is
text a stranger wrote.

**The per-message timer is offered on the way out and stated afterwards.** The
disappearing timer travels in every message's context info, so it genuinely is
per message and can be set when sending. Nothing in the protocol changes it
afterwards — `KeepInChatMessage` preserves a message rather than rescheduling it
— so the message menu says "expires in X" and does not offer to edit it.

**Receipts belong to a version, and there is no longer a general list beside
them.** A reader's flat `delivered` is the earliest across every version — the
answer to "did this reach them at all" — and it was being drawn under a heading
about one revision, where it says the correction arrived on the strength of the
original having done so. The panel now offers only per-version lists, and each
carries recebido / lido / tocado (delivered / read / played) for that version
alone.

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

**A "Tocado" ("Played") section appears when the type allows it OR when a
receipt exists.**
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

**WhatsApp profile pictures have no attachment media-key encryption.** They
arrive as ordinary image bytes over HTTPS, are visible in server memory, and
are sealed before being written to a contact row. This is separate from Wappie
account and workspace avatars, which are validated image data URLs stored as
shared profile metadata without archive encryption.

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
- Outbound **text and media** pass through server memory as plaintext after
  arriving over HTTPS. The current upload encrypts media before sending it to
  WhatsApp; it does not accept ciphertext prepared by the browser.
- The downloader accepts media without a key or encrypted-file hash. See the
  [current limitation and planned hardening](media-security.md); this prevents
  a universal claim that every accepted media object is encrypted at rest.
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
  hashes. File names and embedded thumbnails are sealed; attachment bytes have
  the storage boundary and missing-key/hash limitation described above.
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

## Hosted remote MCP is metadata-only (2026-09-21)

> Still true of `https://api.wappie.thehappie.co/mcp`, of self-hosted
> containers and of every `metadata` connection. For the attested reader at
> `https://mcp.wappie.thehappie.co/mcp`, "Message text inside an attested
> reader (2026-09-26)" below supersedes it.
>
> Its paragraph on dynamic client registration and client metadata documents
> (the two-host allowlist and the Go relay that fetches documents) is
> superseded for the attested reader, from reader 0.6.0, by "Any MCP client,
> identified by its own document (2026-10-01)" below.

The local stdio MCP stays exactly as it is: keys on your computer, plaintext
optional, nothing to revise. The hosted connector is a second transport, not a
replacement, and the line it draws is the one the archive already drew: the
process that can be reached from the internet on somebody else's schedule
never holds a key that opens content. `packages/mcp-http` runs the existing
reader over Streamable HTTP with an API key that is read-only, restricted to
the consented devices and dated to expire. It is handed no service account and
no archive private key, so sealed bodies are `locked` there the way they are
for any unauthorized local reader, and a compromise of that host is a metadata
leak, not a content leak. Metadata still reaches the assistant's provider, and
the docs say so instead of hiding behind "encrypted".

**The authorization server lives in the Node reader, not in Go.** Whoever
mints tokens can read with them. Putting the OAuth server in the archive
process would have given the server that sits next to every sealed body a
credential that reads the archive through the front door, plus a token-signing
key to protect. So the reader is its own RFC 9728 resource and RFC 8414
authorization server: PKCE S256 only, tokens bound to the `/mcp` resource
(RFC 8707) so one minted for one installation is refused by another, opaque
tokens stored as hashes, refresh rotation serialised per family with a short
grace window because the hosts retry. The Go server keeps a registry of
connections and relays opaque blobs over loopback; it can list, revoke and
answer "is this still active", and nothing more.

**Dynamic client registration and client metadata documents, both.** DCR is
what the hosts speak today, restricted to HTTPS redirects on `claude.ai` and
`chatgpt.com`, with the authentication method assigned as `none` whatever the
client asked for, because a public client's secret protects nobody. CIMD is
where the client SDK is heading, and it needs an outbound fetch; the reader is
denied the network, so that fetch goes through a Go relay that enforces the
same host allowlist, refuses redirects and caps the body. The two allowlists
must match, and the runbook says so rather than trusting anyone to remember.

**The consent is proven, not assumed.** The browser seals the connection
bundle to the reader's public key with HPKE, so the archive server that relays
it cannot open it, and proves with an HMAC over a `link_secret` that travelled
only inside that sealed bundle that the same browser approved the same
request. The reader mints the authorization code only after that proof
verifies; three bad proofs burn the request and revoke the connection.

**The API key is provisional until the connection exists.** The console issues
it with twenty minutes to live and only a successful registration extends it to
the consented 30, 90 or 365 days. An abandoned consent dies on its own instead
of leaving a live key behind, and an expired key fails inside the same query
that would have found it, with the same hashing on the miss, so expiry adds no
timing oracle. A janitor revokes what has expired and marks connections
`expired`, because a connector that outlives its consent is the failure mode
that matters.

**Rollback needs a down-step this time.** Migrations 39 and 40 change `api_keys`
and add `mcp_connections`, and the previous executable refuses a schema it
does not know. The deployment record carries the reverse SQL, rehearsed before
the pilot; the price is that consented connections are lost on rollback and
users approve again. Better a documented re-consent than a rollback path that
does not exist.

`docs/rest-api.md` still says the server never opens archived content or
receives archive private keys. That sentence stays true, and it was the test
for every choice above.

## Message text inside an attested reader (2026-09-26)

The hosted connector could not read what people most want to ask about. The
2026-09-21 line (the process reachable from the internet never holds a key that
opens content) is kept for `api.` and for self-hosting, and a second reader is
allowed across it under conditions that make the crossing checkable.

**Where the key may exist.** Only inside an AWS Nitro Enclave whose image is
public, built from the public tree and verified by the browser before it
seals anything (`docs/mcp-enclave.md`). TLS ends inside the enclave on a new
hostname, `mcp.`, because `api.` mixes the REST API and `/mcp` and could not be
passed through. CAA pins certificates for `mcp.` to the enclave's own ACME
account before the address resolved, the TLS key is new at every boot, and
Certificate Transparency is watched for a key no enclave attested. The honest
residue is written into the consent card and the docs: whoever controls DNS
can still impersonate the reader to the AI host for as long as it lasts, and
leaves a public certificate behind.

**Ephemeral keys first.** The per-connection X25519 key is generated inside the
enclave and lives only in its memory. No KMS policy change can reopen it later,
because there is nothing stored to reopen. The price is that every reader
release, reboot or crash clears it: the connection turns `reseal` (not
revoked), keeps its id and the assistant's tokens, and the person who
consented renews it in the console with their password. A mode that wraps the
key under KMS so it survives restarts is a later, separate choice (2c), with
its own weaker sentence on the card.

**One service account per connection, never reused.** `users.public_key` has no
update path, and making one would be a new way to redirect every grant a user
holds. So a text connection gets its own service account whose public key is
the attested one, read-only permissions on exactly the consented numbers and
one grant per number; renewal creates a new account and swaps it in on the same
connection. Such accounts never count as the "another reader remains" backup
that protects a number from losing its last reader, because their grants die
with the enclave's memory.

**Revocation is one helper under the tenant.** `device_key_grants` and
`device_permissions` have forced row-level security, so a `DELETE` outside
`pg.InTenantTx` removes nothing and reports no error. Every path that ends a
text connection (console, reader, a failed relay, expiry, removing or
disabling the service or the person who consented, access found gone) calls
the same helper in the tenant's transaction, and the enclave asks the server
about every text connection each minute, so an idle one loses its key within a
minute of a revocation. Revocation never erases what the assistant already
received, and the card says so.

**Search must not tell the server what matched.** The reader asks the archive
for pages and opens them in the enclave. Stopping at the first `limit` hits,
or asking for the history of each hit, would show the server which messages
contain the words. With a text query the reader always scans the whole budget
and does not check history per hit; contact lookup always reads the same
number of pages.

**Deliberately narrow.** The password stays (one Argon2id derivation for all
chosen numbers); durations are 1, 30 or 90 days with a seven-day idle refresh;
the personal contacts snapshot, attachment bytes and sending are out (for 2b;
stage A opens attachments for media connections only, see
[§16](mcp-enclave.md#16-stage-a-attachments)); text is enabled only for
workspaces the operator lists (`WS_MCP_CONTENT_TENANTS`) behind a kill switch
(`WS_MCP_CONTENT_ENABLED`). Legal texts and these docs are published before
any workspace other than the test workspace is listed.

The local stdio MCP is unchanged. `docs/rest-api.md` still holds: the archive
server never opens archived content or receives archive private keys. The
enclave reads the archive through that same REST API, as a client would.

## Any MCP client, identified by its own document (2026-10-01)

The connector admitted two hosts, `claude.ai` and `chatgpt.com`, and that
allowlist was the whole defence against forged identities and against the
document fetch reaching inside the network. Every other MCP client was
locked out, VS Code, Zed and goose included, although each publishes a
document on its own domain. The owner asked for any client and approved the
plan's recommendations on 2026-10-01 (D1 to D18,
[§19](mcp-enclave.md#19-any-mcp-client-060)). From reader 0.6.0 the attested
reader admits a Client ID Metadata Document on any https host that passes a
host check, and the security moves into what the person sees and what the
reader enforces.

**The domain is the identity; the name is a claim.** A web redirect must sit
on exactly the document's host, and a loopback redirect may use any port. The
consent card leads with the domain and its main domain, shows the full
identity and return addresses of a client Wappie has not tested, and prints
the name a client gives only in quotes. A public suffix on its own, a host
shared by path (`s3.amazonaws.com`, `webhook.site`) and every host under
Wappie's own domain are refused; a subdomain of shared hosting (`github.io`)
is admitted with a warning.

**The reader fetches documents itself.** With any host admitted, a Go relay
that fetches documents could present one for any large domain that has an
open redirect anywhere, and the card would show that domain while the code
went to Go. So the enclave fetches over TLS it verifies, through an egress
proxy on its parent that passes bytes only to public addresses on port 443,
resolves each name once and follows no redirect: the parent and Go can refuse
or delay a document, never forge one. The browser checks that every field the
card shows is attested.

**Tested clients are pinned, not trusted by domain.** ChatGPT serves a valid
document at any path under `chatgpt.com/oauth/`, and `claude.ai` vouches for
two different clients, so a domain alone pins nothing. The clients Wappie
has tested are image constants with their exact redirects, measured and
published, and are never fetched; a tested client that asks for another
redirect is served as untested. The first list (Claude, ChatGPT, Codex and
Claude Code) is final only after a live baseline on the current reader, and a
web client that accepts a sign-in it did not start is not listed. After the
baseline the list is Claude and Claude Code (below).

**Dynamic registration only for the pinned redirects.** It proves only that a
code goes to an address on a host, which an open redirect fakes, and the
specification has deprecated it. Registration accepts the pinned Claude and
ChatGPT redirects and nothing else (Claude's only, after the baseline), which
also closes the hole where any path on those hosts could be registered.

**What an untested client may do is narrower.** Metadata once the person
ticks "I started this"; text and attachments only after a second, deliberate
tick and with a confirmed e-mail address; never drafts, notes or sending; a
history window of 7, 30 or 90 days; 2,000 messages and 50 attachments a day;
20 calls a minute; shorter lifetimes; at most three per workspace. Apps on the
person's own computer cannot be identified there, so even tested ones get
intermediate lifetimes and no drafts or notes. Every consent carries the "I
started this" tick, tested clients included.

**Every connection is announced, and the list is checked.** A banner in the
console and an e-mail whose only link revokes that one connection, with no
link that leads to a login page, because an e-mail that teaches people to
type their password after a click would cost more than any connector leak.
The console compares Go's list with the one the reader signs, so a hidden
connection is detected.

**A token for tools without OAuth.** Minted in the browser, shown once, only
its hash sealed to the reader, always untested, text valid one day by
default, optionally bound to networks.

**A rollback costs a reconnect.** The reader's sealed state changes format,
so the previous reader refuses it rather than serving the new connections
under looser rules; rolling back means deleting the state, and every
connection reconnects.

`docs/rest-api.md` still holds: the archive server never opens archived
content or receives archive private keys.

## Fewer steps, without a new reader image (2026-10-04)

Owner decisions M3, M4 and M6; the contract is
[§19.35](mcp-enclave.md#1935-fewer-steps-without-a-new-image-a1-to-a7).

**A step-up instead of the password.** Every text consent and renewal asked
for the Wappie password and waited for an Argon2id derivation, the largest
step in each. The browser already holds the account key for the session, so
it seals the grants with that; what the password proved, that the person at
the screen is the one signed in, is now a sign-in within ten minutes, a
passkey with user verification, or the password, checked by the server,
which refuses every write a grant of text goes into without it, and every
grant of a number's key to anyone: given to a member or a standing service
account, a grant reads the archive for as long as it stands, so a browser
left open past the window must not make one either. The archive server still
never receives an archive key or the password.

**Each workspace decides, beneath the operator.** The operator's lists
(`WS_MCP_CONTENT_TENANTS` and its kin) did not scale past the test workspace.
The owner of each workspace now turns text, attachments, drafts and AI on or
off; Wappie Cloud starts them on, a self-hosted server off. The operator
keeps the kill switches, a deny list and which workspaces the attested reader
serves. Plans and trials are the platform's, behind one hook that answers yes
until the platform decides.

**A reconnect replaces, and an idle row ends.** Reconnecting the same
assistant used to leave the old connection holding a place under the cap;
the consent now replaces it (unticked, both stay), and a connection whose
refresh token has died ends by itself.

## Claude is the only tested assistant (2026-10-05)

ChatGPT's plugin flow kept failing in the live baseline on reader 0.5.0 and
blocked the project, so the owner kept only Claude as a tested assistant and
moved on. Claude on the web and Claude Code passed, each by its document;
ChatGPT, in Chat and in Work, and Codex did not finish. Reader 0.6.0's
measured list is Claude's document, Claude Code's, and Claude's registration
on its own two callbacks, which the owner kept without a baseline run.
ChatGPT and Codex still connect, as any MCP client Wappie has not tested:
their documents are fetched and judged like any other, under the untested
limits, and registration no longer accepts ChatGPT's redirects. The
console's guide shows Claude and "Other assistants"; nothing promises
ChatGPT. A vendor that passes the whole script on a later reader is listed by
that reader's release ([§19.34](mcp-enclave.md#1934-the-tested-list-after-baseline-b-2026-10-05)).

## Sign-in through an identity provider wraps the account key (2026-10-05)

The hosted cloud signs in through The Happie Co's id. (docs/platform-sign-in.md);
a self-hosted installation keeps its own login, and the Go code is inert
until `WS_PLATFORM_ISSUER` is set.

**The provider's key wraps Wappie's account key; it does not replace it**
(owner decision D2). Every grant, the AI keychain and the personal contacts
are sealed to the account key, and `users.public_key` still has no update
path. The key is stored once more under a key derived from id.'s product key
`sk_p`, as 61 bytes of AES-256-GCM bound to `users.id`, the `sub`, the
product key id and the public key. It is symmetric because an HPKE seal to
`pk_p` could be made by the server itself.

**A pin, never an e-mail match.** The first product key seen for each
`(sub, product_key_id)` is pinned, insert only; a later key is refused as
`account_key_changed`, with an alert, and the pin is kept. An existing
account is linked only with its old password or recovery code, proved to
this server and opened in the browser (decision D1: the owner's pilot is
kept); an address is at most a hint shown to its verified owner. New
accounts take `users.id = sub`; a linked account keeps its id, which grant
AADs and foreign keys bind.

**One step-up, the fewer steps'.** Sign-in moved onto the fewer steps (its
migration became 0048) and drops its own `sessions.step_up_at`: the proof is
`sessions.authenticated_at` for every account, and every guarded write asks
`internal/stepup`'s `Checker`. What D3 changes is how an account that signs
in through id. earns the proof: id.'s re-authentication with `prompt=login`,
checked from userinfo's `auth_time` against `sessions.step_up_not_before`
(kept in 0048 for that), replacing the passkey and the password, since
Wappie runs no WebAuthn for those accounts (platform decision 0008). Until
step 4 builds it, such a session holds no proof and is refused by name
wherever one is needed, rather than counting a sign-in that id. may have
answered without asking the person anything.

**D3 done: the step-up at id. (2026-10-06).** Step 4 builds it, with the
owner's twelve decisions of that day (docs/platform-sign-in.md, "Step-ups"):
`POST /v1/auth/platform/step-up/start` records `step_up_not_before`; the
console opens id. in a new window (the same tab when the browser blocks it)
with `prompt=login`; `POST /v1/auth/platform/step-up/finish` takes the
access token to userinfo once and records the proof only for this client,
the linked `sub`, the pinned key of its epoch (another key is
`account_key_changed`, with the alert, and a step-up never pins) and an
`auth_time` at most a minute before the start, within ten minutes of it.
The proof is `authenticated_at = now()` on the database's clock, written
with the start's clearing in one statement, so one start makes one proof.
A sign-in through id. counts as a proof from its `auth_time` (the console
asks for `prompt=login`), and a link from now. 0048, not yet deployed, was
amended in place for it: `sessions.via_provider`, which also closes the
rollback window's open door (`/v1/auth/me` no longer hands the legacy
password wrap to a session through id.), and the ticket's `auth_time`.

**Step 6: the rollback window ends (2026-10-12).** D4 kept a linked
account's old password, recovery code and Wappie passkeys for 14 days after
the cutover, so that switching the provider off would let it sign in as
before. With no real customers and no old password worth keeping, the owner
ended it at once. Migration 0049 nulls, for every account linked to id., the
old password's verifier, salt and parameters, the password and recovery
wraps and the recovery code's verifier, deletes its passkeys and their
flows, and ends every live session one of those started; `WS_LOCAL_LOGIN=off`
closes the password routes. 0049 changes data only, so its down-step is the
ledger row and an older release still starts; what it removed does not come
back, and going below 0048 now means deleting the accounts that sign in
through id. first, the ones linked before 0049 as well as those created
there (docs/platform-sign-in.md, "The end of the window"). The cost: a linked
account's key is then held only by its platform wrap, under id.'s product
key, and the console cannot rewrap a new epoch yet. A key reset at id., or
another key for the pinned epoch, would lose the account key and everything
sealed to it, so until the rewrap ships the backup from before 0049 and the
old password are kept.

## A replay of any length reaches the client that reads it (2026-10-14)

A subscription replaying more than about 256 frames in one burst closed a
healthy client as a "slow consumer", with code 1008, which the SDK reports as
access having changed. Found while building decision 0038, whose deletion
test kept its data under that size. The cause was the writer: it checked
access before every frame, a database round trip or two, while the replay
queued a page of five hundred frames at memory speed into a queue of 256
that closes the connection when full.

**The subscription waits for the client; nothing else does.** Its frames,
replay and live, now go through a queue of their own (`session.push`), and a
full one makes the subscription wait rather than close the connection. Kept
apart from the replies' queue, so a long replay cannot fill the room a
command's answer needs, and replies are taken first. A client that stops
reading is still bounded where it was: the 15-second write deadline closes
it, and a live stream lags once the bus's queue fills, which is what the bus
was designed to do and what the console already handles.

**One access check per batch, never after it.** The writer takes the frames
already queued, at most 64, and checks once. The check starts after each of
them was queued, so "checked before writing queued frames" (docs/workspaces.md)
still holds: a frame queued after a revocation commits is never written. What
it trades is up to one batch queued before the commit, against a round trip
per frame; the periodic check and the local wake are unchanged.
`TestRevocationMidReplayStopsDelivery` revokes a key from outside the process
mid-replay and allows at most 64 frames written after the commit; a writer
that stopped checking fails both it and
`TestExternalKeyRevocationStopsLiveDelivery`.

**The replay's hold on live events is bounded.** The bus buffered live events
without limit during a replay, harmless while a replay took as long as its
reads, since a client that fell behind was closed. It now holds at most
`queueDepth`, all the handover could deliver into an empty queue anyway, and
lags past that; typing seen during a replay is not held at all, since the
handover discarded it. The lag is reported as soon as live delivery starts,
counted in `ws_lag_total` (registered, never incremented until now).

## Notices lock the workspace, then the connection (2026-10-14)

A reader's second `budget_hit` for one connection and code answered 500
when it arrived while the first one's e-mail was being claimed (CI of
thehappieco/wappie#45, `TestBudgetHit`). `RaiseNotice` locked the connection
and then upserted the notice. `ClaimNoticeMail` locked the notice and then
reached the connection only through the foreign key of the revoke link it
inserts. Postgres aborted one of the two after `deadlock_timeout`. A reader
that lost got a 500. A claim that lost sent no e-mail, ever, because only
the first raise of an event claims one. Three more cycles had the same
cause. A notice's first row, a revoke link and a seen mark reference
`tenants`, and their foreign keys take that row's share lock after the
connection's. Every end locks `tenants` and then the connection, so a
revocation could deadlock with a first raise, a claim (which also left a
link for an ended connection) or a member's seen mark.

`RaiseNotice`, `ClaimNoticeMail` and `MarkSeen` now take their locks in the
order every end and every draft or send uses ([§17.19](mcp-enclave.md#1719-recorded-during-s0)): `tenants`
`FOR KEY SHARE` (`shareWorkspaceTx`), then the connection, then the notice
or mark. A claim checks the connection is still live under the connection's
`FOR UPDATE`, after the workspace's advisory lock and before its notice.
`TestRaiseAndClaimNoticeDoNotDeadlock` and
`TestNoticesAndEndingDoNotDeadlock` force each cycle and also race the real
paths. Every cycle failed before the change.

## The contract's membership part, connected and observing (2026-10-19)

Release B of platform decisions 0040 and 0041 ([the contract](contract.md)):
Wappie subscribes the people it holds, follows the platform's feed,
compares, and sends access snapshots and item events. It enforces nothing
yet. Twenty-four decisions shaped it (the plan's DB1 to DB24); where the
owner or the platform changed one since, the entry says what holds.

**DB1. Connect and observe ship together.** Observe is "receives and
sends, does not enforce" (0005), and connecting alone already receives and
sends: the comparison is a read-only function over rows stored anyway. A
new account's home must come with the first PUT, and the first snapshot
must follow it within seconds, or the console counts every followed
member's numbers as unknown protection. One migration (0051), one binary.

**DB2. The mode is in the database, the transport in the configuration.**
`contract_state.mode` is `off` or `observe`; `WS_CONTRACT_*` only say how to
reach the platform. `off` before the first observe is release A; `off`
after one stops the leader, the returning sign-ins' PUTs and the
freshness shadow, but a new account still takes the platform's home or is
refused: Wappie never goes back to homes of its own. Without a transport,
observe is fail-static and refuses only new accounts. The owners' acts that
the platform mails about are gated on where that mail goes (DB13).

**DB3. Observe compares and logs only.** No membership, role, status,
revocation, closing, rename or closure is applied, and nothing is deleted.
The exceptions: a new account's home, the record of platform workspaces,
and paused person invitations (DB6). A new account whose document is not
`active` is refused and unsubscribed: creating it would be acting.

**DB4. The freshness hook is wired at every gated act, and refuses only
from enforce** (the owner, 2026-10-14: "só registrar"). At observe Wappie
applies no document, so a fresh one changes no authorization: a refusal
would only refuse while the platform is down. The shadow's logs ("freshness:
would refuse", "freshness: stale at act") are enforce's evidence. The hot
paths (sends, group administration, MCP sends) read only the stored
freshness, in the background, and make no call.

**DB5. A move out of a team stays its only owner's** (decision 0043, which
replaced the co-owner move of the owner's first answer). The local
sole-owner check and the access refusal decide; the hook asks for the
mover's document with a fresh GET and logs "transfer: would refuse" unless
it lists them as the team's owner with an owner count of 1, which enforce
makes binding. 0051 records no owner count.

**DB6. Person invitations into a platform team are paused** (the owner,
2026-10-14). The key is the record, never a setting, so a container, a
restored `runtime.env` or a return to `off` never reopens them; only the
0051 down-step does. `409 invitations_paused`, not `managed_elsewhere`:
at observe the platform's invitations do not reach Wappie. Service
invitations stay open.

**DB7. One leader for all background contract work**, by the advisory lock
`contract` held on its own connection (`pg.Locker.Hold`), whose loss ends
the leader within its heartbeat; every leader write is compare-and-set.

**DB8. Freshness per sub, in the database, on its clock, from answers
only.** A PUT's or GET's validated document sets `fresh_at` whatever its
version; a feed page never does, and vouches through `published_through`
only for subs the platform follows in the stored generation. A signed
refusal of any code confirms nothing. Platform times past the database's
clock by over 5 minutes are refused.

**DB9. A snapshot for every recorded platform workspace from observe**,
empty when Wappie has none: the console reads a missing one as unknown
protection.

**DB10. Which rows are sent.** Rows written at or after the first observe
and the workspace's naming. Pauses, strandings and moves written while off
after an observe are never sent; deletions, recoveries and purges are, on
the return (the spec always sends them, and a purge must not arrive
without its deletion). A replayed deletion, recovery or purge is sent by
its `occurred_at`; the platform answers `duplicate` for one it holds.

**DB11. One `item.sync_paused` per number, actor and hour.** Later pauses
fold into the first, which carries their readers; a pause under an hour
after a delivered one sends nothing. The actor is the person behind the
act: a key's creator counts as the actor (README 9), so a person's pause
and their key's fold together; a key with no creator is nobody's, never a
person's. Folded rows settle only with their
head's signed answer. A pause nobody but its actor reads is `not_sent`.

**DB12. `devices.pause_cause`**: `person`, `move` or `deletion`, set by every
writer and defaulted by a trigger, so the snapshot's `by_person` is a
person's stop and never Wappie's own pause.

**DB13. The owner's strand override, where the platform mails the other
owners.** `strand_deleted` lets an owner, after a step-up, remove or disable
a deleted number's last key holder, writing `item.stranded` and the other
owners' `number_stranded`. The owner confirmed on 2026-10-14 that it goes
only where the platform will mail the other owners: the contract on, in a
recorded team that is not closed. A self-hosted installation keeps release
A's refusal; opening it there would need the owner's agreement and a
mailer. Its readers are those just before the change (README 9).

**DB14. The owners' in-app notices** `number_stranded` and
`number_moved_out`, for the workspace's other active owners, never the
actor, in every edition.

**DB15. A self-hosted mail path.** 0051 carries its schema (`item_mails`,
`mail_from`, `reader_user_ids`, `mailed_at`); its sender is a separate
change that this release does not include, and the cloud never runs it.
It may run only where the installation never used the platform.

**DB16. Capture is released for a workspace that is not active**, by the
supervisor, before enforce can close one.

**DB17. The secret's envelopes use Wappie's own KMS key**, under one
context for both files (`service=wappie`, `env=prod`,
`purpose=contract-secret`, `ref=platform`), so a promote is a rename. The
key, its policy and the managed policy on the shared role follow the
account's pattern and are the owner's to create, from a local file never
committed. `runtime.env` pins the full key ARN.

**DB18. The kit moves to v0.8.0 for Go only.** The TypeScript pins stay,
and CI holds `packages/client`'s built `dist` equal to release A's, so the
enclave reader's measurement does not change.

**DB19. One label rule**: `label.Clean` is NFC then the kit's
`contract.CleanLabel`, tested against the kit's vectors.

**DB20. The last document is stored as received** (`contract_accounts.doc`):
subs, workspace ids, roles, statuses, counts and team names, never an email
or a person's name. Enforce applies from it.

**DB21. Never unsubscribe a person Wappie holds.** Every PUT follows a
committed intent row; a refused sign-up DELETEs only after a fresh read
finds the sub unlinked, and `already_linked` and `ticket_invalid` never do;
every other orphan is the sweep's, 15 minutes after its last PUT, by
compare-and-set.

**DB22. What a log line may hold**: subs, user, workspace and device ids,
counts, codes and classes; never an email, a name, a label, a hint, a phone
number or a secret. A platform call's failure is logged by its outcome,
code or class; a database or file error by its text, which names neither a
person nor a secret; the secret loader's failures by step and class only,
never by text, because a KMS refusal's text names the role's ARN, the
account and the key.

**DB23. One lock order for the contract's writers**: `contract_state`, the
records by id, the workspace `FOR KEY SHARE`, then its `item_events` rows in
`seq` order, with a deadlock retry, so none crosses a purge.

**DB24. Someone is told when the contract fails.** No metrics are scraped
on the pilot, so `whatserverd contract status --check` is the alert: it
exits 1 with one line per finding, well before the platform's own two
alerts fire, for a daily job to add to its warnings.

**A suspended sole holder stays protected** (the platform's message of
2026-10-19, after Wappie's reply of 2026-10-14). `sole_key_holders` checks
a person whose account is disabled, their membership active and with no
deadline, as it checks an active one, so release A's refusal and the
snapshot's `protected` both keep them while their keys are kept. Only an
active person is a backup, as before. No Wappie path disables an account
yet (only an operator's SQL does), so this only widens the refusal, on
the safe side.

## Pausing and resuming by role (2026-10-26)

The owner took every recommendation of the platform's design of
2026-10-26 (`contract-tokens-and-settings.md`, section 11), in their words
"sim para tudo", relayed by the platform. Its question 1: people pause and
resume an item's sync by role, in both apps, never through a stored Manage
flag. Mailie already did; Wappie's `device.stop` and `device.start` needed
Manage, which an owner or an admin can give a member.

`device.stop`, and `device.start` on a paused number, now need
`store.ActionPause`, not `ActionManage` (`frameAction`, and
`resolveDevice` for the start). For a person it is the membership's role,
owner or admin, read in the same row as the other permissions
(`devicePermissionTx`); a personal workspace's person is its owner, and a
member's `can_manage` never counts. A key needs `full`, as for managing,
and the number in its list. A key that acts as a service account also
needs the account's own Manage flag, as before: the design leaves keys
under their scope (0053's tokens will carry `manage` the same way), and a
service account acts as itself, so it keeps the rule it had. An assistant
connection's key is refused it like any frame that manages.

Only pausing and resuming moved. Renaming, the receipt mode, pairing
retries, groups, backfill, grants, deletion and recovery keep their
rules. A retry of a registration that never linked lifts its pause, if it
has one: only then does the retry also need `ActionPause`, since an owner
or an admin paused it and the retry, once the phone accepts, starts
capturing. A refusal is `not_authorized` with a message naming the role
rule, as Mailie's is, rather than a new code: the console words it, and
`packages/client` takes no runtime change (its build is measured into the
reader's PCR0). `can_pause` tells each caller what it may do, in
`devices.list`, `device.info` and `GET /v1/devices`
([devices](devices.md#who-pauses-and-resumes)).

The design's "sync now", a reader's on a number that is not paused, has no
frame of its own here: `device.start` on a number that is not paused
connects it now. The owner's answer keeps it off the role ("sync now stays
with the readers of an item that is not paused"), so it keeps Manage, the
rule it had, until the contract's `item.sync_now` (its settings part)
gives it to readers. `resolveDevice` checks Manage when the row it reads is
not paused and the role when it is; `handleDeviceStart` checks the role
again on its own read before it lifts a pause, so a stop that lands in
between is never lifted under Manage. A sync now lifts no pause, and one
that fails puts none back (a resume that fails still restores the pause
it lifted, with its cause), so a member with Manage never leaves a number
paused. `history.backfill` keeps Manage. Since the settings part's DS13,
a person's sync now asks Read and the number's key, in the frame and in the
console alike; a key keeps Manage.

## The contract's settings part (2026-11-08)

Step 12a puts Wappie's `numbers` section in the platform's console through
the contract's settings part (kit v0.10.1; the platform's spec, section 14).
It ships in two releases: "read" sends the sections with `accepts: []`,
follows the command feed and answers every command `kind_not_accepted`;
"commands" runs the kinds. One migration, 0052, holds the schema of both.
Seventeen decisions shaped it (DS1 to DS17, numbered apart from the
membership part's DB so the two never collide).

**DS1. 12a takes migration 0052, all of its schema.** The ledger, the
feed's state, the sections' and persons' seqs and due times, the logout
cause, the pause times and actors, the settings triggers and the label
cutover, for both releases, so the second migrates nothing. Step 7's own
0052 becomes 0053. Its down-step refuses while settings are not off or a
later migration is applied, counts what it drops, and leaves exactly 51's
schema ([Rolling back below 0052](deployment.md#rolling-back-below-0052)).

**DS2. The settings mode is in the database.** `contract_settings_state.mode`
is `off`, `read` or `on`, apart from `contract_state`, so a take never waits
behind the account side. `read` and `on` need the contract on, and
`contract mode off` turns settings off in its own transaction. A binary
that does not know a mode reads it as `read`, never as `off` or `on`. A
change makes every section and person document due now (their `accepts`
change).

**DS3. One clock per workspace, two columns.** The snapshot keeps
`snapshot_seq`; the sections and the acts take `sections_seq`. Each takes
the greatest of the clock in milliseconds and both columns plus one, under
the record's lock, so the two documents rise on one clock and a section
never moves the seq a snapshot in flight records its outcome by. A
document takes its seq first, in its own REPEATABLE READ measuring
transaction (an act holding the record makes it run again, and it then
sees the act); an act takes its seq first, under its record. So a section
at or above a result's seq shows it. The sender's snapshot does the same
(`SnapshotNumbered`, since the platform's check of fcffb55, finding 3):
12a measured it, then numbered it, so a rename that committed in between
left one snapshot above the result with the old label (the residual the
plan bounded by 0051's label trigger), and the console showed the rename
done beside the old name until the next one. Past its seq the snapshot
measures read-only, so its seq is its one write. Because the numbers and
the snapshot reads hold the record while they measure, they fail on each
other, on an act and on the event sender's record: a read that fails so
tries again after a random pause of n times 2 to 7 ms after its n-th
failure, eight tries in all (12a's five, at once, ran out within a burst
of acts). Every act updates the record, never only locks it: a read that
waits on a lock alone keeps the view it took before the wait. No code
numbers a document after measuring it (`TestWorkspaceClockWriters`). And
a section's `snapshot_seq` is the last one numbered, which may be a
snapshot whose send failed: the console's "shown" check reads the
platform's own kept seq, so that is harmless. A person's
document does the same on `contract_persons.seq`, with `sent_seq` for its
outcome's compare-and-set.

**DS4. The ledger keeps exactly 30 days.** A row holds the command as
received (bytes: its MAC is the app's proof) and the sha256 of its
canonical form without `generation`, `cseq`, `secret` and `mac`, kept
exactly 30 days from its take (decision 0056), counted as 720 hours, never
as calendar days that follow the session's time zone across a change of
daylight saving time: every read ignores an older
row, a delivery of its id is a new row, and the trim deletes it. A command
refused before `ValidateIn` passed keeps no decoded column, and a body
that is not one object, holds a NUL or is not UTF-8 never fails a page;
an id that is no UUID gets no row. The security log's
`contract_command_invalid` names no person (`user_id` and `sub` NULL),
only the command's id, its cseq and why, since that log is never trimmed.

**DS5. The order of decisions.** At take: another app's body, a MAC that
holds under no secret, a command of another generation than its page,
`ValidateIn`, the 30 days, `expires_at`, then a `wseq` the memory has
passed with another id; each answered in the take's transaction. A replay
posts its result again and moves to the current generation; only a copy
whose MAC holds may finish an open row with another body
(`invalid_command`), a forged one only logs. A body the kit cannot
canonicalize for its MAC is forged; one whose MAC holds but that does not
decode as a command is the platform's, `invalid_command` and not forged.
The ledger's id is the `id` member named exactly, as the kit reads the
command it verifies. Only the page's generation resets, at most once a
minute from the command feed; a second within the minute waits it out with
an ERROR (`command_reset_loop`), which the plan had as a WARN: a fault that
resets everything once a minute must reach `--check`. A reset that finds
the generation moved under it starts no wait. The executor runs in take order (`take_seq`, not `cseq`, which a
restored platform starts again below), one open row at a time per
workspace and producer; a row whose run fails with a store error backs off
5 s doubled up to a minute, holds back only its own workspace and
producer, and is answered `rate_limited` (60 s) after 5 tries. A result
is written in its act's transaction by compare-and-set on its having none;
one of a command whose row is of another generation is dropped, and the
poster drops any it finds before each batch. A tightening delivered
`again`, of a kind this binary runs, is never answered with a retry (a
check that holds it back, or `rate_limited` after a store error): the
platform compares it with the result it kept and takes any other outcome
or code as a conflict, never issued again, so the restore would keep what
the tightening took away. It waits the run backoff instead, its class
`again_` and the code, and is judged again until it runs; at the fifth try
one ERROR (`command_stuck`). The team's status is judged again in the
act's transaction, which holds the workspace's record, since a document
stored after R3 (R4's freshness keeps the actor's) may close it.

**DS6. The logout cause is a typed column, decided once.** A `BEFORE`
trigger fills `devices.logout_cause` when a number moves into
`logged_out`: a deletion's two reasons (`no session at deletion`,
`unlinked when deleted`) are `deletion`, any other (the phone's unlink, a
missing session) `phone`, whose remedy is the same relink. A number already
logged out keeps its cause whatever reason follows, so a phone's logout
followed by a deletion (whatsmeow deleted the session at the logout, so
the deletion finds none) stays `phone`. Rows logged out before 0052 are
classed by their reason alone, so a phone's logout then deleted reads
`deletion`. No writer's Go file changes, and a store test fails if the
trigger stops naming the deletion's two reasons.

**DS7. Who paused, from three columns.** `paused_at`, `paused_by_kind` and
`paused_by_user` on `devices`: a trigger sets the time at each new pause
or change of cause, and `app` for a move's or a deletion's; an
`AFTER INSERT` trigger on `item_events` (`sync_paused`, `recovered`) names
a person or a legacy key's creator; the console's stop writes its own. A
second stop with the same cause keeps the first pause's time and actor. A
resume clears them and stamps `unpaused_at`. 0052 fills paused rows from
what it finds: a deletion's from `deleted_at`, a move's from its
transfer, a person's from its newest event unless one of its notices was
marked resumed after it. Still unknown, and sent as null, by design until
the frames share one pause transaction: a frame's stop that tells nobody
(every personal workspace), a frame's stop on a moved number, a pause put
back after a failed resume, and paused rows 0052 found no trace of.
`paused_by_user` references `users` `ON DELETE SET NULL`, as `deleted_by`
does: a removed account leaves no id behind, and the kind stays.

What 0052's fill can get wrong, accepted: schema 51 keeps no trace of a
resume once nobody is left to mark (`MarkResumed` marks only unseen
notices). A pause that told nobody, after a resume of an older pause
whose event it would take, is credited to that older event's actor and
time: a stop whose notices were all seen before the resume, or a
recovery (its event tells no reader), each followed by a resume and then
a silent stop. It is a display only, of pauses made before 0052 whose
events are under 30 days old; a pause put back after a failed resume, the
likelier case, is the same pause and is credited rightly. The migrating
release's verification lists the person pauses 0052 filled, so the
operator can check them.

**DS8. A registration's pairing is the leader's registry's.**
`pending[].pairing` says whether the leader's process pairs the
registration now (`wa.Registry.PairingSince`), and `can_retry` whether the
retry would start one by the socket frame's own rules: the process neither
pairs nor holds it (`Holds`), and it has a key (an epoch above 0). A
pairing starts and ends with no row change, so the section sender compares
the registry's view with the pending rows it last sent every 10 seconds and
sends the section again where they differ. Only the leader's process is
seen: the pilot serves from one, and a pairing in another process shows
`pairing: false` until it links (its row changes then).

**DS9. The runners beside the frames.** The console's acts on a number
live in `internal/numberacts`, beside the relink, so the socket's frames
can move onto them later: each act's checks and writes are one store
transaction, and around it the runner does what the frame does with the
process (the registry's stop and start, and through
`internal/wsapi/console_hooks.go` the pairing cancelled, the status
broadcast and the notices pushed). Until the frames move, the rules live
in two places, and a parity test per kind holds them together. The target
is checked before the role, as the frames resolve the number first. A
resume lifts a move's pause by role, as the frame does. One divergence: a
console resume whose start fails keeps the pause lifted, where the frame
puts it back, since its `ran` was committed with the lift and the number's
connection shows in its row; the supervisor starts it within its tick. A
runner's start is bounded (15 seconds) where the frame's is not: the
executor runs every workspace's commands one at a time, and a connect
that keeps failing retries for a minute and a half; past the bound a
sync now is `connect_failed` and a resume is the supervisor's. Each act
reads its number by the command's workspace beside the row-level
security, so a fault in either still finds nothing of another workspace.

**DS10. A rename to a label Wappie sets aside is refused.** A
placeholder, an opaque or legacy id, or a name holding the number's own
digits, as typed or as the contract cleans it, is `not_authorized`, and
nothing is stored. 12a ran it and stored it, as the frame does, and the snapshot
published `null`: the console showed the rename done and the number
unnamed (the platform's check of fcffb55, finding 4). `label_changed`
would say it best ("Wappie keeps the name another way"), but its
`detail.cleaned` must be a label the kit's `ValidLabel` takes, never
empty or `null`, and `item.rename`'s `after` is always a label (the
spec's 14.7), so no answer says "published as unnamed". Of the codes
`item.rename` may answer, `not_authorized` is the one that is true: the
spec's 14.9 reads "the actor's role or the app's rule does not allow it",
and Wappie's rule (the spec's 8.1: the app sets aside placeholders, ids
and the number itself) does not allow that name as a number's label; it
is final, as a retry would meet the same rule, and nothing changed, so
the number keeps the name the console drew. `state_changed` (a race),
`app_only` (Wappie's own screen would store it and the console would
still show it unnamed) and `invalid_value` (not one of `item.rename`'s
codes) are not. The check runs on the label as typed, as the spec's 8.1
sets aside before the cleaning: the number itself ("+55 11 90000-0001",
or its bare digits) and a UUID of digits clean to "…" and the last four
digits, which a check of the cleaned label alone offered back as a
`label_changed` (the review of the follow-ups), where the frame's copy of
the same text publishes `null`. It runs on the cleaned label too, before
`label_changed`, so a confirmation never offers a name that would then
be refused. The frame still stores such a label, as Wappie's own screens
take it: the one divergence of the rename's parity test.

**DS11. Sign-out everywhere ends what began before it.**
`person.sign_out_everywhere` ends the actor's session families whose first
row is older than its `issued_at`, their workspace sessions with them, and
counts their live rows (`sessions_ended`); a later family, an API key, a
key acting for the person, an MCP or AI connection all stay. It locks as a
logout does, the passkey registration lock first, which every session's
start takes too. `signed_out_everywhere_at` keeps the latest `issued_at`
that ran, since the ledger keeps 30 days only; a rerun delivered again
after Wappie's own restore ends only what began before the command.

**DS12. The numbers section's cadence, and the labels.** As the spec's
14.2 asks: 2 seconds after a change the section shows (0052's triggers, on
their own channel, and every payload of the snapshot's dirty channel,
members included, so a document that changes the workspace's members
sends it too), at once after an act or a reset, at the leader's start, and
55 minutes after its last accepted one. A connection that only flips
between online and offline (whatsmeow writes offline at every disconnect)
waits 30 seconds, so a flapping number sends one section per workspace per
30 seconds; a later connection time alone sends nothing, the row showing it
as of `measured_at`. After an outage the command feed's first page makes
every section that backs off due at once, as the account feed's does for
the snapshots. A row the wire refuses is left out with `truncated`, as the
spec's 14.2 says, where the plan had the whole section `local_invalid`; a
section that still fails is. A parked snapshot does not hold back its
workspace's section, which has its own park. A numbers row carries no
label (the snapshot's is the number's). 0052 nulled the labels of the item events not yet sent, once.
A row is `read_only` when its number is logged out or banned (the spec's
14.3), deleted (the platform's commitment), or no identity of it is
stored (a pairing that connected and never linked; the platform's check
of fcffb55, finding 5): Wappie holds no session it could start for it,
the "no session to the number" of the spec's 14.9 `read_only`. The rule
reads what is stored, so it also takes a number that did link but whose
identity Wappie failed to save at the pairing and at every connection
since (the device holds it in memory only, with an ERROR each time): very
rare, and while it captures the console holds back Pausar on it, which
Wappie's own screen still offers. Its sync
now is `not_linked`, and a stop would leave a pause the console cannot
lift (`can_resume` false, a resume `state_changed`), so the console holds
both back, as on a logged-out number, and sends the person to Wappie
("Abrir no Wappie", `not_linked`'s way out too). There its start, its
pairing retry (it connected) and its relink (no identity stored to
compare the scan with, the spec's 14.13) all refuse it: an owner deletes
it and links the phone as a new number. Once its identity is known the
row changes (0052's trigger watches `lid` and `pn`).
The person's notices (the commands release) are the unseen ones of
platform workspaces where Wappie lets the person in (membership, account
and workspace active, the membership not expired: a disabled member sees
no notice of the team in the console, as on Wappie's own page), the newest
300 (more sends the document `truncated`, as a list cut to fit; no
ERROR, the bound is the spec's), each versioned as `SeenNotice`
acknowledges it, their label cut over at render (one stored before 0052
is kept only when today's rule gives the same), and a notice deleted sends the person's document again, as does a
change in a workspace where they hold one, and an account's status
(everyone's). An act makes the documents it shows in due at once, a parked
one too, for one try: a park would otherwise keep the console from ever
seeing the act shown. A switch between `read` and `on` makes every
document due in its transaction and again once the leader's watcher holds
the new mode, since the sender renders `accepts` from it.

**DS13. Sync now for a person is Read's.** The platform's answer 4 (the
owner's "readers"): a person's sync now asks `ActionRead`, in the
console's `item.sync_now` and on the socket's `device.start` of a number
not paused alike; keys, and service accounts through them, keep Manage
with full scope. Followed literally, an owner or an admin who does not
read the number may not. The runner shipped first, built and tested;
`item.sync_now` entered `accepts` with the release that widened the frame,
so the console never offered what Wappie's own screen refused. Since any
reader may click it, and the executor runs every workspace's commands one
at a time, a sync now's start that fails makes the number's next sync
nows wait a minute: `rate_limited`, with the seconds left, and no start,
so repeated clicks on a number that cannot connect hold the other
commands for at most one start bound a minute per number.

**DS14. One lock order for every 12a writer**, `Restart`'s:
`contract_state`, `contract_accounts`, the records in id order,
`contract_settings_state`, the ledger rows in id order, the `wseq` memory,
`tenants`, `devices`, `device_notices` and `sessions`,
`contract_sections`, `contract_persons`. A reset clears the command feed in
`Restart`'s own transaction. A take holds `contract_state` `FOR SHARE`, so
a take and a reset never interleave. An act takes its record first and
reads `contract_state` and `contract_accounts` with no lock (a stale
generation only leaves a result the poster drops), and records an ERROR
only after its transaction ends. The results poster clears
`results_error` before it settles the ledger rows. Every statement that
locks several ledger rows or persons takes them in key order (a `FOR
UPDATE` subquery), the trim's and a take's deletions included, and a row
past its 30 days is the trim's alone: neither a reset nor the poster drops
it.

**DS15. Both roles must allow.** Wappie observes the platform's
memberships, so a command runs only where Wappie's own local role (its own
screens' rule) and the role the stored account document gives the
workspace both allow it; where they differ it is `not_authorized`, both
ways. A document that is not active, of another generation, or that does
not name the workspace counts as none. Rename is Manage's: the document's
member is enough only where the local Manage is the stored flag's.

**DS16. The platform is told first.** `contract settings read` (or `on`)
the first time, and `off` once the feed was read, need `--platform-told`:
from the first read the platform watches the command feed for good, and
alerts when it goes silent.

**DS17. A resume's mark is never lost.** The console's resume marks its
number's pause notices resumed in the transaction that lifts the pause,
as the relink's attach does. The frames mark in a transaction of their
own, which may fail: a repair, hourly in every process and before each
person's document, marks a notice whose number has been unpaused for 10
minutes, at the unpause's time (`devices.unpaused_at`, or 0052's migrate
time for a resume before 0052 stamped one). The plan had a minute, but
`device.start` lifts the pause before it starts the number, whose connect
may retry for a minute and a half, and puts the pause back when it fails:
a mark inside that window would say resumed of a number paused again. A
number paused again is left: its notice is open. A workspace with no
notice to mark takes no lock for the repair.

## The console's flags kinds (2026-11-09)

Step 12b gives the console's `numbers` section three more kinds:
`item.flags_raise`, `item.flags_drop` and `item.access_remove`, a
person's `read`, `send` and `manage` on a number. No migration: the ledger
takes any kind, and the flags, grants, triggers and protection rule exist.
F1 built the acts on Wappie's own permission write and the runners; F2
wires them into the executor and lists them. The platform's answers to Q1
to Q6 and the owner's to Q7, Q8 and Q58 are applied. These decisions are
numbered on from DS17 (DS26 to DS45 belong to the later sections of 12b).

**DS18. Who.** The flags kinds need `RuleAdmin`: owner or admin locally
and in the stored document, both (DS15). An owner's flags are only an
owner's (the owner's answer to Q58): where the target is an owner,
locally (whatever the membership's status) or in their stored document,
the actor must be an owner on both sides, else `not_authorized`. The
target's role is read fail-closed, so a person the two sides disagree on
counts as an owner. Wappie's own permissions screen refuses an admin the
same way (`ErrOwnerTarget`, 403 `not_authorized`). Since F4 the socket's
`grant.revoke`, which changes no flag, refuses an admin on an owner too,
read fail-closed the same way, with a `not_authorized` frame (DS48, the
platform's answer).

**DS19. The drop** removes `before \ after` from the current flags, so a
flag raised since stays, as the platform's reference app does. When
`read` goes, every grant of the person on the number goes, at every
epoch, even when the flag was already gone (no dormant key, 0040). It is
never `state_changed`: Wappie keeps no time per flag (the spec's 14.6),
so a drop retried late may undo a raise made since on Wappie's own
screen (the owner kept this, Q7).

**DS20. The remove** sets every flag false and keeps the row, so a key
shared later does not bring back read and send through
`grant_initial_permissions`; every grant of the person on the number
goes, a key holder's without read too. The person stays in the snapshot
with `can: []` (Q1).

**DS21. Deleted numbers.** Drop and remove run on a deleted number of
the workspace, read under quarantine for that one statement (and the row
written under it, which 0036's ownership trigger needs); `sole_key_holders`
still protects its last holder (`last_reader`). A raise there is
`state_changed`, as the platform's own retry answers it; another
workspace's number or a gone one is `not_found`. Wappie's own screen
finds no deleted number; that difference is pinned by the parity test.

**DS22. The target person.** Not linked or not followed: `not_held`,
judged on a seq, also when `based_on.docs` leaves them out. For a raise,
a target Wappie holds as not active locally (a suspended or expired
membership, a disabled local account, a stored document disabled or
closed, or a disablement seen later than the document's own) is a final
`not_found`, judged read-only before the freshness, so it is never
`memberships_unconfirmed`: no retry lifts a suspension (the platform's
Q6). For a drop or a remove, `ran` only when there is no membership row
at all; a suspended or expired one still has its flags and grants
removed.

**DS23. Freshness.** A raise asks `RequireWidening` for the actor and the
target (in a team both, a GET for a stale one; in a personal workspace
the actor's stored status). A drop of read, and a remove, ask
`RequireBackups` when the target reads the number or holds its key, in a
team only. Both run before the act, outside any write transaction;
`last_reader` is judged inside it. A refusal is `memberships_unconfirmed`,
a retry; a drop or remove delivered again waits instead.

**DS24. No seal, no connections.** `grant_needed` is never answered: the
kit refuses a raise of read, and Wappie's send and manage need no seal.
A person's MCP connections and AI integrations keep their copy of the
number's key after their Read goes, as on Wappie's own screen
([mcp-enclave](mcp-enclave.md) 15.15). The owner answered Q8 yes, for the
person's own connections and integrations only: F3 ends those that held
the number, whole, on the screen and in the acts alike (DS47, the
platform's decision 0061).

**DS25. A binary sends only the sections it renders.** The sender picks
only rows of the sections this binary renders (`NextSection`'s filter,
`numbers` today), and 0054's and 0055's down-steps delete the rows they
added, so a binary rolled back below a section never loops sending
`numbers` for a row it cannot render.

**DS46. The flags kinds go live with R3's deploy, after the platform's
notice.** There is no switch: a binary lists the kinds it runs from its
start, the settings mode being `on` already. `WS_CONTRACT_FLAGS` was
dropped, since it would mean editing the pilot's `runtime.env`, and a
binaries-only rollback is as cheap. F2 merges only when R3's kit is ready,
so no earlier release, step 7's stage A included, carries the kinds
unannounced. Their rollback is the release before's binaries, after
telling the platform: a drop or a remove in flight then waits
(`kind_not_accepted` is a retry for a tightening), a raise in flight ends
final.

**DS47. A person's lost Read ends their own connections that held the
number** (the owner's answer to Q8, relayed by the platform, final, and
the platform's decision 0061, which amends 0060 on what ends and what a
consent needs; F3). When a person's Read on a number goes, or their
access to it is removed, on Wappie's permissions screen or through the
console's `item.flags_drop` (of read, or of the last flag left) or
`item.access_remove`, the one write both use (`setDevicePermissionTx`)
also ends, in the same transaction, every live MCP connection the person
consented to (metadata or content, any client) and every AI integration
they created in that workspace that holds the number (its key names it,
or its service account has a permission or a grant on it): whole,
`access_lost`, also when it holds other numbers. Each ends as a revoke ends it
(`endMCPConnectionTx`): its key revoked, its drafts still waiting for a
person revoked, on every number, and for content and AI its service
account removed with its permissions and grants on every number. Its
reader is told after the commit as `Revoke` and `RevokeAI` tell it (best
effort; the 30-second re-tell is the backstop). Another person's
connections, workspace API keys with no connection behind them, and
legacy MCP tokens keep what they were given, whoever gave it (0032,
0053).

Why whole (0061): a connection or integration narrowed to the numbers
left could never renew, since a renewal must name exactly its key's
numbers while the reader's record and an AI integration's `ai_config`
(whose `cfg_tags` cover every number it was sealed over) still name the
one taken off, and Wappie's check would then show the integration as not
verified: it would linger in a state that looks broken. A media
connection's attachment caches also answer by the numbers its sealed
record names until it ends ([mcp-enclave](mcp-enclave.md) 16.9). The
person consents again for the numbers they still read. A deletion and a
move out already end such connections the same way. F3's first build
(`212e8ed`) took the number off and ended only a connection left with no
number or with attachments; 0061 replaced that before any release.

The write decides when it applies, from the flags it writes, so the
screen and the acts agree by construction: when Read goes (the stored
row had it), or when no flag is left (an access removal:
`item.access_remove`, the screen's PUT with every flag false, or the
console's `item.flags_drop` of the last flag left, send or manage, with
Read gone already). That last drop deletes no key (DS19; its freshness
asks nothing, DS23), yet ends the connections as the screen's PUT with
no flag does; F3's first build ended them only on a write that dropped
keys, so the console's drop of the last flag ended none (found in
review, fixed before any release). A change that keeps send or manage
while Read was already gone (a raise, a drop of the other flag, a drop
of read) ends nothing, and nor does a raise, a drop of send or manage
with Read kept, one that finds the flag gone already (it writes
nothing), or a refusal (`last_reader`, an admin on an owner). The
screen's PUT without Read still deletes a dormant grant, as before
([contract](contract.md), the flags kinds).

Connections already live with no Read behind them are not swept by F3.
Before 0061 a metadata consent asked no Read (an admin could give one on
any number of the workspace), and before F3 a lost Read left a content
connection or an AI integration as it was. Such a connection, whose
person has no Read on a number its key names, has no Read for a drop of
read to take: it ends when the person's access to that number is removed
(a remove, the screen's PUT with no flag, a drop of their last flag),
when the number is deleted or moved out, on a revoke, or at its expiry.
A content one or an AI integration cannot renew without Read, so it
lasts at most its consented lifetime (90 days at most); a metadata one
never renews and lasts up to its own (a year at most, for a tested web
client). The platform answered: the check at every start ends them, from
F4 on (DS48).

Every consent, metadata included, and every renewal is refused
(`ErrMCPKeyUnsuitable`, HTTP 422 `key_unsuitable`) unless the person
consenting reads every number of its key at that moment: Read, the flag
and a grant at the number's current epoch, not retired (0053). A
metadata connection needs it as a token needs Read for metadata (0053);
otherwise the person could consent again at once to what losing Read
just ended. Consent, renewal and the drop all hold the workspace's
tenants row, so a consent the console prepared before the drop and
recorded after it is refused, and no live connection of the person
reaches the number. A metadata connection has no renewal of its own in
Wappie (it never reseals): a reconnection, replacing one or not, is a
new consent, held to the same rule.

Locks keep 3.2's order: the person's permission, membership and grants,
then their connections in id order (`FOR UPDATE`), then each
connection's own rows, as a revoke takes them. The AI pick still asks
for the number on the row's key as well as in its `ai_config`, though
nothing narrows a live integration's key any more.

0061's third rule, a `grant.revoke` alone that leaves the person no
grant at the number's current epoch, is F4 (DS48).

**DS48. A grant revoked alone takes Read; the check at every start**
(the platform's decision 0061, its third rule, QF3; the platform's answer
on F4's scope; and its answers F1 to F5 on wappie#74; F4).

The socket's `grant.revoke` deletes the person's grants on the number,
at every epoch, as before. A revoke that deleted one leaves them no
grant at the number's current epoch. When the person has the Read flag,
that takes their Read, though the flag stays. In the same transaction it
ends every live MCP connection they consented to (metadata or content)
and every AI integration they created that held the number, whole,
`access_lost`, as a drop of read does (`Keys.RevokeGrantEnded`,
`grantTakenTx`, then F3's `leaveOwnConnectionsTx`). Their readers are
told after the commit, within one 5-second bound, as the screen and the
console's acts tell them (best effort; the 30-second re-tell is the
backstop). A revoke that finds no grant ends nothing. A refusal changes
nothing. Another person's connections, workspace API keys and their
`acts_as` accounts, and legacy MCP tokens keep what they were given,
whoever gave it (0032, 0053).

A dormant grant (the Read flag already off) gives no Read, so its revoke
takes none and ends nothing (the platform's F3). The flag is cleared on
one path only, `setDevicePermissionTx`, which ends the connections when
it takes Read. The 0023 trigger and a move to Personal only write it
true, and the other writes delete whole rows after the person's
connections ended. `TestReadFlagClearedOnlyBySetDevicePermission` pins
this. From a dormant grant the paths differ in one way. The screen's PUT
without Read and the console's `item.flags_drop` of read delete the
grant too; when they leave no flag at all, they end the person's
connections on the number, as an access removal does (DS47). With send
or manage kept they end nothing, as a dormant grant's revoke does. Only
`grant.revoke` changes no flag, so only it can leave a connection from
before 0061 on a number with no flag left: the check at the next start
ends it (below).

The rule looks after the act at what is left: a grant at the number's
current epoch, its archive key not retired. So a grant replaced in the
same transaction takes nothing, and nor does an act that deletes an old
epoch's grant and keeps the current one. `grant.revoke` deletes every
epoch, so for it only the flag decides; those two cases are tested
through a test hook (`GrantTakenForTest`).

A rotation deletes no grant and never reaches the rule (0061). A content
connection or an AI integration then needs a reseal or a renewal anyway.
A metadata connection does not: it never reseals (0042) or renews, and
its key's check (`AllowsDevice`) asks nothing of the person's grant. So
a person left out of a rotation would keep a metadata connection until
it expires, up to a year. No code rotates or retires a key, and none
will until the platform decides how: `CreateArchiveKey` runs only at
epoch 1 (pairing, `device-key`, which refuses a second key, and the demo
seed), and nothing sets `retired_at`. A `grant.revoke` during a
rotation, when the person holds only the old epoch's grant, takes the
key they would be sealed again from: it counts.

**Who may revoke** (the platform's F2). `grant.revoke` reads its actor's
role again under the workspace's lock (`lockWorkspaceManager`): a
socket's role can be stale. The actor must be an active owner or admin
of an active workspace, as 0040 asks of every act on access; otherwise
`ErrMembershipForbidden`. Only an owner changes an owner's access (DS18,
the owner's Q58, the platform's 0060): an admin whose target
`ownerTargetTx` reads as an owner, fail-closed, is refused with
`ErrOwnerTarget`, before the last-reader check and the delete, a live
grant or a dormant one alike. The socket answers both with a
`not_authorized` frame, not an HTTP 403; before F4 both fell through to
`internal`. A workspace or a membership that is not active is refused
the same way. `RevokeGrant`, the error-only form, takes the actor too.

Wappie's own screen revokes the key with `grant.revoke` before its PUT
(the web app's `changeDevicePermission`). An admin who unticked an
owner's Read would have lost the owner's key before the PUT was refused.
The server now refuses that revoke. The web app, in wappie-cloud and its
own pull request, disables an owner's whole row for a viewer who is not
an owner, and a row whose role is not loaded yet: the PUT refuses an
admin any change there (`ErrOwnerTarget`).

**A connection's own account** (the platform's F2, built in F4). A lone
`grant.revoke` on an account a connection names (`service_user_id`)
narrowed the connection without ending it, since
`leaveOwnConnectionsTx` matches `created_by` only: the state 0061
removes. The revoke now locks that connection before the account's rows
(the tenants row, then the connection, then its own rows) and, when it
deleted a grant, ends it whole, `access_lost`, in the same transaction.
Its reader is told after the commit. Wappie chose to end it rather than
refuse: a refusal would leave no way to take a copy back short of the
connection's own revoke.

`PutGrant` refuses a grant to a live connection's own account on a
number its key does not name or its person does not read
(`ErrConnectionAccountGrant`). The check at every start counts each
grant of the account as a number the connection holds, so such a grant
would end the connection at the next start. `grant.add` and a pairing's
grants answer `not_authorized`, the code `grant.add` gives an actor who
may not share (its `conflict` means a wrong epoch or a number with no
key). `device-key` asks the same of every account it is given
(`Keys.CheckGrant`) before it makes the number's key, and refuses a
connection's account: a refusal after the key would leave a key nobody
holds. A workspace API key's `acts_as` account stays as 0053 leaves it.

Wappie's screen's PUT (`PUT /devices/{id}/permissions`) reaches a
connection's own account too, through the REST API; the screen itself
calls `grant.revoke` or `grant.add` first. It follows the same two
rules (`setDevicePermissionTx`). A PUT that takes the account's Read
flag or deletes one of its grants ends that connection whole,
`access_lost`, in the same transaction, the connection locked before
the account's rows; its reader is told after the commit. Any other PUT
on the account, a raise or a row with no flag, takes only a number its
key names and its person reads, else `ErrConnectionAccountGrant`, 403
`not_authorized`, and nothing changes: the check counts every
permission row of the account, whatever its flags. A consent's
provisional account, which no connection names yet, takes any, as the
console's consent needs. The console's flags acts find their target by
its platform identity, which a connection's account has not.

**The archive reset** (the platform's F5). `ResetArchive`, the
operator's `reset-archive`, counts as Read taken away from everyone
(0061's third rule): it deletes every grant and leaves none at a
number's current epoch, which is neither a rotation nor a replacement.
It used to end nothing, and it may run while the server keeps running,
so it does not leave the connections to the next start's check. After
`device-key` gave a kept number a new key, sealed to the accounts
named, a live metadata connection of a person not named again read the
new metadata for up to a year (`AllowsDevice` asks nothing of the
grant). Without
`-keep-devices` the cascade emptied `api_key_devices`, so no check could
find those connections. Now the reset:

1. takes the workspace's lock first (`lockWorkspaceAccess`), which
   `endMCPConnectionTx` needs and which puts the reset in the lock order
   (`reader_safety.go`), so a consent recorded at the same time comes
   before it, and ends with it, or after it, and is refused;
2. ends every live connection of the workspace, any kind, pending,
   active or reseal, revoked and `access_lost`, through
   `endMCPConnectionTx`, before its deletes: a plain select by
   workspace, not the check's join;
3. returns the count, which the command prints. wappie-api's
   `WatchRevocations` tells the readers once it runs.

The operator stops `wappie-api` before any reset and starts it after.
The reset holds the workspace's tenants row to its end, and ingest needs
that row for every message, so a running server's ingest for the
workspace waits on it, holding connections of the shared pool. A
running server also caches each number's key (ingest's `pipelineFor`)
and nothing tells it the key changed: after `reset-archive
-keep-devices` and `device-key` it keeps sealing to the old key until it
restarts. So with `-keep-devices` the runbook is: stop `wappie-api`,
reset, `device-key -device <id> -grant <email>` for each number, start
`wappie-api` (docs/devices.md). The reset prints these steps, and
`device-key` ends with the restart. DS49 removes the need for the
restart: a running server now hears the reset and `device-key`.

The tests found two more things, fixed with it. With `-keep-devices` the
reset left the journal (`events`) and the receipts, which the
workspace's sequence numbered, and set the sequence back to 0, so the
next message failed on `events_pkey`; they go with the rest now. A
consent whose key no longer names any number (its numbers deleted by
the reset, or moved out) passed `consenterReadsTx` with nothing to
check; it is refused now. Taking the tenants row first also ends a
deadlock with ingest, which takes that row (`nextSeq`) before the chat
rows the reset deletes.

Every path that deletes or invalidates a person's grant, and why it is
or is not the lone revoke:

- `Keys.RevokeGrantEnded` (`grant.revoke`): the lone revoke. The flag
  stays, so nothing else would end the connections. It counts, as
  above. On a connection's own account it ends that connection.
- `setDevicePermissionTx` with its keys dropped (the screen's PUT
  without Read, `item.flags_drop` of read, `item.access_remove`): the
  Read flag goes with the grants. F3 already ends the person's
  connections when Read goes or no flag is left (DS47). With Read gone
  before, there was no Read to take. On a connection's own account,
  which only the screen's PUT reaches, it ends that connection when it
  takes the account's Read or a grant, as above.
- `UpdateMember` to disabled and `removeMember`: every grant and
  permission of the person in the workspace goes after
  `endConnectionsOfMemberTx` ended all their connections
  (`member_disabled`, `member_removed`). Nothing is left to end.
- `removeServiceAccountTx` (a connection's end, the janitor's expired
  provisional accounts): a connection service account's copies, never a
  person's grant. Not counted.
- `TransferPersonal` (a move to Personal): it moves only a number
  nobody else has access to (0040), so the grants it deletes hold no
  one's Read; the mover's own connections to the number end in the same
  transaction (`access_lost`). Not the lone case.
- Cascades: a number purged after its deletion (its connections ended
  at the deletion), a registration that never linked. Users and
  workspaces have foreign keys that cascade to their grants, but no code
  deletes either. None is an act on one person's grant; nothing is left
  to end.
- `ResetArchive`: every archive key and grant goes. It counts as Read
  taken away from everyone and ends every live connection first, as
  above.
- `CreateArchiveKey` at a new epoch (a rotation): every grant of the
  old epoch stops being current without being deleted. 0061: it does
  not count.
- `retired_at` on an archive key: nothing sets it.
- `PutGrant`'s upsert: a grant's sealed key replaced at the same epoch,
  in place. Not a removal.

**The check at every start** (the platform's F1). No marker and no
migration: `serve` runs `EndConnectionsWithoutRead` at every start, in a
goroutine once the HTTP listener is bound (by then the process it
replaces has let go of the port, and its sockets are ending). Never
`setupWith`, which the command line runs too, and it never fails the
start. It ends, whole and `access_lost`, every live connection whose
person does not read one of the numbers it holds: metadata, content and
AI; pending, active and reseal. A connection holds a number as
`leaveOwnConnectionsTx` counts it: its key's row, or its service
account's permission or grant on it. Its person reads the number as
`consenterReadsTx` asks of a consent: the Read flag, a grant at the
number's current epoch, its key not retired, the number not deleted. It
also ends a content connection or an AI integration whose own account
no longer reads, by the same rule, a number its key names while its
person still does: a narrowed one, which a `grant.revoke` or a PUT on
that account served by a binary before F4 left.

It locks nothing in the steady state. The tenants row is also ingest's
sequence lock (`nextSeq`), and the check runs while the start's history
work ingests. So each workspace's candidates are read first without the
workspace's lock. Only a workspace with a candidate is locked: one
transaction under its tenants row, waiting at most 5 seconds for each
lock (`lock_timeout`), the candidates read again and ended in id order,
each through `endMCPConnectionTx` as a revoke ends it. A busy workspace
is left as it was for the next start; the others go on.

It logs each end at Warn, ids only: the workspace, the connection, and
its numbers by kind with their remedy (keyless and orphan below;
narrowed, whose remedy is a new consent). It logs each busy workspace
at Warn too, and a failure or a panic at Error; neither stops the
process. Each reader is told within a 5-second bound of its own
(`TellRevoked`); `WatchRevocations` is the backstop.

It is an invariant check. The first pass after F4 ends what the rules
before left: a metadata consent that asked no Read before 0061, a
content connection or AI integration whose person lost Read before F3,
and a connection whose person lost their grant to a `grant.revoke`
before F4, and a content connection or AI integration narrowed by a
`grant.revoke` or a PUT on its own account before F4. After that first
pass, an end means an older binary served a reset, a lone revoke or
such a narrowing, or a path missed one. Why every start rather
than once: F4 does not wait for R4, a rollback needs no down-step, and
the check also heals a busy workspace, a lone revoke served by an older
binary and anything a path missed. Several servers need nothing more:
the next start closes a window that a server on the release before
leaves. Before F4 goes live on the pilot, its candidates are counted
read-only first.

**A number nobody reads** (the platform's F4: one definition of Read,
no carve-out). The check ends every live connection that holds such a
number, as `consenterReadsTx` refuses a consent on one. There are two
kinds, and the start's log line names each with its remedy:

- Keyless, no archive key at all (epoch 0): `reset-archive
  -keep-devices` from a binary before F4, a pairing cut off between
  `CreateWithID` and `CreateArchiveKey`, or a row older than 0009.
  Remedy: `whatserverd device-key -device <id> -grant <email>`, then a
  new consent.
- Orphan, a key and no grant to anyone but connections' and consents'
  accounts (`wsctl pair -orphan`, or `device-key` with no account).
  Those accounts' copies are sealed to keys that live only in a reader,
  so they do not count, as the contract's key holders leave them out.
  Remedy: a grant sealed with the printed key, or delete the number and
  pair it again with `-grant` (`device-key` refuses a number that has a
  key).

A rotation does not count. The check keeps a connection whose person
waits for a rotated number's new key: they keep the Read flag and hold
a grant at an earlier epoch of the number, its archive key not retired,
and none at the current one. Once that old key is retired, or the old
grant is gone (a `grant.revoke`), they no longer wait. Until the
platform decides on rotation, this skip stands and nothing sets
`retired_at`.

Tests: `TestGrantRevokeEndsOwnConnections`,
`TestGrantRevokeTakesNothing` (a revoke that finds no grant, a dormant
grant, the last key, an old epoch deleted, a grant replaced),
`TestGrantRevokeRotation`, `TestGrantRevokeOwnerOnly`,
`TestGrantRevokeConnectionAccount`, `TestGrantAddConnectionAccount`
(with `CheckGrant`) and `TestSetPermissionConnectionAccount` (the PUT
on a connection's account: a raise or a row with no flag past the
consent refused, a raise on its own number taken, Read taken ending the
connection whole) (store). `TestConsoleParityOwnConnections` runs the socket's lone
`grant.revoke` as a fourth path, with the same rows left, the same
readers told and the Read flag kept, and a dormant grant's revoke beside
the screen's PUT from the same state; `TestConsoleParityFlags` refuses
an admin's `grant.revoke` of an owner as the screen and the acts refuse
their drop and remove; `TestGrantFramesConnectionAccount`, its frames
and the PUT, 403 `not_authorized` past the consent and an end with its
reader told (wsapi).
`TestResetArchiveEndsConnections` (a consent and a renewal after the
reset refused; after `-keep-devices` and a new key granted to another
account, the old metadata key refused; without `-keep-devices`, ended
too) (store). `TestConnectionsWithoutReadSweep`,
`TestConnectionsWithoutReadSweepHeldByService`,
`TestConnectionsWithoutReadSweepBusyWorkspace`,
`TestConnectionsWithoutReadSweepLocksNothing` and
`TestConnectionsWithoutReadSweepNobodyReads` (an epoch-0 number, an
orphan number, one whose only grant left is a connection's account's,
a workspace an older binary reset, one this binary reset) and
`TestConnectionsWithoutReadSweepNarrowed` (store). `TestReadFlagClearedOnlyBySetDevicePermission` (store).
`TestOwnConnectionsLockOrder` races a lone revoke and the check, with
leftovers of its own to end every round, against F3's paths;
`TestResetArchiveLockOrder` races the reset against ingest, consents, a
renewal, a lone revoke, the check and the rest (store).
`TestCheckReadAtStart`, `TestReportReadCheck`,
`TestCheckReadAtStartSurvivesAPanic` and `TestServeRunsReadCheck` check
the start's lines, the busy one included, whom it tells and on which
bound, a panic, and where it runs; `TestServeWiresReaders` checks the
socket server tells serve's readers; `TestResetAndDeviceKeyTexts` pins
the reset's and `device-key`'s steps, the order in `device-key` of its
checks and its key, and the runbook in docs/devices.md
(cmd/whatserverd).

**DS49. Ingest and grants follow the number's archive key** (the
platform's decision W46, `7929b4a`, binding, from Wappie's own finding;
its part (b)).

The finding. Ingest builds each number's pipeline once (`pipelineFor`)
and keeps it: the number's archive public key and epoch, read once, and
a content key in memory that is due after 15 minutes or 1000 seals.
Nothing dropped it when the key changed: `Forget` ran only on a
release, a deletion and a move. After `reset-archive -keep-devices` and
`device-key`, a running server:

1. until its content key was due, stored messages under a content key
   the reset had deleted (`messages.content_key_id` has no foreign key):
   lost;
2. after that and before `device-key`, had each new content key refused
   by its foreign key: messages refused;
3. after `device-key`, which makes the new key at epoch 1 again, sealed
   its next content key to the old public key and filed it at epoch 1:
   every later message unreadable, silently, until a restart.

The same reuse of epoch 1 let a grant sealed with the old key be
recorded at epoch 1: `grant.add` compared only the epoch. Under 0061
such a grant counts as Read, so it admitted consents and metadata for a
person who cannot open the number.

**(i) The notice.** `ResetArchive` and `CreateArchiveKey` send
`store.ArchiveKeyChannel` (`wappie_archive_key`) in their transaction,
so it reaches every process at the commit. The payload is the workspace
id for a reset and `workspace:number` for a new key. These are the only
paths that make or delete the key of a number that may be ingesting:

- `CreateArchiveKey`: pairing (a number's first key, which no pipeline
  holds yet), `device-key` and the demo seed.
- `ResetArchive`: every key of the workspace.
- A deletion's purge deletes the key 30 days after the deletion's own
  notice (`DeviceExcludedChannel`) let go of the number, and a pairing
  that fails deletes a number that never linked. Neither leaves a
  pipeline to drop.
- A move to Personal keeps the key and its epoch. It pauses the number,
  whose release drops the pipeline, and the process that served the
  move drops it too.
- Nothing rotates or retires a key (DS48).

`serve` listens on a connection of its own, as for deletions
(`listenNotices`, `keepListening`), and drops the pipelines named:
`Router.ForgetWorkspace` for a reset, `Router.Forget` for a number. The
next message builds the pipeline again from the key as it is now. After
the reset it is refused, since the number has no key, and after
`device-key` it seals to the new key. Each time listening starts, and
again after a failure, the listener drops every pipeline
(`Router.ForgetAll`), since a notice sent while it was not listening is
lost. Each notice is an Info line. `pipelineFor` holds the router's
mutex while it reads the key, so a notice that lands during a build
waits and drops the pipeline built.

Why a notice: it costs nothing in the steady state, and it ends the
first case within the notice's delay, which no check at the next
content key can. The checks below need no notice, and the notice spares
each number one refused write after a reset.

A dropped pipeline seals nothing more (`Pipeline.drop`,
`errPipelineDropped`). The history worker held one pipeline for a whole
chunk, so after a notice it went on sealing under the deleted content
key, and once that key was due every later message of the chunk was
refused. Now each message of a chunk, each chat name and each contact
name fetches the number's pipeline (`Router.ingest`, `Router.SealFor`).

**(ii) The check before each content key.** Every sealer of the router,
and `reproject`'s, makes its content keys through
`Keys.CreateContentKeyFor` (`ingest.PinnedKeys`). In the content key's
own transaction it takes the workspace's tenants row `FOR UPDATE`
(`lockWorkspaceAccess`), then reads the number's current key and epoch,
and refuses another key or none with `store.ErrArchiveKeyChanged`. The
insert's own trigger (0036's `archive_owner_lock`) takes that lock
anyway, so this only takes it earlier. A weaker lock deadlocked: two
numbers of one workspace each held it and waited for the other at the
trigger (`TestCreateContentKeyForTwoNumbers`). A reset takes that row
`FOR UPDATE` before its deletes, so the read sees the key wholly before
the reset or wholly after it. Read first, a reset and `device-key` could commit
between the read and the insert, and the foreign key would find the new
key's row at epoch 1; the race test shows that. A failed seal, this
refusal or any other, drops the pipeline (`Pipeline.sealAll`,
`Router.drop`), so the next message builds it again. This catches the
third case with no notice heard, at the next content key, and the
second with a clear error. It costs one indexed read per content key,
at most one per 1000 seals or 15 minutes of a number.

**The check at each write.** A value sealed before the reset's commit
and written after it named a content key the reset had deleted. The
write waited for the reset's lock on the workspace, then went in: a row
in the new archive that nobody can open, holding its message's slot
against a backfill. So every write of what ingest sealed names the
archive key its content key was sealed to: `InsertMessage.ArchiveKey`
(a message, and a placeholder it fills), `Messages.Reproject`,
`ChatMeta.NameArchiveKey`, `ContactName.ArchiveKey` and
`Contacts.SetAvatar`. The pipeline sets it, and `SealFor` returns it to
the avatar worker. After the workspace's lock (`nextSeq`, or the
write's own `storage_lock` trigger), the write reads whether that
content key is still stored at an epoch whose key is that archive key
(`contentKeyIsTx`), and refuses it with `ErrArchiveKeyChanged`
otherwise. Naming the key and not only the id matters: after
`device-key`, a new content key takes id 1 again, and a stale write
naming id 1 would pass an id check. This also ends the first case with
no notice heard, at the next write rather than the next content key. A
write that names no key (a tool, a test, the demo seed) is not checked.
It costs one primary key read per write.

A message refused for a changed key, here or by the check before a
content key, is tried once more with the pipeline built again
(`Router.ingest`, and `SealFor` for a seal). After `device-key` it is
stored under the new key. Between the reset and `device-key` the number
has no key, and it is refused with `ErrNoArchiveKey`: not stored, and a
later backfill can still bring it.

**(iv) Every grant names its key.** `store.ArchiveKeyFingerprint`
(`internal/store/archive_fingerprint.go`) is the one definition: the
lowercase hex SHA-256 of the stored public key bytes
(`device_archive_keys.public_key`, the 32 raw X25519 bytes), 64
characters, no prefix. `store.Grant.Fingerprint` is required.
`PutGrant`, the one statement that writes a grant, compares it with the
number's key at the grant's epoch, not retired, after the workspace's
lock and in the same transaction (`archiveKeyIsTx`, in the same file,
which step 7's token grant shares). Another key is
`ErrArchiveKeyChanged`. No key is both `ErrArchiveKeyChanged` and
`ErrNoArchiveKey`, so `grant.add` and `token.grant`, which test them in
different orders, both answer `conflict`. A number moved to Personal or
deleted meanwhile is `ErrNumberGone`, as the insert's ownership trigger
answered before.
A missing or malformed fingerprint is `ErrGrantFingerprint`. A reset
takes the same lock first, so a grant whose context was read before
the reset is refused after it. Why the fingerprint and not the epoch:
the epoch number is reused after a reset, and (c), never reusing it,
needs a migration.

The writers:

- `grant.add` names the fingerprint of the key the client opened and
  seals. It carries the permissions screen's grants and every grant to a
  connection's or an AI integration's account: the console's consent
  and renewal seal the key in the browser and send `grant.add`. The
  handler also compares early, with the key it reads for the epoch.
- A pairing's grants: the request carries the public key itself, so the
  server names that key's fingerprint.
- `device-key` and the demo seed: the key the command just made.
- The screen's `PUT /devices/{id}/permissions` and the console's acts
  write no grant; they delete one. A move to Personal moves rows and
  makes none.

The grant context: every grant listed by `GET /v1/auth/me`,
`grants.list` and `GET /v1/grants` carries `fingerprint`, computed from
the key row at the grant's epoch: the number's key now, not the key
sealed in that grant. So a client does not echo it. It computes the
fingerprint of the key it opened (`seal.archiveKeyFingerprint` of its
public half, the same SHA-256), refuses a grant whose key differs from
the listed one with `no_grant`, and sends its own. An echo would let an
old grant at a reused epoch, sealed with a key a reset deleted, be
granted again: it is listed with the new key's fingerprint.

**The wire.** Core and cloud ship together, since the cloud pins the
core.

- `grant.add` (`GrantRequest`) takes a required `fingerprint`. A
  client without it is refused with `bad_request`. Another key's
  fingerprint, or a number with no key, is `conflict`, as a wrong
  epoch is. Both codes are in the existing set.
- `grants.list` (`GrantEntry`), `/v1/auth/me` (`grants[]`) and
  `GET /v1/grants` gain `fingerprint`. A client that ignores it reads
  them as before.
- `pair` does not change.
- A web page loaded before the deploy gets `bad_request` on its next
  grant or consent with message text, and a reload fixes it. If the
  core went out before the web, every `grant.add` would get it, so the
  web goes out with the core or first; the R3 core ignores the field.

The clients that send `grant.add`, changed with it: wappie-cloud's web
(the permissions screen's `grantAccess`, the consent's `mcpSetup`, and
the session's lender `createDeviceGrantLender`, which computes each
key's fingerprint), `packages/client` (`withDeviceKey` and
`withDeviceKeys` compute it and pass it to `use`;
`seal.archiveKeyFingerprint`; the protocol types) and `packages/cli`
(`wsctl grant`). The Go `wsctl` only pairs, and the enclave reader only
reads grants.

Step 7's `token.grant` uses this file once step 7 merges main: its own
`internal/store/archive_fingerprint.go` goes, and its `archiveKeyIsTx`
calls, `ErrArchiveKeyChanged` and `ArchiveKeyFingerprintLen` resolve
to these.

**The runbook** (docs/devices.md). A running `wappie-api` needs no
restart after a reset or `device-key`. With `-keep-devices`: reset,
then `device-key` for each number; a message in between is not stored.
The reset still holds the workspace's lock to its end, so the
workspace's ingest waits while it runs; on a large archive the operator
stops `wappie-api` first and starts it after. The reset's steps and
`device-key`'s last lines say this. DS48's restart step is gone.

Not here: (c), never reusing an epoch number, needs a migration.
Nothing finds or removes a grant recorded before this change with an
old key at a reused epoch. One needs a `grant.add` sent between a reset
with `-keep-devices`, `device-key` and the client's next read of its
grants. Clients now refuse to grant from one (`no_grant`), but it still
counts as Read. The listening connection can hang half open until TCP
notices; the checks above hold meanwhile, as for deletions.

Tests: `TestArchiveKeyFingerprint` (the format, two vectors),
`TestCreateContentKeyForChecksTheKey`,
`TestCreateContentKeyForRacingReset`, `TestArchiveKeyNotices`,
`TestParseArchiveKeyNotice`, `TestPutGrantNamesItsKey` (a missing or
malformed fingerprint, the old key after the reset and at the reused
epoch refused, the new one taken, the context's fingerprint) and
`TestPutGrantRacingReset`, `TestCreateContentKeyForTwoNumbers` (no
deadlock) and `TestSealedWritesNameTheirKey` (each write, with its own
key, another key, a content key not stored, and no key named) (store).
`TestStaleSealerAfterNewKey`, `TestStaleSealerAfterReset`,
`TestStaleSealerBeforeItsKeyIsDue`, `TestStaleSealerAfterAnotherContentKey`
(id 1 taken again by another process), `TestMessageSealedDuringReset`,
`TestHistoryChunkAcrossReset` (notice heard and not),
`TestRouterForget` and `TestADroppedPipelineSealsNothing` (ingest).
`TestGrantAddNamesTheKey` (a client without the field, the old key from
a context read before the reset, the new key) and
`TestPairingGrantsNameTheirKey` (wsapi). `TestGrantsAreListedPerAccount`
(authapi, `/v1/auth/me`) and `TestRestrictedServiceKeyGrantsAndRevocation`
(restapi, `GET /v1/grants`) check the context's fingerprint.
`TestResetThenDeviceKeyWhileServing` (listening; not listening, with a
message between the reset and `device-key`, the stale content key not
due, and due; and started after both), `TestServeListensForArchiveKeys`,
`TestDeviceKeyGrantsNameTheKey` and `TestResetAndDeviceKeyTexts`
(cmd/whatserverd). The web's `grantStepUp`, `deviceGrants`, `mcpSetup`
and `mcpContent` tests check each `grant.add` names the key's
fingerprint, and `deviceGrants` that a stale grant is refused.
`packages/client`'s check the same, the Go vectors, and
`packages/cli`'s that it is passed on.

**DS51. A message that fills a placeholder is sealed to the
placeholder's uid** (from the contact-names review, X1).

The finding. Ingest picks a fresh uid for each message and seals its
values to it. The kit binds each value to its row: the AAD is label,
kind, tenant, row and header (`seal.AAD`), and the row is that uid. A
reader opens each value with the row's uid (`packages/client`'s opener
passes `message.uid`, for the body, raw, payload, media key, thumbnail
and file name alike). A message can fill an empty placeholder instead
of making a row (`fillStub`: an unsupported row with no body, no payload
and no attachment, under the same number, chat key and id). The row
then keeps the placeholder's uid. So its body, raw protobuf and payload
failed authentication, and readers showed them as tampered. The fill
also wrote no media row: an attachment's key, thumbnail and file name
were dropped, and nothing queued its download.

The fix, in the server only.

- `fillStub` fills only a message sealed to the placeholder's uid. A
  message sealed to another uid gets `store.PlaceholderError`, which
  names the placeholder's uid, and nothing is written. The check and the
  update share one WHERE clause (`emptyPlaceholder`).
- `Pipeline.Ingest` then seals the message again to that uid and inserts
  it again, once. Live messages, history and outbound all go through it.
- The fill writes the attachment's row under the placeholder's uid, as
  `Insert` does, and the pipeline nudges its download. It also sets the
  chat's `last_type` when the placeholder was the chat's newest message
  by timestamp, as `Reproject` does.
- `InsertResult.Filled` and `Result.Filled` report a fill. A fill is a
  duplicate too: no new sequence and no event. A reader sees the message
  when it next reads the chat.

Why the store decides. It decides in the insert's transaction, so a
placeholder written between a lookup and the insert is never missed. A
lookup before every seal would add a query on the hot path, since
history redelivers in bulk, and would still need the check. The cost is
a second seal, and only for a message that fills a placeholder.

Why not give the row the sealed uid. The uid is the primary key, and
other rows name it: `media.message_uid` (a foreign key with no ON
UPDATE), `ai_derived.message_uid`, `events.message_uid`, the
`target_uid` of reactions, edits and deletions, and `mcp_outbound`'s
`message_uid` and `reply_to_uid`. Clients also hold it from the
placeholder's own event. Keeping the placeholder's uid changes none of
them.

The other paths that write sealed message values:

- `Insert` of a new row seals to the row's own uid. Correct.
- `Messages.Reproject` (`reproject.apply` and `whatserverd reproject`)
  seals to the row's own uid. Correct.
- `MarkProtocol` writes no sealed value.
- An edit, a deletion or a reaction is a row of its own; `fillStub` fills
  only kind `message`.
- A copy under the conversation's other key (LID or phone number) is a
  duplicate and fills nothing, as before.
- A `placeholder` row (the phone masked the message) is not
  `unsupported`, so nothing fills it.
- `Router.ingest`'s second try after `ErrArchiveKeyChanged` goes through
  the same loop.

Rows filled before this change. Their values are sealed to a uid that
was never stored, and their attachment rows are missing. The server
cannot find them: it cannot open anything. A holder of the number's
archive key can. A value that does not open under its row's uid, under
a content key that opens, is one of them.

- Repair with the key. The lost uid can be computed from any value's GCM
  tag, given the content key: GHASH is linear in the AAD, and the uid is
  16 bytes of it. A prototype found it in 80 of 80 tries, with 1 to 4
  candidates, all of which decrypt to the same text. Every value of a
  row was sealed to the same uid, and it is a UUIDv7 made at the fill, so
  the values check each other. Every message keeps its raw protobuf, so
  a row has at least two values. The values are then sealed again to the
  row's uid, and the attachment's row is rebuilt from the raw protobuf
  through `normalize.FromRaw`, as `reproject` does. This needs a command
  run with the archive private key, like `reproject`. It is not built
  here.
- Fetch again from WhatsApp. A redelivery finds a filled row, not a
  placeholder, so it is a duplicate and changes nothing. The row would
  first have to become a placeholder again. And `history.backfill`
  anchors on the chat's oldest stored message, so it cannot reach one in
  the middle. Only a full history sync after a relink would bring it,
  and only while the phone still has it.

Not here: no migration, and no client change. A fill publishes no
event, as before.

Tests: `TestARealMessageFillsItsPlaceholder` (ingest: a placeholder,
then the real message through the pipeline; each value opens under the
row's uid, the media row exists and its download is queued, the chat's
type follows, no event, a redelivery changes nothing) and
`TestTwoCopiesFillAPlaceholderOnce` (two copies at once: one fills, one
is a duplicate, neither fails). `TestAFillSealedToAnotherUIDWritesNothing`,
`TestAFillKeepsItsAttachment` and
`TestARealMessageReplacesTheStubThatStoleItsPlace` (store).
`TestSealedWritesNameTheirKey`'s placeholder case now fills under the
placeholder's uid.

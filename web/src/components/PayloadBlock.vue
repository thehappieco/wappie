<script setup lang="ts">
import { computed, ref } from 'vue'

import type { Payload } from '../api/protocol'
import { joinGroup, openConversation, vote } from '../state/actions'
import { type MessageView } from '../state/archive'
import { limitOf, nextSelection, type Vote } from '../state/polls'
import { filename as icsName, ics } from '../ui/calendar'
import { stamp } from '../ui/format'
import { parse as parseCard } from '../ui/vcard'

// Cards only. Mentions used to be drawn here too, as a "menciona Fulano"
// footnote, because there was nowhere else to put them — the body is plain text
// rendered without v-html. They are now highlighted inside the sentence, which
// is where a mention means something, and MessageBubble keeps the footnote for
// the ones whose number does not appear in the text at all.
// The message is optional because most cards need nothing but the payload.
// The group invitation needs it: accepting requires knowing who sent the
// invitation, and WhatsApp validates the code against that pair.
const props = defineProps<{ payload: Payload; message?: MessageView }>()

const p = computed(() => props.payload)

const invite = computed(() => p.value.group_invite)
const inviteExpired = computed(() => {
  const at = invite.value?.expiration
  return at !== undefined && at * 1000 <= Date.now()
})

// The tally is computed when the message view is built, because counting means
// opening every vote and hashing every option — neither of which belongs in a
// render pass. Absent on a poll whose page has not finished opening.
const tally = computed(() => props.message?.poll?.tally)

/** votersFor is who chose one option, by its exact text. */
function votersFor(option: string): Vote[] {
  return tally.value?.options.find((o) => o.text === option)?.voters ?? []
}

function chose(option: string): boolean {
  return votersFor(option).some((v) => v.fromMe)
}

/** share is one option's bar width, as a share of the largest count. */
function share(option: string): string {
  const counts = (tally.value?.options ?? []).map((o) => o.voters.length)
  const most = Math.max(1, ...counts)
  return `${(votersFor(option).length / most) * 100}%`
}

/** voterList names who chose an option, for the hover. */
function voterList(option: string): string {
  const who = votersFor(option).map((v) => v.who)
  return who.length ? who.join(', ') : 'ninguém ainda'
}

const answered = computed(() => {
  const n = tally.value?.voters ?? 0
  if (n === 0) return 'ninguém respondeu ainda'
  return n === 1 ? '1 pessoa respondeu' : `${n} pessoas responderam`
})

// Voting needs the message, because the vote is keyed to the poll's own id and
// author. A poll drawn from a panel with no message behind it is read-only,
// which is honest: there is nothing there to answer.
const canVote = computed(() => Boolean(props.message))
const voting = ref(false)
const voteError = ref('')

/**
 * How many options this poll accepts from one voter.
 *
 * Not `selectable_count` read literally: a poll that stated no limit carries
 * zero there, and reading that as one is what made every multiple-choice poll
 * refuse a second tick. See limitOf.
 */
const limit = computed(() => limitOf(p.value.poll ?? {}))

/** Whether the poll accepts more than one answer. Also the indicator's shape. */
const multiple = computed(() => limit.value > 1)

/** How many of the limit are already spent. */
const chosenCount = computed(() => (p.value.poll?.options ?? []).filter(chose).length)

const atLimit = computed(
  () => `esta enquete aceita ${limit.value} ${limit.value === 1 ? 'escolha' : 'escolhas'}`,
)

/**
 * full says an option cannot be added because the limit is spent.
 *
 * Said before the press, by disabling it, rather than after — which is what
 * WhatsApp's own client does and is the kinder half of the same answer. The
 * refusal in pick() stays as the guard: a disabled button is a rendering, not
 * a rule.
 */
function full(option: string): boolean {
  return !chose(option) && chosenCount.value >= limit.value
}

/**
 * pick sends a vote, or withdraws one.
 *
 * A vote replaces the voter's previous answer rather than adding to it, so the
 * whole current selection goes out each time — that is what the wire carries —
 * and pressing an option already chosen sends the rest without it, which is how
 * WhatsApp takes a choice back.
 */
async function pick(option: string) {
  if (!props.message || voting.value) return
  const mine = (p.value.poll?.options ?? []).filter(chose)
  const next = nextSelection(mine, option, limit.value)
  if (next.refused) {
    voteError.value = `esta enquete aceita ${limit.value} ${limit.value === 1 ? 'escolha' : 'escolhas'}; desmarque uma antes`
    return
  }

  voting.value = true
  voteError.value = ''
  // The archive is what says the vote happened: the row comes back over the
  // socket and the tally is recomputed from it. Nothing is drawn optimistically
  // here, so a vote that did not leave never looks like one that did.
  if (!(await vote(props.message, next.options))) voteError.value = 'não deu para votar'
  voting.value = false
}

/** albumLine says what the header declares, in words. */
const albumLine = computed(() => {
  const images = p.value.album?.images ?? 0
  const videos = p.value.album?.videos ?? 0
  const parts: string[] = []
  if (images) parts.push(images === 1 ? '1 foto' : `${images} fotos`)
  if (videos) parts.push(videos === 1 ? '1 vídeo' : `${videos} vídeos`)
  // An album that declares nothing is still an album. WhatsApp sends the
  // header before it knows the counts, and "Álbum com 0 fotos" would be a
  // sentence about a bug rather than about the message.
  return parts.length ? `Álbum com ${parts.join(' e ')}` : 'Álbum'
})

type JoinState = 'idle' | 'joining' | 'joined'
const joining = ref<JoinState>('idle')

async function accept() {
  if (!props.message || joining.value !== 'idle') return
  joining.value = 'joining'
  joining.value = (await joinGroup(props.message)) ? 'joined' : 'idle'
}

/** The group picture that came with the invitation, as a data URL. */
const inviteThumb = computed(() =>
  invite.value?.thumbnail ? `data:image/jpeg;base64,${invite.value.thumbnail}` : '',
)

/**
 * A map link rather than an embedded map. Embedding one would load a tile
 * server, which means telling a third party every coordinate in the archive —
 * and the content security policy refuses the request anyway.
 */
function mapLink(lat: number, lon: number): string {
  return `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=16/${lat}/${lon}`
}

// Contact cards, parsed. The vCard arrives as text inside the sealed payload
// and is opened here — the shapes phones actually send need real parsing, not a
// regular expression: folded lines, quoted-printable for every accented name,
// and the waid parameter that is the only actionable thing in the card.
const cards = computed(() =>
  (p.value.contacts ?? []).map((raw) => {
    const card = parseCard(raw.vcard ?? '')
    return {
      raw,
      card,
      href: raw.vcard ? blobHref(raw.vcard, 'text/vcard') : '',
      filename: `${(card.name || raw.display_name || 'contato').replace(/[^\p{L}\p{N}]+/gu, '-')}.vcf`,
    }
  }),
)

/** eventFile is the .ics, built in this browser out of what it opened. */
const eventFile = computed(() => {
  const event = p.value.event
  if (!event) return null
  const uid = props.message ? `${props.message.uid}@whatserver2` : `evento@whatserver2`
  return { href: blobHref(ics(event, uid, new Date()), 'text/calendar'), name: icsName(event) }
})

/**
 * blobHref makes a file the browser can save.
 *
 * The URLs are deliberately not revoked. A card or an event is a few hundred
 * bytes, the alternative is revoking one while somebody is mid-click, and the
 * whole set goes when the tab does.
 */
const hrefs = new Map<string, string>()

function blobHref(text: string, type: string): string {
  if (typeof URL.createObjectURL !== 'function') return ''
  const key = `${type}:${text}`
  const seen = hrefs.get(key)
  if (seen) return seen
  const href = URL.createObjectURL(new Blob([text], { type: `${type};charset=utf-8` }))
  hrefs.set(key, href)
  return href
}

function openChat(waid: string) {
  void openConversation(`${waid}@s.whatsapp.net`)
}
</script>

<template>
  <div>
    <div v-if="p.location" class="card">
      <div class="title">
        {{ p.location.name || (p.location.seq ? 'Localização em tempo real' : 'Localização') }}
      </div>
      <div v-if="p.location.address" class="dim">{{ p.location.address }}</div>
      <div class="dim">
        {{ p.location.lat.toFixed(5) }}, {{ p.location.lon.toFixed(5) }}
        <template v-if="p.location.accuracy_m"> · ±{{ p.location.accuracy_m }} m</template>
      </div>
      <a
        class="linkish"
        :href="mapLink(p.location.lat, p.location.lon)"
        target="_blank"
        rel="noreferrer noopener"
        >ver no mapa</a
      >
    </div>

    <div v-if="p.poll" class="card poll">
      <div class="title">{{ p.poll.question || 'Enquete' }}</div>
      <!-- The count is drawn here and nowhere else: the server holds the poll
           and every vote and can match neither to the other, because both are
           sealed. This client opens them, hashes each option and looks for the
           result among the selections. -->
      <button
        v-for="(option, i) in p.poll.options ?? []"
        :key="i"
        class="poll-option"
        type="button"
        :class="{ chosen: chose(option), votable: canVote, multi: multiple }"
        :disabled="!canVote || voting || full(option)"
        :title="full(option) ? atLimit : voterList(option)"
        @click.stop="pick(option)"
      >
        <i :class="{ on: chose(option) }" />
        <span class="poll-label">{{ option }}</span>
        <span class="poll-count">{{ votersFor(option).length }}</span>
        <b class="poll-bar" :style="{ width: share(option) }" />
      </button>
      <!-- Said, because it changes what pressing an option does. A poll that
           stated no limit accepts as many as it has options, which is what
           "allow multiple answers" produces on a phone. -->
      <div class="dim" v-if="multiple">
        {{
          limit >= (p.poll.options?.length ?? 0)
            ? 'várias escolhas'
            : `até ${limit} escolhas`
        }}
      </div>
      <div class="dim">
        {{ answered }}
        <!-- Said out loud rather than folded into the numbers. A vote nobody
             could open is still somebody having answered, and a tally that
             quietly left it out would report fewer people than voted. -->
        <template v-if="tally && tally.sealed > 0">
          · {{ tally.sealed }} não {{ tally.sealed === 1 ? 'pôde' : 'puderam' }} ser
          {{ tally.sealed === 1 ? 'aberto' : 'abertos' }}
        </template>
        <template v-if="tally && tally.unmatched > 0">
          · {{ tally.unmatched }} para uma opção que não está aqui
        </template>
      </div>
      <div class="dim" v-if="voteError">{{ voteError }}</div>
    </div>

    <div v-for="(contact, i) in cards" :key="i" class="card">
      <div class="title">{{ contact.card.name || contact.raw.display_name || 'Contato' }}</div>
      <div class="dim" v-if="contact.card.title || contact.card.organisation">
        {{ [contact.card.title, contact.card.organisation].filter(Boolean).join(' · ') }}
      </div>
      <div v-for="(tel, j) in contact.card.numbers" :key="`t${j}`" class="card-line">
        <span class="dim" v-if="tel.label">{{ tel.label }}</span>
        <span>{{ tel.number }}</span>
        <!-- Only where the card names a WhatsApp account. The printed number is
             written however the sender's phone felt like writing it; the waid
             parameter is the one thing here that resolves to a conversation. -->
        <button v-if="tel.waid" class="linkish" type="button" @click.stop="openChat(tel.waid)">
          abrir conversa
        </button>
      </div>
      <div v-for="(mail, j) in contact.card.emails" :key="`e${j}`" class="card-line">
        <span class="dim" v-if="mail.label">{{ mail.label }}</span>
        <span>{{ mail.address }}</span>
      </div>
      <div v-for="(note, j) in contact.card.notes" :key="`n${j}`" class="dim">{{ note }}</div>
      <!-- Built from what this browser opened and never sent anywhere. The card
           is sealed content; handing it to something that renders vCards would
           undo the whole arrangement. -->
      <a
        v-if="contact.href"
        class="linkish"
        :href="contact.href"
        :download="contact.filename"
        @click.stop
        >baixar .vcf</a
      >
    </div>

    <div v-if="p.event" class="card">
      <div class="title">{{ p.event.name || 'Evento' }}</div>
      <div class="dim" v-if="p.event.start_time">
        {{ stamp(new Date(p.event.start_time)) }}
        <template v-if="p.event.end_time"> até {{ stamp(new Date(p.event.end_time)) }}</template>
      </div>
      <div v-if="p.event.description">{{ p.event.description }}</div>
      <div class="dim" v-if="p.event.location?.name">{{ p.event.location.name }}</div>
      <div class="flag revoked" v-if="p.event.is_canceled" style="display: inline-block">
        cancelado
      </div>
      <a
        v-if="eventFile"
        class="linkish"
        :href="eventFile.href"
        :download="eventFile.name"
        @click.stop
        >adicionar ao calendário</a
      >
    </div>

    <div v-if="invite" class="card invite">
      <div class="invite-head">
        <img v-if="inviteThumb" class="avatar sm" :src="inviteThumb" alt="" />
        <div>
          <div class="title">{{ invite.name || 'Convite para um grupo' }}</div>
          <div class="dim">convite de grupo</div>
        </div>
      </div>
      <div v-if="invite.caption">{{ invite.caption }}</div>
      <!-- The expiry is stated rather than left to the button failing. A code
           that has run out needs a new invitation, not another press. -->
      <div class="dim" v-if="invite.expiration">
        {{ inviteExpired ? 'expirou em' : 'vale até' }}
        {{ stamp(new Date(invite.expiration * 1000)) }}
      </div>
      <!-- Nothing here is automatic. Joining makes this account a member,
           visible to everyone already in the group, and there is no undo on
           this side — so it takes a press, every time. -->
      <button
        v-if="message && !inviteExpired"
        class="linkish"
        type="button"
        :disabled="joining !== 'idle'"
        @click.stop="accept"
      >
        {{ joining === 'joined' ? 'entrou' : joining === 'joining' ? 'entrando…' : 'entrar no grupo' }}
      </button>
      <div class="dim" v-else-if="inviteExpired">peça um convite novo</div>
    </div>

    <!-- A header and nothing else. It says how many pictures and videos follow
         and carries none of them: they arrive as ordinary messages of their
         own, and nothing in the protobuf links one back to this. So it is drawn
         as what it says rather than as a grid somebody guessed at. -->
    <div v-if="p.album" class="card">
      <div class="title">{{ albumLine }}</div>
      <div class="dim">as mídias chegam como mensagens próprias</div>
    </div>

    <!-- A business template's buttons. Labels only: pressing one sends a reply
         this archive has no way to compose, and a button that does nothing is
         worse than a list of what was offered. -->
    <div v-if="(p.buttons ?? []).length" class="card">
      <div class="dim">botões oferecidos</div>
      <div class="buttons">
        <span v-for="(label, i) in p.buttons ?? []" :key="i" class="flag">{{ label }}</span>
      </div>
    </div>

    <div v-if="p.link_preview" class="card">
      <div class="title">{{ p.link_preview.title || p.link_preview.url }}</div>
      <div class="dim" v-if="p.link_preview.description">{{ p.link_preview.description }}</div>
      <a
        v-if="p.link_preview.url"
        class="linkish"
        :href="p.link_preview.url"
        target="_blank"
        rel="noreferrer noopener"
        >{{ p.link_preview.url }}</a
      >
    </div>
  </div>
</template>

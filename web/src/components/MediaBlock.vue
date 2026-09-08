<script setup lang="ts">
import { computed, ref } from 'vue'

import { fetchMedia, type MessageView } from '../state/archive'
import { playedMessage } from '../state/reading'
import { bytes, duration } from '../ui/format'

const props = defineProps<{ message: MessageView }>()

const media = computed(() => props.message.media!)
const busy = ref(false)

const isPicture = computed(() => ['image', 'sticker'].includes(media.value.type))
const isVideo = computed(() => ['video', 'ptv'].includes(media.value.type))
const isSound = computed(() => ['audio', 'ptt'].includes(media.value.type))

/**
 * The URL of the attachment, once there is one to draw.
 *
 * The local copy comes first and it is not a fallback: for something this tab
 * sent, the file is right here and always will be, while the archived copy has
 * to be uploaded to WhatsApp and fetched back from its CDN before the server
 * can serve it. Preferring the download would mean watching a photograph you
 * just sent turn into a placeholder.
 */
const openedURL = computed(() => {
  if (media.value.localURL) return media.value.localURL
  return media.value.full?.state === 'ready' ? media.value.full.url : undefined
})

/** How far the upload has gone, while it is still going. */
const sending = computed(() => media.value.upload)
const percent = computed(() => {
  const progress = sending.value
  if (!progress?.total) return 0
  return Math.min(100, Math.round((progress.sent / progress.total) * 100))
})

const trouble = computed(() => {
  const full = media.value.full
  if (props.message.pending === 'failed') return props.message.failure || 'não enviou'
  if (props.message.pending === 'unarchived') return 'Enviada, mas não entrou no arquivo.'
  if (media.value.status === 'gone') {
    return 'A url expirou antes do arquivo chegar. Só o remetente pode reenviar.'
  }
  if (!full) return ''
  switch (full.state) {
    case 'pending':
      return `Ainda no servidor: ${full.status}.`
    case 'expired':
      return 'A url expirou antes do arquivo chegar.'
    case 'error':
      return full.message
    default:
      return ''
  }
})

async function reveal() {
  // Revealing a view-once is what WhatsApp calls playing it, and the owner
  // asked for the ordinary client behaviour here: the sender is told. It goes
  // through the same switch as every other receipt, so incognito silences it.
  if (props.message.viewOnce && !props.message.fromMe && !reported.value) {
    reported.value = true
    void playedMessage(props.message.waID)
  }
  // Nothing to fetch for an attachment that never came from the archive: the
  // row has no media record, so this would spend a spinner on an early return.
  if (busy.value || openedURL.value || props.message.pending) return
  busy.value = true
  try {
    await fetchMedia(props.message)
  } finally {
    busy.value = false
  }
}

/** The waveform is 64 amplitude samples, 0..100. */
const bars = computed(() => media.value.waveform ?? [])

/**
 * onPlayed reports a voice note listened through, or a view-once opened.
 *
 * Only for somebody else's message: telling WhatsApp we played our own is
 * meaningless. And only once — the flag is not reset, because a second listen
 * is not a second fact and a receipt cannot be taken back.
 */
const reported = ref(false)

async function onPlayed() {
  if (reported.value || props.message.fromMe) return
  reported.value = true
  await playedMessage(props.message.waID)
}
</script>

<template>
  <div>
    <!-- A picture or a video: the sealed inline preview draws immediately, and
         the full attachment is fetched only when asked for. Fetching every one
         while scrolling would download the conversation. -->
    <div v-if="isPicture || isVideo" class="media">
      <video
        v-if="openedURL && isVideo"
        :src="openedURL"
        controls
        :loop="media.isGIF"
        :muted="media.isGIF"
      />
      <img v-else-if="openedURL" :src="openedURL" :alt="media.fileName || 'anexo'" />
      <img v-else-if="media.thumbURL" :src="media.thumbURL" alt="prévia" @click.stop="reveal" />
      <div
        v-else
        style="height: 140px; width: 220px; display: grid; place-items: center"
        @click.stop="reveal"
      >
        <span class="sealed">sem prévia</span>
      </div>

      <!-- Leaving this tab. Its own band rather than the veil, so the picture
           stays visible underneath: the whole reason to draw it now is that
           somebody can see what they are sending. -->
      <div v-if="sending" class="sending">
        <div class="sending-bar" :style="{ width: `${percent}%` }" />
        <span>enviando {{ percent }}%</span>
      </div>
      <div v-else-if="trouble" class="veil">{{ trouble }}</div>
      <div v-else-if="!openedURL" class="veil" @click.stop="reveal">
        {{ busy ? 'Abrindo…' : isVideo ? '▶ abrir vídeo' : 'abrir imagem' }}
        <template v-if="media.fileLength"> · {{ bytes(media.fileLength) }}</template>
      </div>
    </div>

    <!-- Voice notes and audio. -->
    <div v-else-if="isSound">
      <div class="waveform" v-if="bars.length && !openedURL">
        <i v-for="(amp, i) in bars" :key="i" :style="{ height: `${Math.max(2, amp / 4)}px` }" />
      </div>
      <!-- "Played" fires when the note finishes, not when it starts. Starting
           is a click; finishing is the thing the sender is being told about. -->
      <audio
        v-if="openedURL"
        :src="openedURL"
        controls
        style="width: 260px; max-width: 100%"
        @ended="onPlayed"
      />
      <button v-else class="ghost" @click.stop="reveal" :disabled="Boolean(trouble)">
        {{ busy ? 'Abrindo…' : media.type === 'ptt' ? '▶ ouvir' : '▶ tocar' }}
        <template v-if="media.seconds"> · {{ duration(media.seconds) }}</template>
      </button>
      <div v-if="sending" class="sealed" style="margin-top: 4px">enviando {{ percent }}%</div>
      <div v-else-if="trouble" class="sealed" style="margin-top: 4px">{{ trouble }}</div>
    </div>

    <!-- Documents and anything else. -->
    <div v-else class="doc">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <path d="M14 2v6h6" />
      </svg>
      <div style="flex: 1; min-width: 0">
        <div class="name">{{ media.fileName || 'documento sem nome' }}</div>
        <div class="size">
          {{ bytes(media.fileLength) }}
          <template v-if="media.mimetype"> · {{ media.mimetype }}</template>
        </div>
        <div v-if="sending" class="sending-line">
          <div class="sending-bar" :style="{ width: `${percent}%` }" />
        </div>
        <div v-else-if="trouble" class="sealed">{{ trouble }}</div>
      </div>
      <span v-if="sending" class="sealed">{{ percent }}%</span>
      <a v-else-if="openedURL" class="ghost" :href="openedURL" :download="media.fileName || 'anexo'">
        baixar
      </a>
      <button v-else class="ghost" @click.stop="reveal" :disabled="Boolean(trouble)">
        {{ busy ? '…' : 'abrir' }}
      </button>
    </div>
  </div>
</template>

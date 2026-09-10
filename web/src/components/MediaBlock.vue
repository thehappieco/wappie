<script setup lang="ts">
import { t } from '../ui/i18n'
import { computed, ref } from 'vue'

import { fetchMedia, type MessageView } from '../state/archive'
import { playedMessage } from '../state/reading'
import { bytes, duration } from '../ui/format'
import AppIcon from './AppIcon.vue'

const props = defineProps<{ message: MessageView }>()

const media = computed(() => props.message.media!)
const busy = ref(false)

const isPicture = computed(() => ['image', 'sticker'].includes(media.value.type))
const isVideo = computed(() => ['video', 'ptv'].includes(media.value.type))
const isRoundVideo = computed(() => media.value.type === 'ptv')
const videoSize = computed(() => {
  const width = media.value.width || 320, height = media.value.height || 180
  const scale = Math.min(1, 320 / width, 340 / height)
  return { width: `${Math.round(width * scale)}px`, aspectRatio: `${width} / ${height}` }
})
const video = ref<HTMLVideoElement>()
const videoPlaying = ref(false)
const videoError = ref('')
const isSound = computed(() => ['audio', 'ptt'].includes(media.value.type))

async function toggleVideo() {
  const player = video.value
  if (!isRoundVideo.value || !player) return
  videoError.value = ''
  if (!player.paused) { player.pause(); return }
  try { await player.play() }
  catch { videoError.value = t('Não foi possível reproduzir este vídeo.') }
}

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
  if (props.message.pending === 'failed') return props.message.failure || t('não enviou')
  if (props.message.pending === 'unarchived') return t('Enviada, mas não entrou no histórico.')
  if (media.value.status === 'gone') {
    return t('A url expirou antes do arquivo chegar. Só o remetente pode reenviar.')
  }
  if (!full) return ''
  switch (full.state) {
    case 'pending':
      return t('O anexo ainda está sendo preparado. Tente novamente em instantes.')
    case 'expired':
      return t('A url expirou antes do arquivo chegar.')
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
    <div v-if="isPicture || isVideo" class="media" data-message-swipe :class="{ 'video-media': isVideo, 'round-video': isRoundVideo }" :style="isVideo && !isRoundVideo ? videoSize : undefined">
      <video
        v-if="openedURL && isVideo"
        ref="video"
        :src="openedURL"
        :poster="media.thumbURL"
        :controls="!isRoundVideo"
        playsinline
        :loop="media.isGIF"
        :muted="media.isGIF"
        @play="videoPlaying = true"
        @pause="videoPlaying = false"
        @ended="videoPlaying = false"
        @click.stop="isRoundVideo && toggleVideo()"
      />
      <img v-else-if="openedURL" :src="openedURL" :alt="media.fileName || t('anexo')" />
      <img v-else-if="media.thumbURL" :src="media.thumbURL" :alt="t('prévia')" @click.stop="reveal" />
      <div
        v-else
        class="media-placeholder"
        @click.stop="reveal"
      >
        <AppIcon :name="isVideo ? 'video' : 'image'" :size="42" />
      </div>

      <button v-if="isRoundVideo && openedURL && !sending && !trouble" class="round-video-toggle" :class="{ playing: videoPlaying }"
        type="button" :aria-label="videoPlaying ? t('Pausar vídeo') : t('Reproduzir vídeo')" @click.stop="toggleVideo">
        <svg width="26" height="26" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
          <path v-if="videoPlaying" d="M6 4h4v16H6zm8 0h4v16h-4z" />
          <path v-else d="M7 3v18l15-9z" />
        </svg>
      </button>
      <span v-if="isRoundVideo && openedURL && media.seconds" class="round-video-duration" aria-hidden="true">{{ duration(media.seconds) }}</span>

      <!-- Leaving this tab. Its own band rather than the veil, so the picture
           stays visible underneath: the whole reason to draw it now is that
           somebody can see what they are sending. -->
      <div v-if="sending" class="sending">
        <div class="sending-bar" :style="{ width: `${percent}%` }" />
        <span>{{ t('enviando {v0}%', { v0: percent }) }}</span>
      </div>
      <div v-else-if="trouble" class="veil">{{ trouble }}</div>
      <div v-else-if="!openedURL" class="veil" @click.stop="reveal">
        {{ busy ? t('Abrindo…') : isVideo ? t('▶ abrir vídeo') : t('abrir imagem') }}
        <template v-if="media.fileLength"> · {{ bytes(media.fileLength) }}</template>
      </div>
    </div>

    <!-- Voice notes and audio. -->
    <div v-else-if="isSound" class="audio-message" data-message-swipe>
      <div class="audio-swipe-body">
        <AppIcon :name="media.type === 'ptt' ? 'microphone' : 'audio'" :size="22" />
        <div class="waveform" v-if="bars.length" aria-hidden="true">
          <i v-for="(amp, i) in bars" :key="i" :style="{ height: `${Math.max(2, amp / 4)}px` }" />
        </div>
        <span v-else>{{ media.type === 'ptt' ? t('Mensagem de voz') : t('Áudio') }}</span>
        <small v-if="media.seconds">{{ duration(media.seconds) }}</small>
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
        {{ busy ? t('Abrindo…') : media.type === 'ptt' ? t('▶ ouvir') : t('▶ tocar') }}
        <template v-if="media.seconds"> · {{ duration(media.seconds) }}</template>
      </button>
      <div v-if="sending" class="sealed" style="margin-top: 4px">{{ t('enviando {v0}%', { v0: percent }) }}</div>
      <div v-else-if="trouble" class="sealed" style="margin-top: 4px">{{ trouble }}</div>
    </div>

    <!-- Documents and anything else. -->
    <div v-else class="doc">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <path d="M14 2v6h6" />
      </svg>
      <div style="flex: 1; min-width: 0">
        <div class="name">{{ media.fileName || t('documento sem nome') }}</div>
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
      <a v-else-if="openedURL" class="ghost" :href="openedURL" :download="media.fileName || t('anexo')"> {{ t('baixar') }} </a>
      <button v-else class="ghost" @click.stop="reveal" :disabled="Boolean(trouble)">
        {{ busy ? '…' : t('abrir') }}
      </button>
    </div>
    <p v-if="videoError" role="alert" class="sealed">{{ videoError }}</p>
  </div>
</template>

<style scoped>
.audio-swipe-body { display: flex; align-items: center; gap: 9px; min-height: 44px; min-width: 0; color: var(--text-dim); font-size: 12px; }
.audio-swipe-body > span, .audio-swipe-body .waveform { flex: 1; min-width: 0; }
.audio-swipe-body .waveform { margin: 0; overflow: hidden; }
.audio-swipe-body > small { margin-inline-start: auto; font-variant-numeric: tabular-nums; }
.media-placeholder { height: 140px; width: 220px; display: grid; place-items: center; color: var(--text-dim); }
.media-placeholder .app-icon { opacity: .15; }
.media.video-media { max-width: 100%; margin: 0 0 4px; }
.video-media video, .video-media img, .video-media .media-placeholder { position: absolute; inset: 0; width: 100%; height: 100%; max-height: none; object-fit: contain; }
.media.round-video { width: 220px; max-width: 100%; aspect-ratio: 1; margin: 0 0 4px; border-radius: 50%; overflow: hidden; }
.round-video video, .round-video img, .round-video .media-placeholder { position: absolute; inset: 0; width: 100%; height: 100%; object-fit: cover; max-height: none; }
.round-video-toggle { position: absolute; left: 50%; top: 50%; transform: translate(-50%, -50%); width: 50px; height: 50px; border: 0; border-radius: 50%; display: grid; place-items: center; background: #0008; color: white; cursor: pointer; transition: opacity 120ms ease; }
.round-video-toggle.playing { opacity: 0; }
.round-video:hover .round-video-toggle.playing, .round-video-toggle:focus-visible { opacity: 1; }
.round-video-toggle:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
.round-video-duration { position: absolute; bottom: 14px; left: 50%; transform: translateX(-50%); padding: 2px 7px; border-radius: 10px; color: white; background: #0008; font-size: 11px; pointer-events: none; }
@media (prefers-reduced-motion: reduce) { .round-video-toggle { transition: none; } }
</style>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { t } from '../ui/i18n'

const props = defineProps<{ url: string; kind: 'audio' | 'video'; circular?: boolean; seconds?: number; poster?: string; silent?: boolean }>()
const media = ref<HTMLMediaElement>()
const playing = ref(false), position = ref(0), measuredDuration = ref(0), error = ref('')
let generation = 0
const duration = computed(() => measuredDuration.value || (Number.isFinite(props.seconds) && props.seconds! > 0 ? props.seconds! : 0))
const posterURL = computed(() => props.poster ? 'data:image/jpeg;base64,' + props.poster : undefined)
function clock(seconds: number) {
  const value = Math.max(0, Math.floor(Number.isFinite(seconds) ? seconds : 0))
  return `${Math.floor(value / 60)}:${String(value % 60).padStart(2, '0')}`
}
function update() {
  const element = media.value
  if (!element) return
  position.value = Number.isFinite(element.currentTime) ? element.currentTime : 0
  if (Number.isFinite(element.duration) && element.duration > 0) measuredDuration.value = element.duration
  playing.value = !element.paused && !element.ended
}
async function toggle() {
  const element = media.value
  if (!element) return
  if (!element.paused) { element.pause(); return }
  const current = generation
  try { await element.play() }
  catch { if (current === generation) error.value = t('Não foi possível reproduzir a prévia neste navegador.') }
}
function seek(event: Event) {
  const element = media.value, value = Number((event.target as HTMLInputElement).value)
  if (!element || !Number.isFinite(value) || duration.value <= 0) return
  try { element.currentTime = Math.min(duration.value, Math.max(0, value)); update() }
  catch { /* A stream with no seekable range can still be played from the start. */ }
}
function stop() {
  generation++
  const element = media.value
  if (element) {
    element.pause()
    element.removeAttribute('src')
    element.load()
  }
  playing.value = false; position.value = 0
}
function failed() { error.value = t('Não foi possível reproduzir a prévia neste navegador.') }
watch(() => props.url, () => { generation++; playing.value = false; position.value = 0; measuredDuration.value = 0; error.value = '' })
onBeforeUnmount(stop)
// The composer owns this URL until Send hands it to the outbox. Detaching a
// player must release its decoder, but must never revoke the outbox's preview.
defineExpose({ stop })
</script>

<template>
  <div class="attachment-preview" :class="{ circular }">
    <video v-if="kind === 'video'" ref="media" :src="url" :poster="posterURL" :controls="!circular" :muted="silent"
      preload="metadata" playsinline :aria-label="t('Prévia do vídeo')" @loadedmetadata="update" @durationchange="update" @timeupdate="update"
      @play="update" @pause="update" @ended="update" @error="failed" />
    <audio v-else ref="media" :src="url" controls preload="metadata" :aria-label="t('Prévia do áudio')" @error="failed" />
    <div v-if="circular && kind === 'video'" class="preview-controls">
      <button type="button" :aria-label="playing ? t('Pausar vídeo') : t('Reproduzir vídeo')" @click="toggle">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path v-if="playing" d="M6 4h4v16H6zm8 0h4v16h-4z" /><path v-else d="m7 3 15 9-15 9z" /></svg>
      </button>
      <span class="preview-time">{{ clock(position) }}</span>
      <input type="range" min="0" :max="duration || 1" step="0.1" :value="position" :disabled="duration <= 0"
        :aria-label="t('Posição na prévia')" :aria-valuetext="clock(position) + ' / ' + clock(duration)" @input="seek" />
      <span class="preview-time">{{ clock(duration) }}</span>
    </div>
    <p v-if="error" class="preview-error" role="status">{{ error }}</p>
  </div>
</template>

<style scoped>
.attachment-preview { min-width: 0; width: 100%; }
.attachment-preview video { display: block; width: 100%; max-height: min(32dvh, 240px); min-height: 100px; border-radius: 12px; background: #101719; object-fit: contain; }
.attachment-preview audio { display: block; width: 100%; min-width: 0; height: 48px; }
.attachment-preview.circular video { width: min(100%, 28dvh, 200px); height: auto; min-height: 0; aspect-ratio: 1; margin-inline: auto; border-radius: 50%; object-fit: cover; }
.preview-controls { display: flex; gap: 8px; align-items: center; margin-top: 8px; min-width: 0; }
.preview-controls button { display: grid; place-items: center; flex: 0 0 40px; width: 40px; height: 40px; border-radius: 50%; color: var(--accent); background: var(--bg-active); }
.preview-controls input { width: 100%; min-width: 24px; height: 32px; padding: 0; accent-color: var(--accent); }
.preview-controls button:focus-visible, .preview-controls input:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.preview-time { font-size: 11px; color: var(--text-dim); font-variant-numeric: tabular-nums; flex: 0 0 auto; }
.preview-error { color: var(--text-dim); font-size: 12px; margin: 8px 0 0; line-height: 1.4; }
</style>

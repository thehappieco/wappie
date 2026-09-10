<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { t } from '../ui/i18n'
import { connection, state } from '../state/archive'
import { openVideoCamera, videoRecordingAvailable, type VideoCamera, type VideoRecording, type RecordedVideo } from '../media/videoCapture'
import type { Choice } from '../media/plan'
import AppIcon from './AppIcon.vue'

const emit = defineEmits<{ close: []; recorded: [file: File, choice: Choice, seconds: number]; native: [file: File] }>()
const dialog = ref<HTMLDialogElement>(), preview = ref<HTMLVideoElement>(), nativeInput = ref<HTMLInputElement>()
const shape = ref<'square' | 'original'>('square'), quality = ref<'standard' | 'hd'>('standard'), facing = ref<'user' | 'environment'>('user')
const phase = ref<'idle' | 'opening' | 'ready' | 'recording' | 'finishing' | 'review'>('idle')
const previewPlaying = ref(false)
const reviewCurrentTime = ref(0), reviewDuration = ref(0)
let reviewFrameURL = ''
let nativePicking = false
const sourceContext = { device: state.deviceID, chat: state.openChatKey, workspace: state.tenantID, connection: connection() }
function sameContext() { return !disposed && state.deviceID === sourceContext.device && state.openChatKey === sourceContext.chat && state.tenantID === sourceContext.workspace && connection() === sourceContext.connection }
const error = ref(''), elapsed = ref(0), width = ref(0), height = ref(0), previewURL = ref('')
const available = videoRecordingAvailable()
let camera: VideoCamera | null = null, recording: VideoRecording | null = null, result: RecordedVideo | null = null
let controller: AbortController | null = null, generation = 0, disposed = false, ticker: ReturnType<typeof setInterval> | undefined
const locked = computed(() => phase.value === 'recording' || phase.value === 'finishing' || phase.value === 'opening')
const actualHD = computed(() => quality.value === 'hd' && Math.min(width.value, height.value) >= 720)
const choice = computed<Choice>(() => shape.value === 'square' ? actualHD.value ? 'ptv_hd' : 'ptv' : actualHD.value ? 'video_hd' : 'video')
const time = computed(() => `0:${String(Math.min(60, elapsed.value)).padStart(2, '0')}`)
function reviewTime(seconds: number): string {
  const whole = Math.max(0, Math.floor(Number.isFinite(seconds) ? seconds : 0))
  return `${Math.floor(whole / 60)}:${String(whole % 60).padStart(2, '0')}`
}
const reviewPosition = computed(() => t('{current} de {duration}', { current: reviewTime(reviewCurrentTime.value), duration: reviewTime(reviewDuration.value) }))
function cleanup() {
  generation++; nativePicking = false; controller?.abort(); controller = null; clearInterval(ticker)
  recording?.cancel(); recording = null; camera?.dispose(); camera = null
  if (preview.value) { preview.value.pause(); preview.value.srcObject = null }
  if (previewURL.value) URL.revokeObjectURL(previewURL.value)
  previewURL.value = ''; result = null; reviewFrameURL = ''; previewPlaying.value = false
  reviewCurrentTime.value = 0; reviewDuration.value = 0
}
function close() { cleanup(); emit('close') }
async function openCamera() {
  cleanup(); const current = generation
  error.value = ''; phase.value = 'opening'; elapsed.value = 0
  controller = new AbortController()
  try {
    const opened = await openVideoCamera({ quality: quality.value, facingMode: facing.value, shape: shape.value, signal: controller.signal })
    if (!sameContext() || current !== generation) { opened.dispose(); return }
    camera = opened; width.value = opened.width; height.value = opened.height; phase.value = 'ready'
    await nextTick()
    if (preview.value && current === generation) { preview.value.srcObject = opened.stream; await preview.value.play() }
  } catch (err) {
    if (!sameContext() || current !== generation) return
    camera?.dispose(); camera = null; phase.value = 'idle'
    error.value = err instanceof Error && err.name === 'NotAllowedError' ? t('Permita o acesso à câmera e ao microfone para gravar.') : err instanceof Error ? err.message : t('Não foi possível abrir a câmera.')
  }
}
function syncReview() {
  const video = preview.value
  if (phase.value !== 'review' || !previewURL.value || !video) return
  if (!sameContext()) { close(); return }
  const duration = Number.isFinite(video.duration) && video.duration > 0 ? video.duration : result?.seconds ?? 0
  reviewDuration.value = Number.isFinite(duration) && duration > 0 ? duration : 0
  reviewCurrentTime.value = Math.min(reviewDuration.value, Math.max(0, Number.isFinite(video.currentTime) ? video.currentTime : 0))
  previewPlaying.value = !video.paused && !video.ended
}
function seekReview(event: Event) {
  const video = preview.value, requested = Number((event.target as HTMLInputElement).value)
  if (!video || phase.value !== 'review' || !previewURL.value || !Number.isFinite(requested)) return
  if (!sameContext()) { close(); return }
  syncReview()
  if (reviewDuration.value <= 0) return
  const position = Math.max(0, Math.min(reviewDuration.value, requested))
  try {
    video.currentTime = position
    reviewCurrentTime.value = position
    // A user seek must win if loadeddata arrives afterward.
    reviewFrameURL = previewURL.value
  } catch { /* Metadata may not yet permit seeking; the next media event restores the position. */ }
}
function showReviewFrame() {
  const video = preview.value
  if (phase.value !== 'review' || !previewURL.value || !video || reviewFrameURL === previewURL.value) return
  if (!sameContext()) { close(); return }
  syncReview()
  reviewFrameURL = previewURL.value
  // A small seek asks Safari/Chrome to paint a decoded frame while paused.
  // It does not start playback or consume the user's recorded message.
  if (Number.isFinite(video.duration) && video.duration > 0) {
    try { video.currentTime = Math.min(.05, video.duration / 2); reviewCurrentTime.value = video.currentTime }
    catch { /* A later frame can still be decoded when playback is requested. */ }
  }
}
async function toggleReview() {
  const video = preview.value
  if (!video || phase.value !== 'review' || !previewURL.value) return
  if (!sameContext()) { close(); return }
  if (!video.paused) { video.pause(); return }
  const current = generation
  try {
    if (video.ended || reviewDuration.value > 0 && video.currentTime >= reviewDuration.value) video.currentTime = 0
    await video.play()
    if (!sameContext() || current !== generation || preview.value !== video) video.pause()
    else syncReview()
  } catch {
    if (sameContext() && current === generation && preview.value === video) error.value = t('Não foi possível reproduzir este vídeo.')
  }
}
function start() {
  if (!camera || phase.value !== 'ready') return
  const current = generation
  try {
    recording = camera.start(); phase.value = 'recording'
    const began = performance.now(); ticker = setInterval(() => { elapsed.value = Math.floor((performance.now() - began) / 1000) }, 200)
    void recording.done.then(async taken => {
      if (!sameContext() || current !== generation) return
      clearInterval(ticker); recording = null
      if (preview.value) { preview.value.pause(); preview.value.srcObject = null }
      camera?.dispose(); camera = null
      if (!taken) { phase.value = 'idle'; return }
      previewPlaying.value = false
      result = taken; width.value = taken.width; height.value = taken.height; elapsed.value = taken.seconds
      reviewCurrentTime.value = 0; reviewDuration.value = Number.isFinite(taken.seconds) ? Math.max(0, taken.seconds) : 0
      previewURL.value = URL.createObjectURL(taken.file); phase.value = 'review'
      await nextTick(); preview.value?.load()
    }).catch(err => {
      if (!sameContext() || current !== generation) return
      cleanup(); phase.value = 'idle'; error.value = err instanceof Error ? err.message : t('Não foi possível gravar o vídeo.')
    })
  } catch (err) { cleanup(); phase.value = 'idle'; error.value = err instanceof Error ? err.message : String(err) }
}
function stop() { if (phase.value === 'recording') { phase.value = 'finishing'; clearInterval(ticker); void recording?.stop().catch(() => {}) } }
function useVideo() {
  if (!result || phase.value !== 'review' || !sameContext()) return
  const taken = result, selected = choice.value
  emit('recorded', taken.file, selected, taken.seconds); close()
}
function changeMode() { if (phase.value === 'ready' || phase.value === 'review') void openCamera() }
function flip() { facing.value = facing.value === 'user' ? 'environment' : 'user'; void openCamera() }
function openNative() {
  if (locked.value || !sameContext()) return
  cleanup(); phase.value = 'idle'; nativePicking = true
  nativeInput.value?.click()
}
function nativeCancelled() { nativePicking = false }
function nativePicked(event: Event) {
  nativePicking = false
  const input = event.target as HTMLInputElement, file = input.files?.[0]
  input.value = ''
  if (!sameContext()) return
  if (file) { emit('native', file); close() }
}
function visibility() {
  // Opening a native mobile camera can hide the document while the file
  // picker still owns its return callback. No live stream is held here.
  if (document.hidden && !nativePicking) close()
}
watch(() => [state.deviceID, state.openChatKey, state.tenantID, state.connected], () => {
  if (!sameContext()) close()
}, { flush: 'sync' })
onMounted(() => { dialog.value?.showModal(); document.addEventListener('visibilitychange', visibility) })
onBeforeUnmount(() => { disposed = true; cleanup(); document.removeEventListener('visibilitychange', visibility); dialog.value?.close() })
</script>

<template>
  <dialog ref="dialog" class="video-dialog" aria-labelledby="video-recorder-title" @cancel.prevent="close" @close="!disposed && emit('close')">
    <section class="video-card">
      <header><div><h2 id="video-recorder-title">{{ t('Gravar vídeo') }}</h2><p>{{ t('Prévia antes de enviar. Até 60 segundos por gravação.') }}</p></div><button class="icon-btn" type="button" :aria-label="t('Fechar')" @click="close"><AppIcon name="close" /></button></header>
      <div class="video-body">
        <div class="video-settings">
          <label>{{ t('Formato') }}<select v-model="shape" :disabled="locked" @change="changeMode"><option value="square">{{ t('Circular (TVP)') }}</option><option value="original">{{ t('Vídeo') }}</option></select></label>
          <label>{{ t('Qualidade') }}<select v-model="quality" :disabled="locked" @change="changeMode"><option value="standard">{{ t('Normal · até 480p') }}</option><option value="hd">{{ t('HD · até 720p') }}</option></select></label>
        </div>
        <div class="video-stage" :class="{ circular: shape === 'square' }">
          <video v-if="phase !== 'idle' || previewURL" ref="preview" :src="previewURL || undefined" :muted="!previewURL" :controls="phase === 'review' && shape !== 'square'" playsinline @loadedmetadata="syncReview" @durationchange="syncReview" @loadeddata="showReviewFrame" @timeupdate="syncReview" @seeking="syncReview" @seeked="syncReview" @play="syncReview" @pause="syncReview" @ended="syncReview" :class="{ mirror: facing === 'user' && !previewURL }" :aria-label="t('Prévia do vídeo')" />
          <AppIcon v-else name="video" :size="48" />
          <button v-if="phase === 'review' && shape === 'square'" class="video-review-toggle" :class="{ playing: previewPlaying }" type="button" :aria-label="previewPlaying ? t('Pausar vídeo') : t('Reproduzir vídeo')" :title="previewPlaying ? t('Pausar vídeo') : t('Reproduzir vídeo')" @click="toggleReview">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path v-if="previewPlaying" d="M6 4h4v16H6zm8 0h4v16h-4z" /><path v-else d="m7 3 15 9-15 9z" /></svg>
          </button>
          <span v-if="phase === 'recording' || phase === 'finishing'" class="video-clock" role="timer"><i />{{ time }}</span>
          <span v-if="phase === 'opening'" class="video-opening" role="status">{{ t('Abrindo câmera…') }}</span>
        </div>
        <div v-if="phase === 'review' && shape === 'square'" class="video-review-timeline">
          <span aria-hidden="true">{{ reviewTime(reviewCurrentTime) }}</span>
          <input type="range" min="0" :max="reviewDuration || 1" step="0.1" :value="reviewCurrentTime" :disabled="reviewDuration <= 0" :aria-label="t('Posição no vídeo')" :aria-valuetext="reviewPosition" @input="seekReview" />
          <span aria-hidden="true">{{ reviewTime(reviewDuration) }}</span>
        </div>
        <p v-if="width && phase !== 'idle'" class="video-resolution">{{ width }}×{{ height }}<template v-if="phase === 'review'"> · {{ elapsed }}s</template><template v-if="actualHD"> · HD</template></p>
        <p v-if="quality === 'hd' && width && !actualHD" class="video-hint">{{ t('Esta câmera não oferece HD nesta configuração. Será usada a resolução disponível, sem ampliação.') }}</p>
        <p class="video-hint">{{ shape === 'square' ? t('O vídeo circular recorta o centro da imagem e não aceita legenda.') : t('O enquadramento da câmera será preservado.') }}</p>
        <p v-if="error" class="alert" role="alert">{{ error }}</p>
        <p v-if="!available" class="video-hint">{{ t('A gravação integrada não está disponível neste navegador. Use a câmera do aparelho e escolha como enviar depois.') }}</p>
      </div>
      <footer>
        <input ref="nativeInput" type="file" accept="video/*" capture="user" class="native-camera" tabindex="-1" @change="nativePicked" @cancel="nativeCancelled" />
        <template v-if="phase === 'idle'"><button type="button" @click="openNative">{{ t('Câmera do aparelho') }}</button><button v-if="available" class="primary" type="button" @click="openCamera">{{ t('Abrir câmera') }}</button></template>
        <template v-else-if="phase === 'ready'"><button type="button" @click="flip">{{ t('Alternar câmera') }}</button><button class="primary" type="button" @click="start"><span class="record-symbol" />{{ t('Iniciar gravação') }}</button></template>
        <button v-else-if="phase === 'recording'" class="primary" type="button" @click="stop"><AppIcon name="stop" :size="18" />{{ t('Parar gravação') }}</button>
        <template v-else-if="phase === 'review'"><button type="button" @click="openCamera">{{ t('Gravar novamente') }}</button><button class="primary" type="button" @click="useVideo">{{ t('Usar vídeo') }}</button></template>
        <button v-else type="button" @click="close">{{ t('Cancelar') }}</button>
      </footer>
    </section>
  </dialog>
</template>

<style scoped>
.video-review-timeline{display:flex;align-items:center;gap:10px;width:min(100%,360px);margin:8px auto 0;color:var(--text-dim);font-size:12px;font-variant-numeric:tabular-nums}.video-review-timeline input{flex:1;min-width:0;height:36px;margin:0;accent-color:var(--accent);cursor:pointer}.video-review-timeline input:focus-visible{outline:2px solid var(--accent);outline-offset:3px;border-radius:4px}.video-review-timeline span{flex:none}
.video-dialog{border:0;padding:0;background:transparent;color:var(--text);max-width:min(520px,calc(100vw - 24px));width:100%;max-height:calc(100dvh - 24px);overflow:visible}.video-dialog::backdrop{background:rgb(0 0 0/.65);backdrop-filter:blur(5px)}.video-card{background:var(--bg-panel);border:1px solid var(--line);border-radius:22px;box-shadow:0 24px 100px #0006;display:flex;flex-direction:column;max-height:calc(100dvh - 24px);overflow:hidden}.video-card header{display:flex;align-items:flex-start;gap:14px;padding:20px 20px 12px}.video-card header>div{flex:1}.video-card h2{margin:0 0 6px;font-size:19px}.video-card p{margin:0;color:var(--text-dim);font-size:13px;line-height:1.45}.video-body{padding:0 20px 16px;overflow:auto;overscroll-behavior:contain}.video-settings{display:flex;gap:10px;margin-bottom:16px}.video-settings label{flex:1;min-width:0;font-size:12px;color:var(--text-dim)}.video-settings select{display:block;width:100%;margin-top:5px;padding:10px 8px;border:1px solid var(--line);border-radius:10px;background:var(--bg-input);color:var(--text)}.video-stage{position:relative;display:flex;align-items:center;justify-content:center;background:#101719;color:#889399;aspect-ratio:4/3;max-height:42dvh;overflow:hidden;border-radius:14px;margin:auto}.video-stage.circular{aspect-ratio:1;width:min(100%,310px);border-radius:50%}.video-stage video{width:100%;height:100%;object-fit:contain}.video-stage.circular video{object-fit:cover}.mirror{transform:scaleX(-1)}.video-review-toggle{position:absolute;inset:50% auto auto 50%;transform:translate(-50%,-50%);display:grid;place-items:center;width:54px;height:54px;border-radius:50%;background:#0009;color:#fff;border:1px solid #ffffff60;box-shadow:0 3px 14px #0005}.video-review-toggle.playing{inset:auto auto 18px 50%;transform:translateX(-50%);width:44px;height:44px}.video-review-toggle:focus-visible{outline:3px solid #fff;outline-offset:3px}.video-clock{position:absolute;left:50%;bottom:20px;transform:translateX(-50%);padding:5px 12px;border-radius:20px;background:#000a;color:white;font-variant-numeric:tabular-nums}.video-clock i,.record-symbol{display:inline-block;width:9px;height:9px;margin-right:7px;border-radius:50%;background:#fa4b62}.video-opening{position:absolute;background:#000a;padding:8px;border-radius:8px;color:#fff}.video-card .video-resolution{text-align:center;margin-top:10px;font-variant-numeric:tabular-nums}.video-card .video-hint{margin-top:10px}.video-card footer{padding:14px 20px;border-top:1px solid var(--line);display:flex;justify-content:flex-end;gap:10px;flex-wrap:wrap}.video-card footer button{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:42px;border-radius:10px}.native-camera{display:none}@media(max-width:480px){.video-card header{padding:16px 16px 12px}.video-body{padding:0 16px 14px}.video-card footer{padding:12px 16px}.video-card footer button{flex:1}}
</style>

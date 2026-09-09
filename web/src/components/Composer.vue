<script setup lang="ts">
import { t } from '../ui/i18n'
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'

import { canSend, noMarks, sendMedia, sendText, state, type Marks } from '../state/archive'
import { startTyping, stopTyping } from '../state/presence'
import { edit, editableFor } from '../state/actions'
import { MAX_BYTES, refuse, type Choice } from '../media/plan'
import { discard, prepare, type Prepared } from '../media/prepare'
import { available as canRecord, begin, type Recording } from '../media/record'
import { bytes } from '../ui/format'
import { enterSends } from '../ui/composerKeys'
import AttachSheet from './AttachSheet.vue'
import { timerLabel } from '../state/ephemeral'
import SendMarks from './SendMarks.vue'
import AppIcon from './AppIcon.vue'

// Writing into the archive, rather than only reading it.
//
// The one thing worth stating: a message sent here is archived by the same
// pipeline that archives an incoming one — same sealing, same projection, same
// event — so the copy that comes back is not a special case. This component
// shows the message before that happens and gets out of the way when it does.
//
// An attachment is the same shape with one extra leg. The bytes go over HTTP
// and the message that points at them over the websocket, and between the two
// the file has to be measured: a picture resized, a video's duration and first
// frame read, a recording's waveform sketched. All of that happens here,
// because the machine that already decoded the file is the one somebody chose
// it on — and because the server is not supposed to be able to look.

const props = defineProps<{ replyTo?: string; editing?: string }>()
const emit = defineEmits<{ (e: 'cancel'): void }>()

const draft = ref('')
const box = ref<HTMLTextAreaElement>()
const chooser = ref<HTMLInputElement>()

/** A file somebody picked, waiting to be told how it should be sent. */
const picked = ref<File | null>(null)
/** The same file, measured and ready to upload. */
const attached = ref<Prepared | null>(null)
const measuring = ref(false)
const attachError = ref('')

const marks = ref<Marks>(noMarks())

/** The conversation's own disappearing timer, which the message follows by default. */
const chatTimer = computed(
  () => state.chats.find((c) => c.key === state.openChatKey)?.ephemeral ?? 0,
)
const showMarks = ref(false)

/** The microphone, while it is open. */
const recording = ref<Recording | null>(null)
const recordedFor = ref(0)
let ticker: ReturnType<typeof setInterval> | undefined
/** Set while the permission prompt is up, which is an await nobody can see. */
const opening = ref(false)
/** Set once this composer is gone, so a late microphone is not orphaned. */
let gone = false
const micAvailable = canRecord()

const quoted = computed(() =>
  props.replyTo ? state.timeline.find((m) => m.waID === props.replyTo) : undefined,
)

/** The message being corrected, when the composer is in edit mode. */
const target = computed(() =>
  props.editing ? state.timeline.find((m) => m.uid === props.editing) : undefined,
)

/** Minutes left before WhatsApp stops accepting the correction. */
const minutesLeft = computed(() => (target.value ? Math.ceil(editableFor(target.value) / 60_000) : 0))

const allowed = computed(() => canSend())

/** Whether a caption is even a thing for what is attached. */
const captionAllowed = computed(() => attached.value?.plan.captionAllowed ?? true)
const canViewOnce = computed(() => attached.value?.plan.viewOnceAllowed ?? false)

/** Set when the flags say something, so the disclosure can say so while closed. */
const marksSummary = computed(() => {
  const said: string[] = []
  if (marks.value.forwarded) said.push(marks.value.score >= 5 ? t('muitas vezes') : t('encaminhada'))
  if (marks.value.viewOnce && canViewOnce.value) said.push(t('ver uma vez'))
  // The timer is a mark like the others and belongs in the closed summary: it
  // is the one that changes what happens to the message on somebody else's
  // phone, and leaving it hidden is how a message goes out with a prazo
  // nobody meant to set.
  if (marks.value.expiration !== undefined) {
    said.push(
      marks.value.expiration === 0 ? t('sem prazo') : t('prazo {duration}', { duration: timerLabel(marks.value.expiration) }),
    )
  }
  return said.join(' · ')
})

/**
 * Why the composer is unavailable, when it is.
 *
 * Three different reasons that a single "cannot send" would blur into one, and
 * only one of them is something the person can act on here.
 */
const reason = computed(() => {
  if (state.unreadable) return t('Sua conta não tem a chave deste aparelho.')
  if (!state.connected) return t('Sem conexão com o servidor.')
  const device = state.devices.find((d) => d.id === state.deviceID)
  if (!device?.running) return t('Este aparelho não está conectado ao WhatsApp agora.')
  return ''
})

const sendable = computed(() => {
  if (attached.value) return true
  if (target.value) return Boolean(draft.value.trim()) && minutesLeft.value > 0
  return Boolean(draft.value.trim())
})

async function submit() {
  // The message is on its way; nobody is typing any more.
  stopTyping()
  if (!allowed.value || !sendable.value) return
  attachError.value = ''

  const carrying = attached.value
  if (carrying) {
    const refusal = refuse(
      carrying.plan,
      { name: carrying.fileName, size: carrying.blob.size },
      draft.value,
    )
    if (refusal) {
      attachError.value = refusal
      return
    }
    const caption = draft.value
    const reply = quoted.value
    const flags = marks.value
    // Cleared before the await, not after: the upload can take a minute, and
    // leaving the composer holding the file that whole time invites sending it
    // twice. The archive line is already on screen by then.
    attached.value = null
    draft.value = ''
    marks.value = noMarks()
    emit('cancel')
    // No discard here. The preview URL now belongs to the archive's keeper,
    // which holds it past the moment the archived row replaces this line and
    // revokes it when it evicts it.
    await sendMedia(carrying, caption, reply, flags)
    return
  }

  const body = draft.value
  if (!body.trim()) return
  const correcting = target.value
  const flags = marks.value
  draft.value = ''
  marks.value = noMarks()
  emit('cancel')
  // An edit replaces a message rather than adding one, so it never goes
  // through the outbox: the archive answers with a new version of the row that
  // is already on screen, and project() folds it in.
  if (correcting) await edit(correcting, body)
  else await sendText(body, quoted.value, flags)
}

// --- attachments -----------------------------------------------------------

function browse() {
  attachError.value = ''
  chooser.value?.click()
}

function onPicked(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  // Reset immediately so picking the same file twice in a row still fires.
  input.value = ''
  if (file) take(file)
}

/**
 * take accepts a file from any of the three ways one arrives.
 *
 * The two size refusals are made here rather than left to the server, because
 * the server makes them at the *end*: it streams the whole thing to WhatsApp
 * and only then measures it. A file over the ceiling would upload completely,
 * fill a progress bar, and be refused at one hundred percent.
 */
function take(file: File) {
  // Attaching a file means this is no longer an edit. Reachable by pasting,
  // since the buttons are hidden while one is in progress — and without this
  // the composer shows an editing chip above an attachment it is about to send
  // as a new message.
  if (props.editing) emit('cancel')
  if (file.size === 0) {
    attachError.value = t('{v0} está vazio.', { v0: file.name })
    return
  }
  if (file.size > MAX_BYTES) {
    attachError.value = t('{v0} tem {v1}; o limite é {v2}.', { v0: file.name, v1: bytes(file.size), v2: bytes(MAX_BYTES) })
    return
  }
  attachError.value = ''
  clearAttachment()
  picked.value = file
}

async function choose(choice: Choice) {
  const file = picked.value
  if (!file) return
  picked.value = null
  measuring.value = true
  // Reading a video's duration and first frame takes real time, and the reader
  // can open another conversation while it happens. The watcher that drops an
  // unsent attachment on that switch cannot help here — this assignment comes
  // after it — so the conversation is remembered and checked.
  const forChat = state.openChatKey
  try {
    const ready = await prepare(file, choice)
    if (forChat !== state.openChatKey) {
      discard(ready)
      return
    }
    attached.value = ready
    if (!ready.plan.captionAllowed) draft.value = ''
    if (!ready.plan.viewOnceAllowed) marks.value = { ...marks.value, viewOnce: false }
    await nextTick(() => box.value?.focus())
  } catch (err) {
    attachError.value = err instanceof Error ? err.message : String(err)
  } finally {
    measuring.value = false
  }
}

/** clearAttachment drops what is held and releases the preview it made. */
function clearAttachment() {
  picked.value = null
  if (attached.value) discard(attached.value)
  attached.value = null
}

// A screenshot is pasted far more often than it is saved and picked, and the
// clipboard is where it already is.
function onPaste(event: ClipboardEvent) {
  const file = event.clipboardData?.files?.[0]
  if (!file) return
  event.preventDefault()
  take(file)
}

// --- the microphone --------------------------------------------------------

async function startRecording() {
  // WhatsApp draws a different bubble for a voice note being recorded, and
  // it is worth the distinction: 'typing' on a message that arrives as audio
  // reads as the client having lied.
  startTyping('audio')
  // The permission prompt sits inside this await, and the button is still on
  // screen behind it. Two clicks would open two microphones, of which only the
  // second could ever be stopped.
  if (opening.value || recording.value) return
  opening.value = true
  attachError.value = ''
  clearAttachment()
  try {
    const open = await begin()
    if (gone) {
      // The conversation was closed, or the tab moved on, while the person was
      // deciding whether to allow the microphone. Nothing would hold this.
      open.cancel()
      return
    }
    recording.value = open
  } catch (err) {
    // Almost always a refused permission, which is a decision somebody made
    // rather than a failure. Saying nothing looks like a broken button.
    attachError.value =
      err instanceof Error && err.name === 'NotAllowedError'
        ? t('O navegador não liberou o microfone para esta página.')
        : err instanceof Error
          ? err.message
          : String(err)
    return
  } finally {
    opening.value = false
  }
  recordedFor.value = 0
  clearInterval(ticker)
  ticker = setInterval(() => (recordedFor.value += 1), 1000)
}

async function stopRecording() {
  stopTyping()
  const open = recording.value
  if (!open) return
  clearInterval(ticker)
  recording.value = null
  const taken = await open.stop()
  if (!taken) return

  if (taken.asVoiceNote) {
    try {
      // The recording's own length is passed in: the microphone was open for
      // exactly that long, and it is the answer when decoding the result to
      // time it does not work.
      attached.value = await prepare(taken.file, 'voice', taken.seconds)
    } catch (err) {
      // Said out loud. A recording that fails to measure silently is a minute
      // of somebody's speech that disappeared with no explanation.
      attachError.value = err instanceof Error ? err.message : String(err)
    }
    return
  }
  // The browser recorded something that is not Opus in an Ogg container —
  // Safari records AAC and cannot be asked otherwise. Perfectly good audio, and
  // not a voice note: sending it as one produces a bubble some phones refuse to
  // play. So it is offered as what it is.
  attachError.value =
    t('Este navegador grava em um formato que o WhatsApp não usa para mensagem de voz. ') +
    t('Dá para mandar como áudio.')
  picked.value = taken.file
}

function cancelRecording() {
  stopTyping()
  clearInterval(ticker)
  recording.value?.cancel()
  recording.value = null
}

onBeforeUnmount(() => {
  gone = true
  cancelRecording()
  clearAttachment()
})

// Dropping a file happens over the conversation, not over the composer: the
// composer is a strip at the bottom and nobody aims at it. So the drop is
// handled up there and handed down here.
defineExpose({ take })

// Desktop keeps Enter to send; touch keyboards use Enter for a new line and
// the visible send button. An IME's confirmation key must only confirm text.
function onKey(event: KeyboardEvent) {
  const touchKeyboard = window.matchMedia?.('(hover: none) and (pointer: coarse)').matches ?? false
  if (enterSends(event, touchKeyboard)) {
    event.preventDefault()
    void submit()
  }
}

// Grows with the text up to a point, then scrolls. A textarea that stays one
// line hides what somebody is about to send.
/** clock is mm:ss, which is how long a recording is read. */
function clock(seconds: number): string {
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}:${String(s).padStart(2, '0')}`
}

function resize() {
  const el = box.value
  if (!el) return
  el.style.height = 'auto'
  el.style.height = `${Math.min(el.scrollHeight, 160)}px`
}
watch(draft, (text) => {
  void nextTick(resize)
  // Typing, and having stopped. Driven by the draft rather than by keystrokes
  // so that pasting, autocorrect and a deletion all count the same way — and so
  // that clearing the box takes the bubble back rather than leaving it up until
  // it expires on the other side.
  if (text) startTyping()
  else stopTyping()
})
watch(
  () => props.replyTo,
  (id) => {
    if (id) box.value?.focus()
  },
)

// Entering an edit loads the text being corrected; leaving one clears it, so a
// half-finished correction is never sent as a brand new message.
watch(
  () => props.editing,
  (uid) => {
    draft.value = uid ? (target.value?.body ?? '') : ''
    if (uid) clearAttachment()
    void nextTick(() => {
      resize()
      box.value?.focus()
    })
  },
)

// Leaving the conversation drops an attachment that was never sent. It belongs
// to the chat it was chosen for, and carrying it into the next one is how
// somebody sends a photograph to the wrong person. A recording in progress goes
// with it: the microphone should not stay open for a conversation nobody is
// looking at.
watch(() => state.openChatKey, () => {
  // Leaving a conversation takes the bubble down with us. Without this the
  // other side sees us typing in a chat we have closed, until it expires.
  stopTyping()
  cancelRecording()
  clearAttachment()
})

onBeforeUnmount(stopTyping)
</script>

<template>
  <div class="composer">
    <div v-if="quoted" class="quoting">
      <div class="grow">
        <div class="quoting-who">{{ quoted.senderName }}</div>
        <div class="quoting-body">{{ quoted.body || '—' }}</div>
      </div>
      <button class="icon-btn" type="button" :title="t('Cancelar resposta')" :aria-label="t('Cancelar resposta')" @click="emit('cancel')"><AppIcon name="close" :size="20" /></button>
    </div>

    <div v-if="target" class="quoting editing-chip">
      <div class="grow">
        <div class="quoting-who">{{ t('Editando uma mensagem enviada') }}</div>
        <div class="quoting-body">
          <template v-if="minutesLeft > 0">{{ t('{v0} min restantes', { v0: minutesLeft }) }}</template>
          <template v-else>{{ t('a janela de vinte minutos já passou') }}</template>
        </div>
      </div>
      <button class="icon-btn" type="button" :title="t('Cancelar edição')" :aria-label="t('Cancelar edição')" @click="emit('cancel')"><AppIcon name="close" :size="20" /></button>
    </div>

    <AttachSheet v-if="picked" :file="picked" @choose="choose" @cancel="clearAttachment" />

    <div v-if="measuring" class="composer-off">{{ t('Lendo o arquivo…') }}</div>

    <!-- What is about to go, as it will go. The preview is the file itself,
         already resized if it is going to be resized, so what is on screen is
         what the recipient gets. -->
    <div v-if="attached" class="quoting attached-chip">
      <img
        v-if="attached.previewKind === 'image'"
        class="attached-thumb"
        :src="attached.previewURL"
        :alt="t('prévia')"
      />
      <video
        v-else-if="attached.previewKind === 'video'"
        class="attached-thumb"
        :src="attached.previewURL"
        preload="metadata"
        muted
        playsinline
      />
      <div class="grow">
        <div class="quoting-who">{{ attached.plan.label }}</div>
        <div class="quoting-body">
          {{ attached.fileName }} · {{ bytes(attached.blob.size) }}
          <template v-if="attached.width"> {{ t('· {v0}×{v1}', { v0: attached.width, v1: attached.height }) }}</template>
          <template v-if="attached.seconds"> {{ t('· {v0}s', { v0: attached.seconds }) }}</template>
        </div>
        <div v-if="attached.missing.length" class="quoting-body sealed"> {{ t('não foi possível ler: {v0}', { v0: attached.missing.join(', ') }) }}
        </div>
      </div>
      <button class="icon-btn" type="button" :title="t('Tirar o anexo')" :aria-label="t('Tirar o anexo')" @click="clearAttachment"><AppIcon name="close" :size="20" /></button>
    </div>

    <div v-if="attachError" class="alert">{{ attachError }}</div>
    <div v-if="state.actionError" class="alert">{{ state.actionError }}</div>

    <SendMarks
      v-if="showMarks"
      :marks="marks"
      :can-view-once="canViewOnce"
      :for-media="Boolean(attached)"
      :chat-timer="chatTimer"
      @update:marks="marks = $event"
    />

    <div v-if="!allowed" class="composer-off">{{ reason }}</div>

    <!-- Recording takes the whole row. Everything else in it would be a way to
         lose what is being said. -->
    <div v-else-if="recording" class="composer-row recording-row">
      <span class="rec-dot" />
      <span class="rec-time">{{ clock(recordedFor) }}</span>
      <span class="grow rec-note">{{ t('gravando — o microfone está aberto') }}</span>
      <button class="icon-btn" type="button" :title="t('Descartar gravação')" :aria-label="t('Descartar gravação')" @click="cancelRecording"><AppIcon name="trash" /></button>
      <button class="primary send" type="button" :title="t('Parar e anexar gravação')" :aria-label="t('Parar e anexar gravação')" @click="stopRecording"><AppIcon name="stop" :size="20" /></button>
    </div>

    <form v-else class="composer-row" @submit.prevent="submit">
      <input
        ref="chooser"
        type="file"
        style="display: none"
        aria-hidden="true"
        tabindex="-1"
        @change="onPicked"
      />
      <button
        v-if="!target"
        class="icon-btn attach"
        type="button"
        :title="t('Anexar um arquivo')"
        :aria-label="t('Anexar um arquivo')"
        @click="browse"
      >
        <AppIcon name="paperclip" />
      </button>
      <textarea
        ref="box"
        v-model="draft"
        rows="1"
        enterkeyhint="enter"
        :placeholder="
          attached
            ? captionAllowed
              ? t('Legenda (opcional)')
              : t('{v0} não leva legenda', { v0: attached.plan.label })
            : t('Mensagem')
        "
        :disabled="Boolean(attached) && !captionAllowed"
        :aria-label="attached && captionAllowed ? t('Legenda') : t('Escreva uma mensagem')"
        @keydown="onKey"
        @paste="onPaste"
      />
      <button
        v-if="micAvailable && !attached && !target"
        class="icon-btn attach"
        type="button"
        :disabled="opening"
        :title="t('Gravar uma mensagem de voz')"
        :aria-label="t('Gravar uma mensagem de voz')"
        @click="startRecording"
      >
        <AppIcon name="microphone" />
      </button>
      <button
        class="icon-btn detail"
        :class="{ on: showMarks || marksSummary }"
        type="button"
        :title="marksSummary || t('Detalhes desta mensagem')"
        :aria-label="t('Detalhes desta mensagem')"
        :aria-expanded="showMarks"
        @click="showMarks = !showMarks"
      >
        <AppIcon :name="showMarks ? 'chevron-up' : 'chevron-down'" :size="18" />
      </button>
      <button
        class="primary send"
        type="submit"
        :disabled="!sendable"
        :title="target ? t('Salvar') : t('Enviar')"
        :aria-label="target ? t('Salvar edição') : t('Enviar mensagem')"
      >
        <AppIcon :name="target ? 'check' : 'send'" />
      </button>
    </form>

    <div v-if="marksSummary && !showMarks" class="marks-summary">↪ {{ marksSummary }}</div>
  </div>
</template>

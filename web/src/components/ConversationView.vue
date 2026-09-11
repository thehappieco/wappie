<script setup lang="ts">
import { t } from '../ui/i18n'
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'

import { conversationPagingContext, loadOlder, people, refreshChats, state, type MessageView } from '../state/archive'
import { loadGroup, setChatTimer } from '../state/groups'
import { TIMER_PRESETS, timerLabel } from '../state/ephemeral'
import { nowTick } from '../state/actions'
import { availabilityIn, typingIn, watchPresence } from '../state/presence'
import { forgetSeen, sawMessage } from '../state/reading'
import { dayLabel, sameDay } from '../ui/format'
import AppIcon from './AppIcon.vue'
import AvatarBadge from './AvatarBadge.vue'
import Composer from './Composer.vue'
import MessageBubble from './MessageBubble.vue'
import ForwardDialog from './ForwardDialog.vue'
import { canForward } from '../state/forwarding'
import { resolveQuotedMessage, type QuoteNavigationResult } from '../state/quoteNavigation'
import { focusQuotedMessage } from '../ui/quoteFocus'

const emit = defineEmits<{ back: [] }>()
const scroller = ref<HTMLElement | null>(null)
const composer = ref<InstanceType<typeof Composer> | null>(null)
const pinnedToBottom = ref(true)
let sizeWatcher: ResizeObserver | null = null

function onScroll() {
  const el = scroller.value
  if (el) pinnedToBottom.value = el.scrollHeight - el.scrollTop - el.clientHeight < 120
}

/**
 * A file dragged onto the conversation.
 *
 * Over the whole conversation rather than over the composer, which is a strip
 * at the bottom that nobody aims at. `dragging` is counted rather than set,
 * because dragenter and dragleave both fire while crossing between child
 * elements and a boolean flickers the whole way across.
 */
const dragDepth = ref(0)
const dragging = computed(() => dragDepth.value > 0)

function onDragEnter(event: DragEvent) {
  if (!Array.from(event.dataTransfer?.types ?? []).includes('Files')) return
  event.preventDefault()
  dragDepth.value += 1
}

function onDragOver(event: DragEvent) {
  if (!dragging.value) return
  // Without this the browser navigates to the file instead, which loses the
  // conversation and everything unsent in it.
  event.preventDefault()
  if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy'
}

function onDragLeave() {
  dragDepth.value = Math.max(0, dragDepth.value - 1)
}

function onDrop(event: DragEvent) {
  dragDepth.value = 0
  const file = event.dataTransfer?.files?.[0]
  if (!file) return
  event.preventDefault()
  composer.value?.take(file)
}

const chat = computed(() => state.chats.find((c) => c.key === state.openChatKey))

/** Rows with the day separators worked out once, rather than per bubble. */
interface Line {
  message: MessageView
  day?: string
  showSender: boolean
}

/** The message being replied to, if any. Cleared once it is sent. */
const replyTo = ref('')

/** The message being edited, if any. Mutually exclusive with replying. */
const editing = ref('')
const forwarding = ref<MessageView>()
const quoteBusy = ref(false)
const quotePages = ref(0)
const quoteError = ref('')
const highlightedQuote = ref('')
let quoteAttempt = 0
let quoteAbort: AbortController | undefined
let quoteHighlightTimer: ReturnType<typeof setTimeout> | undefined

function cancelQuoteNavigation() {
  quoteAttempt++
  quoteAbort?.abort()
  quoteAbort = undefined
  quoteBusy.value = false
  quotePages.value = 0
  quoteError.value = ''
  highlightedQuote.value = ''
  if (quoteHighlightTimer) clearTimeout(quoteHighlightTimer)
  quoteHighlightTimer = undefined
}

function quoteFailure(result: QuoteNavigationResult): string {
  switch (result.status) {
    case 'not_found': return t('A mensagem original não está no histórico disponível desta conversa.')
    case 'limit': return t('A mensagem original ainda não foi encontrada. Toque na citação novamente para continuar a busca.')
    case 'busy': return t('Aguarde as mensagens terminarem de carregar e tente novamente.')
    case 'unavailable': return t('Não foi possível continuar a busca nesta conversa. Verifique a conexão e tente novamente.')
    case 'error': return t('Não foi possível carregar a mensagem original. Tente novamente.')
    default: return ''
  }
}

async function navigateQuote(waID: string) {
  if (quoteBusy.value) return
  cancelQuoteNavigation()
  const attempt = quoteAttempt
  const context = conversationPagingContext()
  if (!context) { quoteError.value = quoteFailure({ status: 'unavailable' }); return }
  const controller = new AbortController()
  quoteAbort = controller
  const current = () => attempt === quoteAttempt && !controller.signal.aborted && context.current()
  quoteBusy.value = true
  pinnedToBottom.value = false
  const result = await resolveQuotedMessage(waID, {
    signal: controller.signal,
    loadPage: () => older(current),
    onProgress: pages => { if (current()) quotePages.value = pages },
  })
  if (!current()) { if (attempt === quoteAttempt) cancelQuoteNavigation(); return }
  quoteBusy.value = false
  quoteAbort = undefined
  if (result.status !== 'found') { quoteError.value = quoteFailure(result); return }
  await nextTick()
  if (!current()) { if (attempt === quoteAttempt) cancelQuoteNavigation(); return }
  const target = scroller.value && focusQuotedMessage(scroller.value, result.waID)
  if (!target) { quoteError.value = quoteFailure({ status: 'error' }); return }
  highlightedQuote.value = result.waID
  quoteHighlightTimer = setTimeout(() => {
    if (current()) highlightedQuote.value = ''
    quoteHighlightTimer = undefined
  }, 1900)
}

function forward(uid: string) {
  const message = state.timeline.find(value => value.uid === uid)
  if (message && canForward(message)) { forgetSeen(); forwarding.value = message }
}
watch(() => [state.openChatKey, state.deviceID, state.tenantID], () => { replyTo.value = ''; editing.value = ''; forwarding.value = undefined }, { flush: 'sync' })
watch(() => [state.openChatKey, state.deviceID, state.tenantID, state.view, state.connected, state.selectedUID, state.groupPanel], cancelQuoteNavigation, { flush: 'sync' })
watch(() => state.loadingChat, loading => { if (loading) cancelQuoteNavigation() }, { flush: 'sync' })

const lines = computed<Line[]>(() => {
  const out: Line[] = []
  let previous: MessageView | undefined
  for (const message of state.timeline) {
    out.push({
      message,
      day: sameDay(previous?.ts, message.ts) ? undefined : dayLabel(message.ts),
      // Only the first of a run from the same person is labelled. In the
      // status feed consecutive posts are usually by different people, so
      // nearly every one carries a name — which is what makes it readable.
      showSender: previous?.senderKey !== message.senderKey || !sameDay(previous?.ts, message.ts),
    })
    previous = message
  }
  return out
})

// Opening a conversation lands at the bottom, where the newest message is.
watch(
  () => state.openChatKey,
  async () => {
    pinnedToBottom.value = true
    await nextTick()
    if (scroller.value) scroller.value.scrollTop = scroller.value.scrollHeight
  },
)

// A live message scrolls into view only if the reader was already at the
// bottom. Yanking someone away from what they are reading is worse than
// missing a notification.
watch(
  () => state.timeline.length,
  async (now, before) => {
    const el = scroller.value
    if (!el || now <= before || !pinnedToBottom.value) return
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 160
    if (!atBottom) return
    await nextTick()
    el.scrollTop = el.scrollHeight
  },
)

async function older(holdPosition: () => boolean = () => true) {
  const el = scroller.value
  const deviceID = state.deviceID
  const chatKey = state.openChatKey
  const tenantID = state.tenantID
  const before = el?.scrollHeight ?? 0
  const previousTop = el?.scrollTop ?? 0
  pinnedToBottom.value = false
  const progress = await loadOlder()
  await nextTick()
  // Hold the reader's place: without this, prepending a page jumps them to the
  // top of a conversation they were reading the middle of.
  if (holdPosition() && el && scroller.value === el && state.deviceID === deviceID && state.openChatKey === chatKey && state.tenantID === tenantID) {
    el.scrollTop = previousTop + el.scrollHeight - before
  }
  return progress
}

/**
 * Marking messages read as they are actually looked at.
 *
 * On screen, not merely loaded: a conversation holds sixty messages and a
 * reader sees five. And only while the tab has focus — a window behind another
 * window is not being read, and an archive that reported otherwise would be
 * lying on the reader's behalf about the one thing it exists to record
 * honestly.
 *
 * Our own messages carry no marker, so they are never observed: telling
 * WhatsApp we read what we sent is meaningless and would clear the badge.
 */
const focused = ref(!document.hidden && document.hasFocus())
let watcher: IntersectionObserver | null = null
let sweep: ReturnType<typeof setInterval> | undefined
let presenceRefresh: ReturnType<typeof setInterval> | undefined

function refreshPresence() {
  if (focused.value) void watchPresence(state.openChatKey)
}

function onFocusChange() {
  focused.value = !document.hidden && document.hasFocus()
  if (!focused.value) forgetSeen()
  else refreshPresence()
}

/** The ids currently intersecting, re-reported on a tick so dwell can elapse. */
const onScreen = new Set<string>()

function observe() {
  watcher?.disconnect()
  const root = scroller.value
  if (!root) return
  watcher = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        const id = (e.target as HTMLElement).dataset.wa
        if (!id) continue
        if (e.isIntersecting) onScreen.add(id)
        else {
          onScreen.delete(id)
          sawMessage(id, false)
        }
      }
    },
    // Half of the bubble, so a message peeking over the edge of the scroller
    // does not count as read.
    { root, threshold: 0.5 },
  )
  for (const el of root.querySelectorAll<HTMLElement>('[data-wa]')) watcher.observe(el)
}

onMounted(() => {
  refreshPresence()
  presenceRefresh = setInterval(refreshPresence, 45_000)
  if (typeof ResizeObserver !== 'undefined') {
    sizeWatcher = new ResizeObserver(() => {
      const el = scroller.value
      if (el && pinnedToBottom.value) el.scrollTop = el.scrollHeight
    })
    if (scroller.value) sizeWatcher.observe(scroller.value)
  }
  if (scroller.value) scroller.value.scrollTop = scroller.value.scrollHeight
  window.addEventListener('focus', onFocusChange)
  window.addEventListener('blur', onFocusChange)
  document.addEventListener('visibilitychange', onFocusChange)
  // The dwell clock needs to be revisited while a message sits still, and an
  // IntersectionObserver only speaks when something crosses the boundary.
  sweep = setInterval(() => {
    // A modal can cover a geometrically visible bubble. Reading pauses while
    // attention is on details, participants, or another modal layer.
    if (state.groupPanel || state.selectedUID || document.querySelector('dialog[open], .modal-veil, .sheet-backdrop')) {
      forgetSeen()
      return
    }
    for (const id of onScreen) sawMessage(id, focused.value)
  }, 300)
})

onBeforeUnmount(() => {
  cancelQuoteNavigation()
  forgetSeen()
  sizeWatcher?.disconnect()
  window.removeEventListener('focus', onFocusChange)
  window.removeEventListener('blur', onFocusChange)
  document.removeEventListener('visibilitychange', onFocusChange)
  watcher?.disconnect()
  if (sweep) clearInterval(sweep)
  if (presenceRefresh) clearInterval(presenceRefresh)
})

watch(() => [state.groupPanel, state.selectedUID], () => forgetSeen(), { flush: 'sync' })
watch(() => [state.openChatKey, state.deviceID, state.connected, state.quiet], refreshPresence)

const availabilityHere = computed(() => availabilityIn(state.openChatKey, nowTick.value))
const presenceLabel = computed(() => availabilityHere.value === 'online' ? t('online')
  : availabilityHere.value === 'offline' ? t('offline') : t('Status indisponível'))
const presenceHint = computed(() => state.quiet
  ? t('No modo incógnito, você não consulta a presença dos contatos. A presença do número é compartilhada com outros usuários e o telefone.')
  : t('O status depende da conexão e das configurações de privacidade do contato.'))

// Re-observe whenever the conversation is rebuilt, which is on every live
// frame: the elements are new objects and the old observer is watching nodes
// that are no longer in the document.
watch(
  () => [state.openChatKey, state.timeline.length] as const,
  async () => {
    onScreen.clear()
    forgetSeen()
    await nextTick()
    observe()
  },
  { immediate: true },
)

/** Who is typing in this conversation, if anybody. */
const typingHere = computed(() => {
  const who = typingIn(state.openChatKey, nowTick.value)
  if (who.length === 0) return ''
  const recording = who.some((t) => t.media === 'audio')
  if (!chat.value?.isGroup) return recording ? t('gravando áudio…') : t('digitando…')
  const names = who.map((t) =>
    people().nameFor(t.senderLID || t.senderPN || t.senderKey),
  )
  if (names.length === 1) return recording ? t('{name} está gravando áudio…', { name: names[0] }) : t('{name} está digitando…', { name: names[0] })
  return recording ? t('{names} estão gravando áudio…', { names: names.join(', ') }) : t('{names} estão digitando…', { names: names.join(', ') })
})

/** Opening the group panel fetches it, refreshing from WhatsApp on the way. */
function openGroup() {
  state.groupPanel = !state.groupPanel
  if (state.groupPanel) void loadGroup(state.openChatKey)
}

async function onTimer(value: string) {
  const seconds = Number(value)
  if (!Number.isFinite(seconds) || !chat.value) return
  // The reply is applied by setChatTimer itself, so the select settles on the
  // value WhatsApp accepted without waiting for a re-listing. The refresh still
  // follows, because the same change can move other things on the row.
  if (await setChatTimer(chat.value.key, seconds)) await refreshChats()
}
</script>

<template>
  <section
    class="conversation"
    :class="{ dropping: dragging }"
    @dragenter="onDragEnter"
    @dragover="onDragOver"
    @dragleave="onDragLeave"
    @drop="onDrop"
  >
    <div class="topbar conversation-header">
      <button class="icon-btn mobile-back" type="button" :aria-label="t('Voltar para conversas')" @click="emit('back')">
        <AppIcon name="back" />
      </button>
      <template v-if="chat">
      <AvatarBadge
        :contact-key="chat.avatarKey"
        :name="chat.name"
        :is-group="chat.isGroup"
        small
      />
      <div class="grow">
        <h2>{{ chat.name }}</h2>
        <div class="sub">
          <template v-if="chat.isGroup && chat.audience">{{ t('{v0} participantes', { v0: chat.audience }) }}</template>
          <template v-else-if="chat.isGroup">{{ t('Grupo') }}</template>
          <span v-else-if="typingHere" class="contact-presence">{{ typingHere }}</span>
          <span v-else class="contact-presence" :class="{ online: availabilityHere === 'online' }" :title="presenceHint">
            <span v-if="availabilityHere !== 'unknown'" class="presence-dot" aria-hidden="true" />{{ presenceLabel }}
          </span>
        </div>
      </div>

      <!-- The disappearing timer, shown and editable. A chat setting rather
           than a message option, because that is all WhatsApp has: there is no
           way to make one message vanish and leave the next alone. Changing it
           is announced to everyone in the conversation by WhatsApp itself. -->
      <select
        class="timer"
        :aria-label="t('Mensagens temporárias')"
        :value="chat.ephemeral"
        :title="t('Mensagens temporárias: ') + timerLabel(chat.ephemeral) +
          t('. Vale para a conversa inteira, e o WhatsApp avisa todo mundo nela.')"
        @change="onTimer(($event.target as HTMLSelectElement).value)"
      >
        <option v-for="s in TIMER_PRESETS" :key="s" :value="s">{{ timerLabel(s) }}</option>
        <option v-if="!TIMER_PRESETS.includes(chat.ephemeral as never)" :value="chat.ephemeral">
          {{ timerLabel(chat.ephemeral) }}
        </option>
      </select>

      <button
        v-if="chat.isGroup"
        class="icon-btn"
        :title="t('Participantes e histórico do grupo')"
        :aria-label="t('Participantes e histórico do grupo')"
        @click="openGroup"
      >
        ⋯
      </button>
      </template>
      <h2 v-else class="grow">{{ t('Conversa') }}</h2>
    </div>

    <div class="banner" v-if="state.lagged"> {{ t('A transmissão teve uma lacuna e a conversa foi recarregada do histórico.') }} </div>

    <div v-if="typingHere" class="typing-line">{{ typingHere }}</div>

    <div v-if="quoteBusy || quoteError" class="quote-navigation-status" role="status" aria-live="polite">
      <span v-if="quoteBusy">{{ quotePages ? t('Procurando a mensagem original… {count} páginas carregadas.', { count: quotePages }) : t('Procurando a mensagem original…') }}</span>
      <span v-else>{{ quoteError }}</span>
      <button type="button" class="ghost" @click="cancelQuoteNavigation">{{ quoteBusy ? t('Cancelar') : t('Fechar') }}</button>
    </div>

    <div class="messages" ref="scroller" @scroll.passive="onScroll">
      <div class="centered-row" v-if="state.hasOlder">
        <button class="ghost" @click="older()" :disabled="state.loadingOlder || quoteBusy">
          {{ state.loadingOlder ? t('Carregando…') : t('Carregar mensagens anteriores') }}
        </button>
      </div>
      <div class="centered-row" v-else-if="state.timeline.length">
        <span class="sealed">{{ t('início do histórico de conversas') }}</span>
      </div>

      <!-- Keyed on the WhatsApp id, not the uid. The two differ for a message
           this tab just sent: the optimistic line names itself after the id it
           minted, and the archived row carries the server's own uid. Keying on
           the uid destroys and rebuilds the whole bubble at that moment, which
           for an attachment means throwing away the local preview and drawing a
           placeholder in its place. -->
      <template v-for="line in lines" :key="line.message.waID">
        <div v-if="line.day" class="day">{{ line.day }}</div>
        <MessageBubble
          :data-wa="line.message.fromMe ? undefined : line.message.waID"
          :data-message-id="line.message.waID"
          :class="{ 'quote-target': highlightedQuote === line.message.waID }"
          :message="line.message"
          :show-sender="line.showSender"
          @reply="editing = ''; replyTo = $event"
          @edit="replyTo = ''; editing = $event"
          @forward="forward"
          @navigate-quote="navigateQuote"
        />
      </template>

      <div v-if="state.loadingChat" class="empty">{{ t('Abrindo a conversa…') }}</div>
      <div v-else-if="!state.timeline.length" class="empty">
        <div>
          <div class="big">{{ t('Nada arquivado nesta conversa') }}</div>
          <div>{{ t('O aparelho pode não ter enviado o histórico dela ainda.') }}</div>
        </div>
      </div>
    </div>

    <div v-if="dragging" class="drop-veil">{{ t('Solte para anexar') }}</div>

    <Composer
      ref="composer"
      :reply-to="replyTo"
      :editing="editing"
      @cancel="replyTo = ''; editing = ''"
    />
    <ForwardDialog v-if="forwarding" :message="forwarding" @close="forwarding = undefined" />
  </section>
</template>

<style scoped>
.quote-navigation-status { display: flex; align-items: center; gap: 10px; padding: 8px 12px; background: var(--bg-raised); border-bottom: 1px solid var(--line); color: var(--text-dim); font-size: 12px; line-height: 1.4; }
.quote-navigation-status span { flex: 1; min-width: 0; }
.quote-navigation-status button { flex-shrink: 0; min-height: 36px; }
.quote-target :deep(.bubble) { outline: 2px solid var(--message-info); outline-offset: 3px; animation: quote-arrival 1.8s ease-out; }
@keyframes quote-arrival { 0%, 45% { box-shadow: 0 0 0 7px color-mix(in srgb, var(--message-info) 22%, transparent); } 25%, 100% { box-shadow: 0 0 0 2px color-mix(in srgb, var(--message-info) 5%, transparent); } }
@media (prefers-reduced-motion: reduce) { .quote-target :deep(.bubble) { animation: none; box-shadow: 0 0 0 4px color-mix(in srgb, var(--message-info) 15%, transparent); } }
.contact-presence { display: inline-flex; align-items: center; gap: 5px; }
.contact-presence.online { color: var(--accent); }
.presence-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
</style>

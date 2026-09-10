<script setup lang="ts">
import { t } from '../ui/i18n'
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'

import { nowTick } from '../state/actions'
import { canSend, discardFailed, loadHistory, people, state, type MessageView } from '../state/archive'
import { expiryLabel, hasExpired } from '../state/ephemeral'
import { displayFallback, formatPhone, parseJID, SERVER_LID, SERVER_USER } from '../state/jid'
import { hhmm, runs, stamp, typeLabel, unmatchedMentions } from '../ui/format'
import { createMessageGestures, MESSAGE_CONTROLS, REPLY_THRESHOLD } from '../ui/messageGestures'
import { reactionSummary } from '../ui/reactionGroups'
import AppIcon from './AppIcon.vue'
import MediaBlock from './MediaBlock.vue'
import MessageActions from './MessageActions.vue'
import MessageTicks from './MessageTicks.vue'
import PayloadBlock from './PayloadBlock.vue'

const props = defineProps<{ message: MessageView; showSender: boolean }>()
const emit = defineEmits<{
  (e: 'reply', waID: string): void
  (e: 'edit', uid: string): void
  (e: 'forward', uid: string): void
}>()

/**
 * The message this one answers, if it is on the page.
 *
 * Matched on the WhatsApp id, because that is what a reply points at — a uid is
 * this archive's own name for a row and the sender never saw one.
 */
const quoted = computed(() =>
  props.message.replyTo
    ? state.timeline.find((v) => v.waID === props.message.replyTo)
    : undefined,
)

const m = computed(() => props.message)
const selected = computed(() => state.selectedUID === m.value.uid)
const bubble = ref<HTMLElement | null>(null)
const actions = ref<InstanceType<typeof MessageActions> | null>(null)
const pressing = ref(false)
const offset = ref(0)
const swiping = ref(false)
const actionsOpen = ref(false)

function hasSelection() {
  return Boolean(window.getSelection()?.toString())
}

function control(event: Event) {
  return event.target instanceof Element && Boolean(event.target.closest(MESSAGE_CONTROLS))
}

function openActions() {
  if (m.value.pending || hasSelection()) return
  actions.value?.open()
}

function feedback() {
  navigator.vibrate?.(12)
}

const gestures = createMessageGestures({
  onHold() { feedback(); openActions() },
  onReply() { emit('reply', m.value.waID) },
  onReady: feedback,
  onSwipe(value) { swiping.value = value },
  onOffset(value) { offset.value = value },
  onPress(value) { pressing.value = value },
  onCapture: capturePointer,
  onRelease(pointerId) {
    const target = bubble.value
    try { if (target?.hasPointerCapture(pointerId)) target.releasePointerCapture(pointerId) } catch { /* The browser may already have canceled this pointer. */ }
  },
  canReply: () => !m.value.pending && !m.value.deleted && !m.value.isStatus && canSend()
    && state.devices.find(device => device.id === state.deviceID)?.can_send === true,
  hasSelection,
})

function pointerDown(event: PointerEvent) {
  if (control(event) || m.value.pending) { gestures.cancel(); return }
  gestures.pointerDown(event)
}

function pointerMove(event: PointerEvent) {
  if (!gestures.pointerMove(event)) return
  if (event.cancelable) event.preventDefault()
  capturePointer(event.pointerId)
}

function capturePointer(pointerId: number) {
  const target = bubble.value
  try { if (target && !target.hasPointerCapture(pointerId)) target.setPointerCapture(pointerId) } catch { /* A canceled pointer no longer exists. */ }
}

function lostPointerCapture(event: PointerEvent) {
  // Moving implicit capture from a child to the bubble also bubbles this event.
  if (event.target === event.currentTarget) gestures.pointerCancel(event)
}

function click(event: MouseEvent) {
  if (!control(event) && event.detail !== 0 && gestures.shouldSuppressClick()) {
    event.preventDefault()
    event.stopPropagation()
  }
}

function keydown(event: KeyboardEvent) {
  if (event.target !== event.currentTarget || event.isComposing) return
  if (event.key === 'Enter' || event.key === ' ' || event.key === 'ContextMenu' || (event.key === 'F10' && event.shiftKey)) {
    event.preventDefault()
    openActions()
  }
}

function contextMenu(event: MouseEvent) {
  if (control(event) || hasSelection() || m.value.pending) return
  event.preventDefault()
  gestures.cancel()
  openActions()
}

async function selectText() {
  await nextTick()
  const text = bubble.value?.querySelector('.text')
  if (!text) return
  const range = document.createRange()
  range.selectNodeContents(text)
  const selection = window.getSelection()
  selection?.removeAllRanges()
  selection?.addRange(range)
}

watch(() => [m.value.waID, state.openChatKey, state.deviceID], () => gestures.cancel())
onBeforeUnmount(() => gestures.dispose())

const mentions = computed(() => m.value.payload?.mentions ?? [])
const textRuns = computed(() => (m.value.body ? runs(m.value.body, mentions.value) : []))

/**
 * Mentions the text has no place for, shown as a footnote below it.
 *
 * Everything else is inline, which is what WhatsApp does and what a reader
 * expects: the point of a mention is seeing, in the sentence, that it was
 * about you.
 */
const trailing = computed(() => unmatchedMentions(m.value.body ?? '', mentions.value))

/** The mention whose identity popover is open, if any. */
const openMention = ref('')

function toggleMention(jid: string) {
  openMention.value = openMention.value === jid ? '' : jid
}

function mentionText(jid: string): string {
  return '@' + (people().nameFor(jid) || displayFallback(jid))
}

/**
 * What is behind a mention: the two halves of an identity, either of which may
 * be absent. A LID exists precisely so a phone number never has to appear, so
 * "sem telefone" is an ordinary answer and not a gap to apologise for.
 */
function mentionIdentity(jid: string): string[] {
  const known = people().find(jid)
  const server = parseJID(jid).server
  const lid = known?.lid || (server === SERVER_LID ? jid : '')
  const pn = known?.pn || (server === SERVER_USER ? jid : '')
  const out: string[] = []
  if (lid) out.push(lid)
  out.push(pn ? formatPhone(pn) : t('sem telefone'))
  return out
}

/**
 * "temporária" while the timer runs, "expirada" once it has passed.
 *
 * Driven by nowTick, which advances every ten seconds, so a message crosses
 * from one to the other on screen rather than at the next reload.
 */
const expiry = computed(() => expiryLabel(m.value, nowTick.value))
const expiryTitle = computed(() => m.value.expiresAt
  ? hasExpired(m.value, nowTick.value)
    ? t('Mensagem temporária expirada em {time}', { time: stamp(m.value.expiresAt) })
    : t('Mensagem temporária até {time}', { time: stamp(m.value.expiresAt) })
  : t('Mensagem temporária'))
const editedTitle = computed(() => t('Mensagem editada · {count} versões', { count: m.value.versionCount }))
const groupedReactions = computed(() => reactionSummary(m.value.reactions))
const reactionsTitle = computed(() => t('Reações da mensagem: {count}. Ver participantes e histórico.', { count: groupedReactions.value.total }))
function reactionTitle(group: { emoji: string; count: number; mine: boolean }): string {
  const label = group.count === 1
    ? t('{emoji}: uma reação. Ver participante.', { emoji: group.emoji })
    : t('{emoji}: {count} reações. Ver participantes.', { emoji: group.emoji, count: group.count })
  return group.mine ? `${label} ${t('Inclui sua reação.')}` : label
}

const forwardedLabel = computed(() =>
  m.value.forwardingScore >= 5 ? t('encaminhada muitas vezes') : t('encaminhada'),
)
</script>

<template>
  <div class="msg" :class="[m.fromMe ? 'out' : 'in', { 'reply-ready': offset >= REPLY_THRESHOLD }]">
    <span class="reply-gesture" aria-hidden="true" :style="{ opacity: Math.min(1, offset / REPLY_THRESHOLD), transform: `translateX(${Math.min(20, offset / 3)}px) scale(${.65 + .35 * Math.min(1, offset / REPLY_THRESHOLD)})` }"><AppIcon name="reply" :size="20" /></span>
    <!-- A div rather than a button, and not for style: this element already
         contains buttons of its own from MediaBlock, and a button inside a
         button is invalid — browsers recover from it differently, and the inner
         click is the one that gets lost. -->
    <div
      class="bubble"
      ref="bubble"
      role="group"
      tabindex="0"
      :class="{ on: selected, revoked: m.deleted, pressing, 'gesture-open': actionsOpen, swiping }"
      :style="{ transform: offset ? `translate3d(${offset}px, 0, 0)` : undefined }"
      :aria-label="m.fromMe ? t('Mensagem enviada às {time}', { time: hhmm(m.ts) }) : t('Mensagem de {sender}, {time}', { sender: m.senderName, time: hhmm(m.ts) })"
      @click.capture="click"
      @keydown="keydown"
      @contextmenu="contextMenu"
      @pointerdown="pointerDown"
      @pointermove="pointerMove"
      @pointerup="gestures.pointerUp"
      @pointercancel="gestures.pointerCancel"
      @lostpointercapture="lostPointerCapture"
      :title="stamp(m.ts)"
    >
      <MessageActions
        v-if="!m.pending"
        ref="actions"
        :message="m"
        @opened="actionsOpen = true"
        @closed="actionsOpen = false"
        @reply="emit('reply', $event)"
        @edit="emit('edit', $event)"
        @forward="emit('forward', $event)"
        @info="loadHistory(m)"
        @select-text="selectText"
      />

      <!-- The quoted message. m.replyTo has been on the view all along and
           nothing drew it, so a reply looked like an unrelated remark. -->
      <div v-if="quoted" class="quote">
        <div class="quote-who">{{ quoted.fromMe ? t('você') : quoted.senderName }}</div>
        <div class="quote-body" v-if="quoted.bodyState === 'ok' && quoted.body">
          {{ quoted.body }}
        </div>
        <div class="quote-body sealed" v-else>{{ typeLabel(quoted.type) }}</div>
      </div>
      <!-- Honest about the limit: the quoted message may be older than the page
           that is loaded, and saying so beats drawing nothing. -->
      <div v-else-if="m.replyTo" class="quote">
        <div class="quote-body sealed">{{ t('resposta a uma mensagem de uma página anterior') }}</div>
      </div>
      <!-- In the status feed the author is the whole point: consecutive posts
           are by different people, and unlabelled they read as one rambling
           stranger. -->
      <div v-if="showSender && !m.fromMe && (m.isGroup || m.isStatus)" class="sender">
        {{ m.senderName }}
      </div>

      <div v-if="m.forwarded" class="flag" style="margin-bottom: 3px; display: inline-block">
        ↪ {{ forwardedLabel }}
      </div>

      <div class="message-content">
      <MediaBlock v-if="m.media" :message="m" />
      <PayloadBlock v-if="m.payload" :payload="m.payload" :message="m" />

      <!-- The body. Four different things can be true of it and a reader has to
           be able to tell them apart. -->
      <div v-if="m.bodyState === 'ok' && m.body" class="text">
        <template v-for="(run, i) in textRuns" :key="i">
          <a v-if="run.href" :href="run.href" target="_blank" rel="noreferrer noopener">{{
            run.text
          }}</a>
          <!-- A mention renders as the name, in the sentence, the way the
               sender's client drew it. The number is what actually travelled;
               clicking says which identity it was. -->
          <button
            v-else-if="run.mention"
            class="mention"
            type="button"
            @click.stop="toggleMention(run.mention)"
          >
            {{ mentionText(run.mention) }}
            <span v-if="openMention === run.mention" class="mention-id">
              <span v-for="line in mentionIdentity(run.mention)" :key="line">{{ line }}</span>
            </span>
          </button>
          <template v-else>{{ run.text }}</template>
        </template>
      </div>
      <div v-else-if="m.bodyState === 'tampered'" class="tampered"> {{ t('⚠ ADULTERADO OU CHAVE ERRADA') }} </div>
      <div v-else-if="m.bodyState === 'locked'" class="sealed">{{ t('selado — chave indisponível') }}</div>
      <!-- A slot where a message should be. The phone masked this one from
           linked devices, so it is on the handset and will never be here — and
           an archive that promises completeness owes the reader the hole. -->
      <div v-else-if="m.type === 'placeholder'" class="sealed"> {{ t('esta mensagem ficou só no celular — o WhatsApp não a entregou aos aparelhos vinculados') }} </div>
      <!-- An unsupported message names the protobuf field it carried. It is
           the only clue there is: the payload is sealed, so without the name
           nobody can say what this build would need to learn to read it. -->
      <div v-else-if="!m.media && !m.payload" class="sealed">
        {{ typeLabel(m.type) }}<template v-if="m.unsupported"> — {{ m.unsupported }}</template>
      </div>

      <!-- Only the ones the text could not hold. Repeating every mention below
           a message that already highlights them is noise. -->
      <div v-if="trailing.length" class="dim mentions-extra"> {{ t('menciona') }} <button
          v-for="jid in trailing"
          :key="jid"
          class="mention"
          type="button"
          @click.stop="toggleMention(jid)"
        >
          {{ mentionText(jid) }}
          <span v-if="openMention === jid" class="mention-id">
            <span v-for="line in mentionIdentity(jid)" :key="line">{{ line }}</span>
          </span>
        </button>
      </div>
      </div>

      <!-- A message that has left this tab and not come back from the archive
           yet. It is shown because waiting for a round trip before drawing what
           somebody just typed reads as the message being lost. -->
      <div v-if="m.pending === 'sending'" class="flag">{{ t('enviando…') }}</div>
      <!-- With a way out of it. A line that never went holds on to whatever it
           was going to send — for an attachment, the whole file — and without
           this there is nothing to do about it but reload the tab. -->
      <div v-else-if="m.pending === 'failed'" class="flag hot" :title="m.failure"> {{ t('não enviou — {v0}', { v0: m.failure }) }} <button class="link" @click.stop="discardFailed(m.waID)">{{ t('descartar') }}</button>
      </div>
      <!-- Sent and not written down. The message is on the recipient's phone;
           this archive will never have a row for it, and saying so is the whole
           point of an archive that claims to be complete. -->
      <div
        v-else-if="m.pending === 'unarchived'"
        class="flag hot"
        :title="t('O servidor enviou a mensagem mas não conseguiu arquivá-la.')"
      > {{ t('enviada, fora do histórico') }} </div>

      <div class="meta">
        <span v-if="m.viewOnce" class="message-mark mark-once" role="img" :title="t('Mensagem de visualização única')" :aria-label="t('Mensagem de visualização única')"><AppIcon name="view-once" :size="14" /></span>
        <span v-if="expiry" class="message-mark mark-timer" role="img" :title="expiryTitle" :aria-label="expiryTitle"><AppIcon name="timer" :size="14" /></span>
        <span v-if="m.edited" class="message-mark mark-edited" role="img" :title="editedTitle" :aria-label="editedTitle"><AppIcon name="pencil" :size="14" /></span>
        <span v-if="m.deleted" class="message-mark mark-deleted" role="img" :title="t('Mensagem apagada')" :aria-label="t('Mensagem apagada')"><AppIcon name="trash" :size="14" /></span>
        <span>{{ hhmm(m.ts) }}</span>
        <MessageTicks :message="m" />
      </div>
      <div v-if="groupedReactions.total" class="reaction-summary" role="group" :aria-label="reactionsTitle">
        <button v-for="group in groupedReactions.visible" :key="group.key" class="reaction-group" :class="{ mine: group.mine }" type="button"
          :title="reactionTitle(group)" :aria-label="reactionTitle(group)" @click.stop="loadHistory(m)">
          <span class="reaction-emoji" aria-hidden="true">{{ group.emoji }}</span><span class="reaction-count" aria-hidden="true">{{ group.count }}</span>
        </button>
        <button v-if="groupedReactions.hiddenGroups" class="reaction-group reaction-more" type="button"
          :title="t('Mais {count} tipos de reação. Ver todas.', { count: groupedReactions.hiddenGroups })"
          :aria-label="t('Mais {count} tipos de reação. Ver todas.', { count: groupedReactions.hiddenGroups })" @click.stop="loadHistory(m)">+{{ groupedReactions.hiddenGroups }}</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.msg { position: relative; }
.bubble { cursor: auto; padding-right: 34px; touch-action: pan-y pinch-zoom; transition: transform 260ms cubic-bezier(.2,.85,.25,1.15), box-shadow 180ms ease-out; }
.bubble:hover:not(.on):not(.gesture-open) { outline: none; }
.bubble:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.bubble.pressing { box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent); }
.bubble.gesture-open { outline: 2px solid var(--accent); }
.bubble.swiping { transition: none; will-change: transform; user-select: none; -webkit-user-select: none; }
.bubble.revoked .message-content { opacity: .6; }
.bubble.revoked .text, .bubble.revoked .text a, .bubble.revoked .text .mention { text-decoration: line-through; text-decoration-thickness: 1px; }
.message-mark { display: inline-flex; align-items: center; color: var(--text-faint); cursor: help; }
.mark-timer { color: #916400; }.mark-edited { color: #08704b; }.mark-deleted { color: #b32732; }.mark-once { color: #2463b9; }
:root[data-theme='dark'] .mark-timer, :root[data-surface='chat'][data-incognito='true'] .mark-timer { color: #f0bd55; }
:root[data-theme='dark'] .mark-edited, :root[data-surface='chat'][data-incognito='true'] .mark-edited { color: #65d6a2; }
:root[data-theme='dark'] .mark-deleted, :root[data-surface='chat'][data-incognito='true'] .mark-deleted { color: #ff939b; }
:root[data-theme='dark'] .mark-once, :root[data-surface='chat'][data-incognito='true'] .mark-once { color: #83baff; }
.msg:has(.reaction-summary) { margin-bottom: 22px; }
.reaction-summary { position: absolute; inset-inline-start: 7px; bottom: -19px; z-index: 1; display: flex; gap: 3px; width: max-content; max-width: calc(100vw - 44px); }
.out .reaction-summary { inset-inline-start: auto; inset-inline-end: 7px; }
.reaction-group { position: relative; display: inline-flex; align-items: center; justify-content: center; gap: 4px; min-width: 34px; min-height: 27px; max-width: 62px; padding: 3px 6px; background: var(--bg-raised); color: var(--text-dim); border: 2px solid var(--canvas); border-radius: 999px; box-shadow: 0 1px 3px #0002; font-size: 11px; font-variant-numeric: tabular-nums; cursor: pointer; }
.reaction-group::before { content: ''; position: absolute; inset: -6px -1px; }
.reaction-group:hover { background: var(--bg-hover); color: var(--text); }
.reaction-group:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.reaction-group.mine { color: var(--text); box-shadow: inset 0 -2px 0 var(--accent), 0 1px 3px #0002; }
.reaction-emoji { font-size: 15px; line-height: 18px; }.reaction-count { min-width: 0; overflow: hidden; text-overflow: ellipsis; }.reaction-more { padding-inline: 8px; font-weight: 650; }
.reply-gesture { position: absolute; inset-inline-start: 0; top: calc(50% - 16px); width: 32px; height: 32px; display: grid; place-items: center; color: var(--text-dim); background: var(--bg-raised); border-radius: 50%; pointer-events: none; }
.reply-ready .reply-gesture { background: var(--accent); color: var(--on-accent); }
@media (prefers-reduced-motion: reduce) { .bubble { transition: none; } }
</style>

<script setup lang="ts">
import { computed } from 'vue'

import type { Marks } from '../state/archive'
import { TIMER_PRESETS, timerLabel } from '../state/ephemeral'

// What a message says about itself, beyond what it says.
//
// Behind a disclosure rather than beside the send button: nobody marks most
// messages this way, and a row of checkboxes over the text box would be in the
// way of the ninety-nine percent. But the archive already reads these flags on
// everything that arrives, and being able to read a flag and not to set one is
// a gap rather than a decision.

const props = defineProps<{
  marks: Marks
  canViewOnce: boolean
  forMedia: boolean
  /** The conversation's own timer, in seconds. The default for this message. */
  chatTimer: number
}>()
const emit = defineEmits<{ (e: 'update:marks', marks: Marks): void }>()

function set(patch: Partial<Marks>) {
  emit('update:marks', { ...props.marks, ...patch })
}

/**
 * "Muitas vezes" is a score, not a second flag.
 *
 * WhatsApp draws the stronger badge from five hops onward, so that is the
 * number this sets. Below it the badge is the ordinary one, and at zero there
 * is no badge at all even with the flag on — which is why turning the flag on
 * floors the score at one.
 */
const manyTimes = computed(() => props.marks.score >= 5)

function toggleForwarded(on: boolean) {
  set({ forwarded: on, score: on ? Math.max(1, props.marks.score) : 0 })
}

function toggleMany(on: boolean) {
  set({ forwarded: true, score: on ? 5 : 1 })
}

/**
 * The timer offered for this one message.
 *
 * "Como a conversa" is the absence of an override, not the chat's number copied
 * in — the two differ if somebody changes the conversation's timer between
 * opening this and pressing send, and copying would freeze the older value.
 *
 * The presets are WhatsApp's, plus the conversation's own when it is not one of
 * them: a chat set to an unusual timer from another client must still be
 * choosable here.
 */
const timer = computed(() => (props.marks.expiration === undefined ? '' : String(props.marks.expiration)))

const offered = computed(() => {
  const all = [...TIMER_PRESETS] as number[]
  if (props.chatTimer > 0 && !all.includes(props.chatTimer)) all.push(props.chatTimer)
  return all.sort((a, b) => a - b)
})

function setTimer(value: string) {
  set({ expiration: value === '' ? undefined : Number(value) })
}
</script>

<template>
  <div class="marks">
    <label class="mark">
      <input
        type="checkbox"
        :checked="marks.forwarded"
        @change="toggleForwarded(($event.target as HTMLInputElement).checked)"
      />
      <span>
        <b>Encaminhada</b>
        <em>o destinatário vê o rótulo "encaminhada" acima da mensagem</em>
      </span>
    </label>

    <label class="mark" :class="{ off: !marks.forwarded }">
      <input
        type="checkbox"
        :checked="manyTimes"
        :disabled="!marks.forwarded"
        @change="toggleMany(($event.target as HTMLInputElement).checked)"
      />
      <span>
        <b>Encaminhada muitas vezes</b>
        <em>a partir de cinco repasses o WhatsApp troca o rótulo e restringe o reenvio</em>
      </span>
    </label>

    <!-- Per message, because that is where the timer actually lives: it travels
         in every message's context info, not on the conversation. Only on the
         way out — nothing in the protocol changes the timer of a message
         already sent, so the message menu states it and does not offer to edit
         it. -->
    <label class="mark">
      <select
        class="timer-select"
        :value="timer"
        @change="setTimer(($event.target as HTMLSelectElement).value)"
      >
        <option value="">como a conversa ({{ timerLabel(chatTimer) }})</option>
        <option v-for="seconds in offered" :key="seconds" :value="String(seconds)">
          {{ timerLabel(seconds) }}
        </option>
      </select>
      <span>
        <b>Prazo desta mensagem</b>
        <em v-if="marks.expiration === undefined">segue o temporizador da conversa</em>
        <em v-else-if="marks.expiration === 0">
          não expira, mesmo com a conversa temporária
        </em>
        <em v-else>some do aparelho do destinatário depois desse prazo — mas fica no arquivo</em>
      </span>
    </label>

    <label class="mark" :class="{ off: !canViewOnce }">
      <input
        type="checkbox"
        :checked="marks.viewOnce"
        :disabled="!canViewOnce"
        @change="set({ viewOnce: ($event.target as HTMLInputElement).checked })"
      />
      <span>
        <b>Ver uma vez</b>
        <em v-if="canViewOnce">some da conversa do destinatário depois de aberta — mas fica no arquivo</em>
        <em v-else-if="!forMedia">só existe para anexos; em texto o WhatsApp mostra um erro</em>
        <em v-else>este tipo de anexo não carrega a marcação de forma confiável</em>
      </span>
    </label>
  </div>
</template>

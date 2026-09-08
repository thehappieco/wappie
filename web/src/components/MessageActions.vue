<script setup lang="ts">
import { computed, ref } from 'vue'

import type { MessageView } from '../state/archive'
import { canDelete, canEdit, editableFor, myReaction, nowTick, react, revoke } from '../state/actions'
import { hasExpired, isEphemeral, timerLabel } from '../state/ephemeral'
import { stamp } from '../ui/format'

// What to do with a message, next to the message.
//
// Not in the forensic panel: clicking a bubble there is a fetch, not a
// selection — it spends a round trip on the message's history and takes over
// the column, which below 620px replaces the conversation outright. Reacting
// should cost neither. The panel keeps its job, which is what the message WAS;
// this is what to do with it.

const props = defineProps<{ message: MessageView }>()
const emit = defineEmits<{
  (e: 'reply', waID: string): void
  (e: 'edit', uid: string): void
}>()

const m = computed(() => props.message)
const picking = ref(false)
const confirming = ref(false)
const showingTimer = ref(false)

/**
 * What this message's own timer says.
 *
 * Stated, never editable. The timer travels in a message's context info, so it
 * is genuinely per message — but nothing in the protocol changes it after the
 * fact. The closest thing WhatsApp has is KeepInChatMessage, which preserves a
 * message rather than rescheduling it, and offering an "editar prazo" that
 * silently did nothing would be worse than saying so.
 */
const timerNote = computed(() => {
  const message = m.value
  if (!isEphemeral(message)) return ''
  const at = message.expiresAt
  if (at) {
    return hasExpired(message, nowTick.value)
      ? `expirou em ${stamp(at)}`
      : `expira em ${stamp(at)}`
  }
  // A timer with no date: the row declares a duration and the archive never
  // computed the instant, which happens on history-synced messages.
  return message.expiration > 0
    ? `temporária, prazo de ${timerLabel(message.expiration)}`
    : 'temporária'
})

// The six WhatsApp itself offers. A full picker is a different piece of work
// and this covers what people actually send.
const QUICK = ['👍', '❤️', '😂', '😮', '😢', '🙏']

const mine = computed(() => myReaction(m.value))

/** Minutes left to edit, for the label. Ticks down on its own. */
const minutesLeft = computed(() => Math.ceil(editableFor(m.value) / 60_000))

async function pick(emoji: string) {
  picking.value = false
  await react(m.value, emoji)
}

async function destroy() {
  confirming.value = false
  await revoke(m.value)
}
</script>

<template>
  <div class="actions" :class="{ open: picking || confirming || showingTimer }">
    <template v-if="picking">
      <button
        v-for="emoji in QUICK"
        :key="emoji"
        class="act emoji"
        :class="{ on: mine === emoji }"
        :title="mine === emoji ? 'Remover' : `Reagir com ${emoji}`"
        @click.stop="pick(emoji)"
      >
        {{ emoji }}
      </button>
      <button class="act" title="Fechar" @click.stop="picking = false">✕</button>
    </template>

    <template v-else-if="showingTimer">
      <span class="act-note">{{ timerNote }}</span>
      <button class="act" title="Fechar" @click.stop="showingTimer = false">✕</button>
    </template>

    <template v-else-if="confirming">
      <span class="act-note">Apagar para todos?</span>
      <button class="act danger-act" @click.stop="destroy">Apagar</button>
      <button class="act" @click.stop="confirming = false">Não</button>
    </template>

    <template v-else>
      <button class="act" title="Reagir" @click.stop="picking = true">
        {{ mine || '☺' }}
      </button>
      <button class="act" title="Responder" @click.stop="emit('reply', m.waID)">↩</button>
      <button
        v-if="canEdit(m)"
        class="act"
        :title="`Editar — ${minutesLeft} min restantes`"
        @click.stop="emit('edit', m.uid)"
      >
        ✎
      </button>
      <!-- Informative. The prazo of a message already sent cannot be changed:
           no operation in the protocol does it. -->
      <button
        v-if="timerNote"
        class="act"
        :title="timerNote"
        @click.stop="showingTimer = true"
      >
        ⏱
      </button>
      <button v-if="canDelete(m)" class="act" title="Apagar para todos" @click.stop="confirming = true">
        🗑
      </button>
    </template>
  </div>
</template>

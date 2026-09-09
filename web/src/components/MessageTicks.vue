<script setup lang="ts">
import { t } from '../ui/i18n'
import { computed } from 'vue'

import { state, type MessageView } from '../state/archive'
import { acksFor } from '../state/receipts'
import { denominatorFor, tickReport } from '../state/ticks'
import AppIcon from './AppIcon.vue'

const props = defineProps<{ message: MessageView }>()

// The denominator comes from the conversation, not from the message: "everyone
// received it" is a claim about how many people are in the room.
const report = computed(() => {
  const chat = state.chats.find((c) => c.keys.includes(props.message.chatKey))
  return tickReport(
    props.message,
    acksFor(props.message.waID),
    denominatorFor(chat, props.message.chatKey),
  )
})

const label = computed(() => {
  switch (report.value.tick) {
    case 'pending':
      return t('enviando')
    case 'sent':
      return t('enviada')
    case 'delivered':
      return t('todos receberam')
    case 'read':
      return t('todos leram')
    case 'played':
      return t('todos ouviram')
    default:
      return ''
  }
})

/** The tooltip carries the caveat, because a tick that stops short owes a reason. */
const title = computed(() =>
  report.value.caveat ? `${label.value} — ${report.value.caveat}` : label.value,
)
</script>

<template>
  <span v-if="report.tick" class="ticks" :class="report.tick" :title="title" role="img" :aria-label="title">
    <AppIcon :name="report.tick === 'pending' ? 'clock' : report.tick === 'sent' ? 'check' : 'checks'" :size="18" />
  </span>
</template>

<style scoped>
.ticks {
  display: inline-flex;
  align-items: center;
  vertical-align: middle;
  line-height: 1;
}

.ticks.read,
.ticks.played {
  color: #53bdeb;
}
</style>

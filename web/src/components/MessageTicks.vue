<script setup lang="ts">
import { computed } from 'vue'

import { state, type MessageView } from '../state/archive'
import { acksFor } from '../state/receipts'
import { denominatorFor, tickReport } from '../state/ticks'

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
      return 'enviando'
    case 'sent':
      return 'enviada'
    case 'delivered':
      return 'todos receberam'
    case 'read':
      return 'todos leram'
    case 'played':
      return 'todos ouviram'
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
  <span v-if="report.tick" class="ticks" :class="report.tick" :title="title">
    <template v-if="report.tick === 'pending'">🕘</template>
    <template v-else-if="report.tick === 'sent'">✓</template>
    <template v-else-if="report.tick === 'delivered'">✓✓</template>
    <template v-else-if="report.tick === 'read'">✓✓</template>
    <template v-else>✓✓✓</template>
  </span>
</template>

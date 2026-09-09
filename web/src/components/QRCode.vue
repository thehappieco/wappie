<script setup lang="ts">
import { t } from '../ui/i18n'
import { computed } from 'vue'

import { encode, svgPath } from '../ui/qr'

// Drawn as a single SVG path of unit squares, scaled by the viewBox. One path
// rather than a few thousand rects keeps the DOM small enough that replacing
// the code every twenty seconds costs nothing.

const props = defineProps<{ text: string; size?: number }>()

const drawn = computed(() => {
  try {
    return { ...svgPath(encode(props.text, 'L')), error: '' }
  } catch (err) {
    // A payload that does not fit is a server sending something unexpected,
    // not something a person can act on — so it says so instead of drawing a
    // picture that cannot be scanned.
    return { path: '', extent: 1, error: err instanceof Error ? err.message : String(err) }
  }
})
</script>

<template>
  <div class="qr" v-if="!drawn.error">
    <svg
      :viewBox="`0 0 ${drawn.extent} ${drawn.extent}`"
      :width="props.size ?? 260"
      :height="props.size ?? 260"
      shape-rendering="crispEdges"
      role="img"
      :aria-label="t('Código QR para conectar o aparelho')"
    >
      <rect :width="drawn.extent" :height="drawn.extent" fill="#fff" />
      <path :d="drawn.path" fill="#000" />
    </svg>
  </div>
  <div v-else class="alert">{{ drawn.error }}</div>
</template>

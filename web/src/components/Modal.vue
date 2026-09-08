<script setup lang="ts">
import { onBeforeUnmount, onMounted } from 'vue'

defineProps<{ title: string; subtitle?: string }>()
const emit = defineEmits<{ close: [] }>()

// Escape closes it, because a thing that covers the page has to be dismissible
// without hunting for the control that does it.
function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape') emit('close')
}

onMounted(() => document.addEventListener('keydown', onKey))
onBeforeUnmount(() => document.removeEventListener('keydown', onKey))
</script>

<template>
  <!-- Over the page rather than beside it. A side panel is part of the layout,
       so its content competes with the conversation for height and pushes the
       composer around; a reader looking at a group's history is not writing a
       message at that moment, and the layout should not pretend otherwise. -->
  <div class="modal-veil" @click.self="emit('close')">
    <div class="modal" role="dialog" aria-modal="true">
      <div class="topbar">
        <div class="grow">
          <h2>{{ title }}</h2>
          <div class="sub" v-if="subtitle">{{ subtitle }}</div>
        </div>
        <slot name="actions" />
        <button class="icon-btn" @click="emit('close')" title="Fechar">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M18 6 6 18M6 6l12 12" />
          </svg>
        </button>
      </div>
      <div class="modal-body">
        <slot />
      </div>
    </div>
  </div>
</template>

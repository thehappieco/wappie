<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'

import { avatarFor, avatars } from '../state/archive'
import { initials } from '../state/jid'
import { whenVisible } from '../ui/visible'

const props = defineProps<{
  contactKey: string
  name: string
  small?: boolean
  isGroup?: boolean
}>()

const element = ref<HTMLElement>()
let cancelLoad = () => {}

// Mounted rows may still be thousands of pixels below the fold. Fetch only
// those near the visible area, and cancel an old contact when a row is reused.
watch(
  [element, () => props.contactKey],
  ([el, key]) => {
    cancelLoad()
    if (!el || avatars.has(key)) return
    cancelLoad = whenVisible(el, () => {
      if (props.contactKey === key) void avatarFor(key)
    })
  },
  { flush: 'post' },
)
onBeforeUnmount(() => cancelLoad())

const url = computed(() => avatars.get(props.contactKey))

/**
 * Two characters that differ between two people with the same label.
 *
 * initials() of "LID 42631895773279" is "L9" for every unnamed person, which is
 * the same collision the label itself used to have. When the name is not a name,
 * the mark comes from the identifier instead — the last two digits, which is
 * enough to tell neighbouring rows apart at a glance while the full identity
 * sits in the title.
 */
const label = computed(() => {
  if (props.isGroup) return '#'
  const named = /\p{L}/u.test(props.name.replace(/^LID\s/, ''))
  if (named) return initials(props.name)
  const digits = props.contactKey.replace(/\D/g, '')
  return digits.slice(-2) || '#'
})

/**
 * A colour per person, hashed from the identifier rather than the name.
 *
 * The identifier is unique where the label may not be, so two unnamed people
 * are never the same badge. Hue only: saturation and lightness are fixed so
 * every badge carries the same weight, and the palette stays legible in both
 * themes.
 */
const hue = computed(() => {
  let h = 0
  for (const ch of props.contactKey) h = (h * 31 + ch.charCodeAt(0)) % 360
  return h
})
</script>

<template>
  <img v-if="url" ref="element" class="avatar" :class="{ sm: small }" :src="url" :alt="name" loading="lazy" decoding="async" />
  <div
    v-else
    ref="element"
    class="avatar tinted"
    :class="{ sm: small }"
    :style="{ '--hue': hue }"
    :title="name"
    aria-hidden="true"
  >
    {{ label }}
  </div>
</template>

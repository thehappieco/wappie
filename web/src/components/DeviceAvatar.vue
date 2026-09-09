<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import type { DeviceInfo } from '../api/protocol'
import { deviceProfilePicture, state } from '../state/archive'
import { initials } from '../state/jid'
const props = defineProps<{ device: DeviceInfo }>()
const url = ref('')
let generation = 0
let retry: ReturnType<typeof setTimeout> | undefined
function clear() { if (url.value) URL.revokeObjectURL(url.value); url.value = ''; clearTimeout(retry) }
watch(() => [props.device.id, props.device.profile_key, state.tenantID, state.phase], () => {
  const current = ++generation
  clear()
  const key = props.device.profile_key
  if (!key) return
  async function load(attempt = 0) {
    try {
      const picture = await deviceProfilePicture(props.device.id, key!)
      if (current !== generation) return
      if (picture) { url.value = URL.createObjectURL(picture); return }
    } catch { /* No picture or no read permission: initials remain. */ }
    if (current === generation && attempt < 2) retry = setTimeout(() => { void load(attempt + 1) }, 3000)
  }
  void load()
}, { immediate: true })
onBeforeUnmount(() => { generation++; clear() })
</script>
<template><img v-if="url" class="device-avatar" :src="url" :alt="device.push_name || device.label" /><span v-else class="device-avatar fallback" aria-hidden="true">{{ initials(device.push_name || device.label || 'Wappie') }}</span></template>
<style scoped>.device-avatar { height: 44px; width: 44px; flex-shrink: 0; object-fit: cover; border-radius: 14px; }.fallback { display: grid; place-items: center; background: color-mix(in srgb, var(--accent) 15%, var(--bg-raised)); color: var(--accent); font-size: 16px; font-weight: 700; }</style>

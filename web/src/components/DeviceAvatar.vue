<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import type { DeviceInfo } from '../api/protocol'
import { deviceProfilePicture, state } from '../state/archive'
import { initials } from '../state/jid'
const props = defineProps<{ device: DeviceInfo }>()
const url = ref('')
let generation = 0
let retry: ReturnType<typeof setTimeout> | undefined
function clear() { if (url.value) URL.revokeObjectURL(url.value); url.value = ''; clearTimeout(retry) }
const retryDelays = [2000, 4000, 8000, 15000, 30000, 30000]
function reload() {
  const current = ++generation
  clear()
  const key = props.device.profile_key
  if (!key || !state.connected) return
  const deviceID = props.device.id
  async function load(attempt = 0) {
    try {
      const picture = await deviceProfilePicture(deviceID, key!)
      if (current !== generation) return
      if (picture) { url.value = URL.createObjectURL(picture); return }
    } catch { /* No picture or no read permission: initials remain. */ }
    // Pairing queues encrypted photo retrieval. A busy history sync can take
    // longer than the original six-second window; retries remain bounded.
    if (current === generation && attempt < retryDelays.length) retry = setTimeout(() => { void load(attempt + 1) }, retryDelays[attempt])
  }
  void load()
}
watch(() => [props.device.id, props.device.profile_key, state.tenantID, state.account, state.phase, state.connected, state.accessRevision], reload, { immediate: true })
function focused() { if (!url.value && document.visibilityState === 'visible') reload() }
onMounted(() => window.addEventListener('focus', focused))
onBeforeUnmount(() => { generation++; clear(); window.removeEventListener('focus', focused) })
</script>
<template><img v-if="url" class="device-avatar" :src="url" :alt="device.push_name || device.label" /><span v-else class="device-avatar fallback" aria-hidden="true">{{ initials(device.push_name || device.label || 'Wappie') }}</span></template>
<style scoped>.device-avatar { height: 44px; width: 44px; flex-shrink: 0; object-fit: cover; border-radius: 14px; }.fallback { display: grid; place-items: center; background: color-mix(in srgb, var(--accent) 15%, var(--bg-raised)); color: var(--accent); font-size: 16px; font-weight: 700; }</style>

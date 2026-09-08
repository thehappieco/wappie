<script lang="ts">
export type IconName =
  | 'back'
  | 'chevron-down'
  | 'chevron-up'
  | 'console'
  | 'devices'
  | 'close'
  | 'check'
  | 'checks'
  | 'clock'
  | 'eye'
  | 'eye-off'
  | 'paperclip'
  | 'microphone'
  | 'stop'
  | 'send'
  | 'trash'
  | 'image'
  | 'video'
  | 'file'
  | 'audio'
  | 'sticker'
  | 'users'
  | 'key'
  | 'wallet'
  | 'building'
  | 'settings'
  | 'logout'
  | 'refresh'
  | 'plus'
  | 'message'
  | 'shield'

const paths: Record<IconName, string> = {
  back: 'M19 12H5m7-7-7 7 7 7',
  'chevron-down': 'm6 9 6 6 6-6',
  'chevron-up': 'm6 15 6-6 6 6',
  console: 'M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z',
  devices: 'M8 3h9a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Zm3 15h3M10 6h5',
  close: 'm6 6 12 12M6 18 18 6',
  check: 'm5 12 4 4L19 6',
  checks: 'm2 12 4 4L16 6m-5 10 2 2L23 8',
  clock: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9-5v5l3 2',
  eye: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Zm13 0a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z',
  'eye-off': 'm3 3 18 18M10.6 5.1 12 5c6.5 0 10 7 10 7a18.5 18.5 0 0 1-3 3.8M6.4 6.4A19.4 19.4 0 0 0 2 12s3.5 7 10 7a10.8 10.8 0 0 0 5.6-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2',
  paperclip: 'm21.4 11.1-9.2 9.1a6 6 0 0 1-8.4-8.4L13 2.6a4 4 0 0 1 5.6 5.6l-9.2 9.2a2 2 0 0 1-2.8-2.8l8.5-8.5',
  microphone: 'M12 3a3 3 0 0 1 3 3v6a3 3 0 0 1-6 0V6a3 3 0 0 1 3-3ZM5 10v2a7 7 0 0 0 14 0v-2m-7 9v3m-4 0h8',
  stop: 'M6 6h12v12H6z',
  send: 'm3 3 19 9-19 9 4-9-4-9Zm4 9h15',
  trash: 'M4 7h16M9 7V4h6v3M6 7l1 14h10l1-14m-8 4v6m4-6v6',
  image: 'M5 3h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Zm-2 13 5-5 5 5 3-3 5 5M16 7h.01',
  video: 'M4 6h11v12H4a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1Zm11 4 6-4v12l-6-4',
  file: 'M14 3H5v18h14V8l-5-5Zm0 0v5h5M8 12h8m-8 4h6',
  audio: 'M10 17V5l10-2v12M10 9l10-2M10 17a3 3 0 1 1-6 0 3 3 0 0 1 6 0Zm10-2a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z',
  sticker: 'M21 13V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h8l8-8Zm-8 8v-8h8M8 8h.01M16 8h.01M8 12c1 2 3 2 4 2',
  users: 'M15 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0ZM3 21v-2a6 6 0 0 1 12 0v2m3-16a4 4 0 0 1 0 8m1 3a5 5 0 0 1 3 5',
  key: 'M14 4a6 6 0 1 1-4 10l-7 7H1v-4l7-7a6 6 0 0 1 6-6Zm3 4h.01',
  wallet: 'M20 7V4H5a3 3 0 0 0 0 6h16v10H5a3 3 0 0 1-3-3V7m19 7h-5v3h5',
  building: 'M5 21V3h12v18M3 21h18M9 7h1m3 0h1M9 11h1m3 0h1M9 15h1m3 0h1m-3 6v-3h3v3',
  settings: 'M4 7h16M4 17h16M7 4v6m10 4v6',
  logout: 'M9 3H4v18h5m5-14 5 5-5 5m-6-5h13',
  refresh: 'M20 7a9 9 0 0 0-15-2L2 8m0-5v5h5m-3 9a9 9 0 0 0 15 2l3-3m0 5v-5h-5',
  plus: 'M12 5v14M5 12h14',
  message: 'M21 11.5a8.5 8.5 0 0 1-8.5 8.5H4l-3 2 1.5-6A8.5 8.5 0 1 1 21 11.5ZM7 9h9m-9 5h6',
  shield: 'M12 2 3 6v6c0 5 9 10 9 10s9-5 9-10V6l-9-4Zm-4 10 3 3 5-6',
}
</script>

<script setup lang="ts">
withDefaults(defineProps<{ name: IconName; size?: number | string }>(), { size: 22 })
</script>

<template>
  <svg
    class="app-icon"
    :width="size"
    :height="size"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="1.8"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
    focusable="false"
  >
    <path :d="paths[name]" />
  </svg>
</template>

<style scoped>
.app-icon {
  display: inline-block;
  flex-shrink: 0;
  vertical-align: middle;
}
</style>

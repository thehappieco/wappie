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

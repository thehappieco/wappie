<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue'
import type { CalendarEvent } from '../api/protocol'
import { filename, ics } from '../ui/calendar'
import { intlLocale, t } from '../ui/i18n'
import AppIcon from './AppIcon.vue'

const props = defineProps<{ event: CalendarEvent; uid?: string }>()
const titleID = useId()
const fileURL = ref('')

// Event content is supplied by another person. Only explicit HTTP(S) links
// may navigate, and credential-bearing links must not disguise their host.
const joinURL = computed(() => {
  try {
    const link = new URL(props.event.join_link ?? '')
    return ['https:', 'http:'].includes(link.protocol) && !link.username && !link.password ? link.href : ''
  } catch { return '' }
})
const times = computed(() => {
  const format = new Intl.DateTimeFormat(intlLocale(), { dateStyle: 'medium', timeStyle: 'short' })
  return [
    { label: t('Início do evento'), value: props.event.start_time },
    { label: t('Fim do evento'), value: props.event.end_time },
  ].flatMap(({ label, value }) => {
    const at = new Date(value ?? '')
    return Number.isNaN(at.getTime()) ? [] : [{ label, iso: at.toISOString(), text: format.format(at) }]
  })
})
const calendarText = computed(() => ics(
  { ...props.event, join_link: joinURL.value || undefined },
  `${props.uid || titleID}@whatserver2`,
  new Date(),
))
function releaseFile() {
  if (fileURL.value) URL.revokeObjectURL(fileURL.value)
  fileURL.value = ''
}
// The file stays local. Replacing/unmounting a card releases its old URL; a
// locale change only changes the text on screen, not the event's UTC instants.
onMounted(() => watch(calendarText, (text) => {
  releaseFile()
  if (typeof URL.createObjectURL === 'function') {
    fileURL.value = URL.createObjectURL(new Blob([text], { type: 'text/calendar;charset=utf-8' }))
  }
}, { immediate: true }))
onBeforeUnmount(releaseFile)
</script>

<template>
  <article class="event-card" :class="{ 'event-canceled': event.is_canceled }" :aria-labelledby="titleID">
    <header class="event-heading">
      <span class="event-icon" aria-hidden="true">
        <svg width="25" height="25" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5" width="18" height="16" rx="3" /><path d="M16 3v4M8 3v4M3 11h18m-13 4h2m4 0h2m-8 3h2" /></svg>
      </span>
      <div><span class="event-kind">{{ t('Evento') }}</span><h3 :id="titleID">{{ event.name || t('Evento') }}</h3></div>
    </header>
    <div v-if="event.is_canceled" class="event-status">{{ t('Evento cancelado') }}</div>
    <dl v-if="times.length" class="event-times">
      <div v-for="time in times" :key="time.label"><dt>{{ time.label }}</dt><dd><time :datetime="time.iso">{{ time.text }}</time></dd></div>
    </dl>
    <p v-if="event.description" class="event-description">{{ event.description }}</p>
    <div v-if="event.location?.name || event.location?.address" class="event-location">
      <AppIcon name="location" :size="18" /><div><span v-if="event.location.name">{{ event.location.name }}</span><span v-if="event.location.address && event.location.address !== event.location.name" class="event-address">{{ event.location.address }}</span></div>
    </div>
    <div v-if="fileURL || (joinURL && !event.is_canceled)" class="event-actions">
      <a v-if="joinURL && !event.is_canceled" :href="joinURL" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer" @click.stop>
        <span aria-hidden="true">↗</span>{{ t('Abrir link do evento') }}
      </a>
      <a v-if="fileURL" :href="fileURL" :download="filename(event)" @click.stop>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v12m-5-5 5 5 5-5M5 16v4h14v-4" /></svg>{{ t('adicionar ao calendário') }}
      </a>
    </div>
  </article>
</template>

<style scoped>
.event-card { min-width: 0; max-width: 340px; margin-bottom: 5px; padding: 14px; border: 1px solid var(--line); border-radius: 14px; background: color-mix(in srgb, var(--text) 4%, transparent); font-size: 13px; overflow-wrap: anywhere; }
.event-heading { display: flex; align-items: center; gap: 11px; }.event-heading > div { min-width: 0; }.event-icon { display: grid; place-items: center; width: 44px; height: 44px; flex-shrink: 0; border-radius: 12px; background: color-mix(in srgb, var(--accent) 12%, transparent); color: var(--accent); }
.event-kind { color: var(--text-dim); font-size: 11px; }.event-heading h3 { margin: 3px 0 0; color: var(--text); font-size: 15px; line-height: 1.35; font-weight: 650; }
.event-times { display: grid; gap: 10px; margin: 14px 0 0; padding: 11px 0; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); }.event-times dt { margin-bottom: 3px; color: var(--text-dim); font-size: 11px; }.event-times dd { margin: 0; line-height: 1.45; font-weight: 550; }
.event-description { margin: 12px 0 0; white-space: pre-wrap; line-height: 1.5; }.event-location { display: flex; align-items: flex-start; gap: 7px; margin-top: 12px; line-height: 1.5; }.event-location > svg { margin-top: 1px; flex-shrink: 0; color: var(--text-dim); }.event-location span { display: block; }.event-address { color: var(--text-dim); font-size: 12px; }
.event-actions { display: grid; margin-top: 10px; }.event-actions a { display: flex; align-items: center; gap: 8px; min-height: 44px; padding: 6px 0; color: var(--accent); font-size: 13px; text-decoration: none; }.event-actions a svg { flex-shrink: 0; }.event-actions a:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; border-radius: 4px; }.event-status { display: inline-block; margin-top: 12px; padding: 4px 8px; color: var(--danger); background: color-mix(in srgb, var(--danger) 10%, transparent); border-radius: 6px; font-size: 12px; font-weight: 600; }.event-canceled .event-icon { color: var(--danger); background: color-mix(in srgb, var(--danger) 10%, transparent); }
@media (hover: hover) { .event-actions a:hover { text-decoration: underline; } }
</style>

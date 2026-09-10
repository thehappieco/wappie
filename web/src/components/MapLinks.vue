<script setup lang="ts">
import { computed } from 'vue'
import { t } from '../ui/i18n'
import { mapLinks } from '../ui/mapLinks'

const props = defineProps<{ lat: number; lon: number; name?: string }>()
const links = computed(() => mapLinks(props.lat, props.lon, props.name?.trim() || t('Localização')))
</script>

<template>
  <nav v-if="links.length" class="map-links" :aria-label="t('Abrir localização no mapa')">
    <span class="map-links-label">{{ t('Conferir no mapa') }}</span>
    <div class="map-links-options">
      <a v-for="link in links" :key="link.provider" :href="link.href"
        :aria-label="t('Abrir no {provider} (nova aba)', { provider: link.label })"
        target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer" @click.stop>
        {{ link.label }}<span aria-hidden="true">↗</span>
      </a>
    </div>
  </nav>
</template>

<style scoped>
.map-links { margin-top: 12px; min-width: 0; }
.map-links-label { display: block; color: var(--text-dim); font-size: 12px; line-height: 1.4; margin-bottom: 6px; }
.map-links-options { display: flex; flex-wrap: wrap; gap: 6px; }
.map-links-options a {
  display: inline-flex; align-items: center; justify-content: center; gap: 6px;
  min-height: 44px; max-width: 100%; padding: 7px 10px; border: 1px solid var(--line);
  border-radius: 10px; background: var(--bg-panel); color: var(--text);
  font-size: 12px; font-weight: 500; line-height: 1.4; text-decoration: none;
}
.map-links-options a span { color: var(--text-dim); }
.map-links-options a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
@media (hover: hover) { .map-links-options a:hover { background: var(--bg-active); } }
</style>

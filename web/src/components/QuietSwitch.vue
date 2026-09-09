<script setup lang="ts">
import { t } from '../ui/i18n'
import { computed, ref } from 'vue'

import { setReceiptMode, state } from '../state/archive'
import AppIcon from './AppIcon.vue'

const busy = ref(false)

const device = computed(() => state.devices.find((d) => d.id === state.deviceID))

// Read from the one flag the gates and the palette read, not re-derived from
// the device row. It used to be derived, and the two disagreed at start-up:
// the flag begins true so an unknown posture emits nothing, the row said
// "active", and the window came up dark with a bell in the corner. One source
// means the icon cannot say something the behaviour is not doing.
const quiet = computed(() => state.quiet)

async function toggle() {
  if (busy.value || !device.value) return
  busy.value = true
  await setReceiptMode(quiet.value ? 'active' : 'passive')
  busy.value = false
}
</script>

<template>
  <button
    v-if="device"
    class="icon-btn quiet"
    :class="{ on: quiet }"
    type="button"
    :disabled="busy"
    :aria-busy="busy"
    :aria-pressed="quiet"
    :aria-label="quiet ? t('Modo incógnito ativado') : t('Modo incógnito desativado')"
    :title="
      quiet
        ? t('Modo incógnito: mantém os indicadores de mensagens não lidas, não envia confirmações de leitura nem mostra que você está digitando. Você também não vê quem está digitando. Clique para desativar.')
        : t('Modo normal: envia confirmações de leitura e mostra que você está online ou digitando. Clique para ativar o modo incógnito.')
    "
    @click="toggle"
  >
    <AppIcon :name="quiet ? 'eye-off' : 'eye'" />
  </button>
</template>

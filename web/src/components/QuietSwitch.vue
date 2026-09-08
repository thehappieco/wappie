<script setup lang="ts">
import { computed, ref } from 'vue'

import { setReceiptMode, state } from '../state/archive'

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
    :title="
      quiet
        ? 'Discreto: não devolve recibo de leitura, não avisa que você está digitando, e você não vê o “digitando” dos outros. A entrega ainda sai marcada como inativa, que os aparelhos recebem e não exibem.'
        : 'Normal: devolve recibo de leitura e avisa que você está digitando. Você aparece online.'
    "
    @click="toggle"
  >
    {{ quiet ? '🔇' : '🔔' }}
  </button>
</template>

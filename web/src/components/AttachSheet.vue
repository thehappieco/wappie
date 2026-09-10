<script setup lang="ts">
import { t } from '../ui/i18n'
import { computed } from 'vue'

import { losesAnimation, offer, planFor, unusualVoiceNote, type Choice } from '../media/plan'
import { bytes } from '../ui/format'
import AppIcon, { type IconName } from './AppIcon.vue'

// How to send this file.
//
// Asked rather than assumed, because the choices are not cosmetic. The same
// photograph is a compressed picture, a full-resolution picture or a document,
// and what our own archive keeps afterwards is whatever was sent — there is no
// second copy anywhere. The same recording is an audio file or a voice note,
// and a voice note is what counts as "ouvida" instead of "lida" on the other
// side.

const props = defineProps<{ file: File }>()
const emit = defineEmits<{
  (e: 'choose', choice: Choice): void
  (e: 'cancel'): void
}>()

const choices = computed(() => offer(props.file).map(planFor))

const choiceIcons: Record<Choice, IconName> = {
  photo: 'image',
  photo_hd: 'image',
  file: 'file',
  video: 'video',
  video_hd: 'video',
  gif: 'video',
  ptv: 'video',
  ptv_hd: 'video',
  audio: 'audio',
  voice: 'microphone',
  sticker: 'sticker',
}

/** A moving image about to be flattened. Worth saying before, not after. */
function flattens(choice: Choice): boolean {
  return losesAnimation(planFor(choice), props.file)
}

/**
 * A voice note made of something WhatsApp does not record voice notes as.
 *
 * Not refused — the message goes and most clients play it. But a phone that
 * will not play it says nothing about why, so the doubt belongs here.
 */
function unusual(choice: Choice): boolean {
  return unusualVoiceNote(planFor(choice), props.file)
}
</script>

<template>
  <div class="sheet">
    <div class="sheet-head">
      <div class="grow">
        <div class="sheet-name">{{ file.name }}</div>
        <div class="sheet-size">{{ bytes(file.size) || t('arquivo vazio') }}</div>
      </div>
      <button class="icon-btn" type="button" :title="t('Cancelar anexo')" :aria-label="t('Cancelar anexo')" @click="emit('cancel')"><AppIcon name="close" :size="20" /></button>
    </div>

    <button
      v-for="plan in choices"
      :key="plan.choice"
      class="sheet-choice"
      type="button"
      @click="emit('choose', plan.choice)"
    >
      <span class="sheet-label"><AppIcon :name="choiceIcons[plan.choice]" :size="20" /> {{ plan.label }}</span>
      <span class="sheet-note">
        {{ plan.note }}
        <template v-if="flattens(plan.choice)"> {{ t('· a animação se perde') }}</template>
        <template v-if="unusual(plan.choice)"> {{ t('· não é Opus; alguns aparelhos podem não tocar') }}</template>
      </span>
    </button>
  </div>
</template>

<style scoped>
.sheet-label {
  display: flex;
  align-items: center;
  gap: 8px;
}
</style>

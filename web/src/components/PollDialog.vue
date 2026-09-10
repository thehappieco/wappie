<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { state } from '../state/archive'
import { createPoll, pollValidation } from '../state/conversationActions'
import { t } from '../ui/i18n'

const emit = defineEmits<{ close: [] }>()
const dialog = ref<HTMLDialogElement>()
const questionInput = ref<HTMLTextAreaElement>()
const question = ref('')
let nextOption = 2
const options = ref([{ id: 0, text: '' }, { id: 1, text: '' }])
const multiple = ref(true)
const busy = ref(false)
const uncertain = ref(false)
const error = ref('')
const locked = computed(() => busy.value || uncertain.value)
const input = computed(() => ({ question: question.value.trim(), options: options.value.map(option => option.text.trim()), multiple: multiple.value }))
const forDevice = state.deviceID
const forChat = state.openChatKey
let disposed = false
let backdropPressed = false

function sameConversation() { return !disposed && state.deviceID === forDevice && state.openChatKey === forChat }
function characters(value: string) { return Array.from(value.trim()).length }
function dismiss() { if (!busy.value) emit('close') }
function backdropClick(event: MouseEvent) {
  if (backdropPressed && event.target === event.currentTarget) dismiss()
  backdropPressed = false
}

async function addOption() {
  if (locked.value || options.value.length >= 12) return
  const id = nextOption++
  options.value.push({ id, text: '' })
  error.value = ''
  await nextTick()
  dialog.value?.querySelector<HTMLInputElement>(`#poll-option-${id}`)?.focus()
}

async function removeOption(index: number) {
  if (locked.value || options.value.length <= 2) return
  options.value.splice(index, 1)
  error.value = ''
  const next = options.value[Math.min(index, options.value.length - 1)]
  await nextTick()
  dialog.value?.querySelector<HTMLInputElement>(`#poll-option-${next?.id}`)?.focus()
}

async function submit() {
  if (locked.value || !sameConversation()) return
  error.value = pollValidation(input.value)
  if (error.value) return
  busy.value = true
  try {
    const result = await createPoll(input.value)
    if (!sameConversation()) return
    if (result.ok || result.stale) { emit('close'); return }
    uncertain.value = Boolean(result.uncertain)
    error.value = result.error || (uncertain.value ? '' : t('Não foi possível enviar a enquete. Tente novamente.'))
  } catch {
    // A transport failure does not prove that WhatsApp rejected the poll.
    // Keep the submitted content visible, but never offer a blind resubmit.
    if (sameConversation()) { uncertain.value = true; error.value = '' }
  } finally { busy.value = false }
}

watch(() => [state.deviceID, state.openChatKey], () => {
  if (!sameConversation()) emit('close')
}, { flush: 'sync' })
watch(input, () => { if (!locked.value) error.value = '' })
onMounted(() => {
  dialog.value?.showModal()
  questionInput.value?.focus({ preventScroll: true })
})
onBeforeUnmount(() => { disposed = true; dialog.value?.close() })
</script>

<template>
  <dialog ref="dialog" class="poll-backdrop" aria-labelledby="poll-title" aria-describedby="poll-description"
    @cancel.prevent="dismiss" @close="!disposed && emit('close')"
    @pointerdown="backdropPressed = $event.target === $event.currentTarget" @click="backdropClick">
    <form class="poll-dialog" novalidate :aria-busy="busy" @submit.prevent="submit">
      <header class="poll-header">
        <span class="poll-symbol" aria-hidden="true"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M4 19V5m0 14h16M9 15v-4m5 4V5m5 10V8" /></svg></span>
        <div class="poll-heading"><h2 id="poll-title">{{ t('Criar enquete') }}</h2><p id="poll-description">{{ t('Faça uma pergunta e deixe a conversa escolher.') }}</p></div>
        <button class="icon-btn" type="button" :disabled="busy" :aria-label="t('Fechar')" :title="t('Fechar')" @click="dismiss"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18" /></svg></button>
      </header>

      <div class="poll-scroll">
        <fieldset :disabled="locked">
          <div class="poll-field">
            <div class="poll-label"><label for="poll-question">{{ t('Pergunta da enquete') }}</label><span id="poll-question-count" :class="{ over: characters(question) > 255 }">{{ characters(question) }}/255</span></div>
            <textarea id="poll-question" ref="questionInput" v-model="question" rows="2" :placeholder="t('O que você quer perguntar?')" aria-describedby="poll-question-count" :aria-invalid="characters(question) > 255" />
          </div>

          <section class="poll-options" aria-labelledby="poll-options-title" aria-describedby="poll-options-hint">
            <div class="poll-label"><h3 id="poll-options-title">{{ t('Opções de resposta') }}</h3><span>{{ options.length }}/12</span></div>
            <p id="poll-options-hint" class="poll-hint">{{ t('Adicione de 2 a 12 opções diferentes, com até 100 caracteres cada.') }}</p>
            <div v-for="(option, index) in options" :key="option.id" class="poll-option">
              <span class="poll-option-number" aria-hidden="true">{{ index + 1 }}</span>
              <div class="poll-option-field"><label class="poll-sr-only" :for="`poll-option-${option.id}`">{{ t('Opção {number}', { number: index + 1 }) }}</label><input :id="`poll-option-${option.id}`" v-model="option.text" type="text" autocomplete="off" :placeholder="t('Opção {number}', { number: index + 1 })" :aria-describedby="`poll-option-count-${option.id}`" :aria-invalid="characters(option.text) > 100" /><span :id="`poll-option-count-${option.id}`" class="poll-option-count" :class="{ over: characters(option.text) > 100 }">{{ characters(option.text) }}/100</span></div>
              <button v-if="options.length > 2" type="button" class="icon-btn poll-remove" :aria-label="t('Remover opção {number}', { number: index + 1 })" :title="t('Remover opção {number}', { number: index + 1 })" @click="removeOption(index)"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M5 12h14" /></svg></button>
            </div>
            <button v-if="options.length < 12" class="poll-add" type="button" @click="addOption"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M12 5v14M5 12h14" /></svg>{{ t('Adicionar opção') }}</button>
          </section>

          <label class="poll-multiple"><span><strong>{{ t('Permitir várias respostas') }}</strong><small>{{ multiple ? t('Cada pessoa pode escolher mais de uma opção.') : t('Cada pessoa pode escolher apenas uma opção.') }}</small></span><input v-model="multiple" type="checkbox" role="switch" /></label>
        </fieldset>

        <div v-if="error" class="alert" role="alert">{{ error }}</div>
        <div v-if="uncertain" class="poll-pending" role="status"><strong>{{ t('Confirmação pendente') }}</strong><p>{{ t('A enquete pode ter sido enviada. Feche esta janela e verifique a conversa antes de criar outra.') }}</p></div>
      </div>

      <footer class="poll-footer">
        <p v-if="busy" class="poll-hint" role="status">{{ t('Aguarde a confirmação do envio.') }}</p>
        <button class="ghost" type="button" :disabled="busy" @click="dismiss">{{ uncertain ? t('Fechar') : t('Cancelar') }}</button>
        <button class="primary poll-submit" type="submit" :disabled="locked">{{ busy ? t('Enviando enquete…') : uncertain ? t('Confirmação pendente') : t('Enviar enquete') }}</button>
      </footer>
    </form>
  </dialog>
</template>

<style scoped>
.poll-backdrop { position: fixed; inset: 0; width: 100%; height: 100dvh; max-width: none; max-height: none; padding: 20px; margin: 0; border: 0; background: transparent; display: none; place-items: center; overflow: hidden; box-sizing: border-box; }
.poll-backdrop[open] { display: grid; }.poll-backdrop::backdrop { background: #0009; backdrop-filter: blur(5px); }
.poll-dialog { display: flex; flex-direction: column; width: min(520px, 100%); max-height: min(90dvh, var(--app-height, 90dvh)); min-height: 0; overflow: hidden; background: var(--bg-panel); color: var(--text); border: 1px solid var(--line); border-radius: 22px; box-shadow: 0 24px 90px #0005; animation: poll-appear 160ms ease-out; }
.poll-header { display: flex; align-items: center; gap: 12px; padding: 20px; border-bottom: 1px solid var(--line); }.poll-symbol { display: grid; place-items: center; width: 44px; height: 44px; flex-shrink: 0; border-radius: 14px; color: var(--accent); background: var(--accent-dim); }.poll-heading { flex: 1; min-width: 0; }.poll-heading h2 { margin: 0 0 5px; font-size: 21px; }.poll-heading p { margin: 0; color: var(--text-dim); font-size: 13px; line-height: 1.4; }.poll-header .icon-btn { flex-shrink: 0; }
.poll-scroll { min-height: 0; overflow-y: auto; overscroll-behavior: contain; padding: 22px; }.poll-scroll fieldset { min-width: 0; border: 0; margin: 0; padding: 0; }.poll-field { display: grid; gap: 10px; }.poll-label { display: flex; justify-content: space-between; align-items: baseline; gap: 10px; }.poll-label label, .poll-label h3 { font-size: 14px; font-weight: 650; margin: 0; }.poll-label > span { font-size: 12px; color: var(--text-dim); font-variant-numeric: tabular-nums; }
.poll-dialog input[type=text], .poll-dialog textarea { font-size: 16px; border-color: var(--line-strong, var(--line)); border-radius: 12px; padding: 12px; box-sizing: border-box; min-width: 0; }.poll-dialog textarea { resize: vertical; min-height: 88px; max-height: 180px; }.poll-options { margin-top: 24px; }.poll-hint { color: var(--text-dim); font-size: 12px; line-height: 1.5; margin: 7px 0 14px; }.poll-option { display: flex; align-items: flex-start; gap: 8px; margin-top: 10px; }.poll-option-number { display: grid; place-items: center; flex-shrink: 0; width: 24px; height: 46px; font-size: 12px; color: var(--text-dim); }.poll-option-field { flex: 1; min-width: 0; }.poll-option-count { display: block; text-align: end; margin: 4px 2px 0; font-size: 11px; color: var(--text-dim); font-variant-numeric: tabular-nums; }.poll-remove { min-width: 40px; min-height: 44px; }.poll-add { display: flex; align-items: center; gap: 8px; color: var(--accent); font-weight: 600; min-height: 44px; padding: 8px 10px; border-radius: 10px; margin-top: 4px; }.poll-add:hover { background: var(--bg-hover); }
.poll-multiple { margin-top: 20px; border-top: 1px solid var(--line); padding-top: 20px; display: flex; align-items: center; justify-content: space-between; gap: 18px; cursor: pointer; }.poll-multiple strong { display: block; font-size: 14px; }.poll-multiple small { display: block; margin-top: 5px; line-height: 1.5; color: var(--text-dim); font-size: 12px; }.poll-multiple input { width: 22px; height: 22px; flex-shrink: 0; accent-color: var(--accent); cursor: pointer; }.poll-dialog .over { color: var(--danger); }.poll-pending { margin-top: 18px; padding: 14px; border-radius: 12px; border: 1px solid var(--line); background: var(--bg-raised); }.poll-pending p { margin: 6px 0 0; font-size: 13px; line-height: 1.5; color: var(--text-dim); }.poll-scroll .alert { margin-top: 16px; }
.poll-footer { flex-shrink: 0; border-top: 1px solid var(--line); padding: 16px 22px; display: flex; flex-wrap: wrap; align-items: center; justify-content: flex-end; gap: 10px; background: var(--bg-raised); }.poll-footer > .poll-hint { flex-basis: 100%; margin: 0; }.poll-footer button { min-height: 44px; }.poll-submit { padding: 10px 18px; }.poll-dialog button:disabled { cursor: default; opacity: .55; }.poll-sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
@keyframes poll-appear { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
@media (max-width: 600px) { .poll-backdrop { padding: 0; align-items: end; height: var(--app-height, 100dvh); top: var(--app-top, 0px); bottom: auto; }.poll-dialog { max-height: min(96dvh, var(--app-height, 96dvh)); border-radius: 22px 22px 0 0; }.poll-header { padding: 16px; }.poll-scroll { padding: 18px 16px; }.poll-footer { padding: 14px 16px max(14px, env(safe-area-inset-bottom)); }.poll-heading h2 { font-size: 19px; }.poll-symbol { width: 38px; height: 38px; } }
@media (prefers-reduced-motion: reduce) { .poll-dialog { animation: none; } }
</style>

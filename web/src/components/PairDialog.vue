<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { admin, cancelPairing, pair } from '../state/admin'
import { state } from '../state/archive'
import { t } from '../ui/i18n'
import QRCode from './QRCode.vue'
const open = ref(false)
const method = ref<'code' | 'qr'>('qr')
const phone = ref('')
const label = ref('')
const grantTo = ref<string[]>([])
const retry = computed(() => admin.pairingTarget)
function reset() {
  method.value = 'qr'; phone.value = ''; label.value = retry.value?.label || ''
  const me = admin.accounts.find(a => a.email === state.account)
  grantTo.value = me ? [me.id] : []
}
function start() { admin.pairingTarget = null; open.value = true; reset() }
function close() { cancelPairing(); admin.pairingTarget = null; open.value = false }
watch(() => admin.pairingTarget, target => { if (target) { open.value = true; reset() } })
onBeforeUnmount(() => { if (admin.pairing.phase === 'waiting') cancelPairing() })
const busy = computed(() => admin.pairing.phase === 'starting' || admin.pairing.phase === 'waiting')
const phoneLooksRight = computed(() => { const digits = phone.value.replace(/\D/g, ''); return digits.length >= 10 && digits.length <= 15 })
const canStart = computed(() => (method.value === 'qr' || phoneLooksRight.value) && (retry.value || grantTo.value.length > 0) && !busy.value)
function toggle(id: string) { grantTo.value = grantTo.value.includes(id) ? grantTo.value.filter(x => x !== id) : [...grantTo.value, id] }
async function submit() {
  await pair({ method: method.value, phone: phone.value.trim(), label: label.value.trim(), grantTo: grantTo.value,
    receiptMode: 'passive', existingDeviceID: retry.value?.id })
}
</script>

<template>
  <section class="console-panel" id="connect-number">
    <div class="console-panel-head"><h2>{{ retry ? t('Concluir conexão') : t('Conectar um número') }}</h2><button class="primary small" v-if="!open" @click="start">{{ t('Adicionar número') }}</button></div>
    <p v-if="!open" class="dim">{{ t('Conecte seu WhatsApp com um QR code ou um código no celular. Você escolhe quais membros poderão acessar as conversas.') }}</p>
    <form v-else-if="admin.pairing.phase === 'idle' || admin.pairing.phase === 'failed'" @submit.prevent="submit">
      <div class="alert" role="alert" v-if="admin.pairing.error">{{ admin.pairing.error }}</div>
      <p v-if="retry" class="hint">{{ t('A conexão será retomada com o nome, a chave e os acessos que já foram definidos para este número.') }}</p>
      <div class="field"><label>{{ t('Como conectar') }}</label><div class="choices"><label class="choice"><input type="radio" value="qr" v-model="method" /><span>{{ t('QR code — escaneie com o celular') }}</span></label><label class="choice"><input type="radio" value="code" v-model="method" /><span>{{ t('Código — digite no celular') }}</span></label></div></div>
      <div class="field" v-if="method === 'code'"><label for="pair-phone">{{ t('Número com código do país') }}</label><input id="pair-phone" v-model="phone" placeholder="+5511999999999" type="tel" autocomplete="tel" inputmode="tel" /></div>
      <div class="field" v-if="!retry"><label for="pair-label">{{ t('Nome interno (opcional)') }}</label><input id="pair-label" v-model="label" :placeholder="t('Ex.: Atendimento')" maxlength="100" autocomplete="off" /><span class="hint">{{ t('Você pode editar esse nome depois. O perfil do WhatsApp permanece igual.') }}</span></div>
      <div class="field" v-if="!retry"><label>{{ t('Quem poderá acessar as conversas') }}</label><div class="choices"><label v-for="a in admin.accounts" :key="a.id" class="choice"><input type="checkbox" :checked="grantTo.includes(a.id)" @change="toggle(a.id)" /><span>{{ a.email }}</span></label></div><span class="hint">{{ t('Os membros selecionados recebem acesso às conversas protegidas deste número. Outros acessos podem ser concedidos depois.') }}</span></div>

      <div class="row-actions"><button class="primary" type="submit" :disabled="!canStart">{{ method === 'qr' ? t('Gerar QR code') : t('Gerar código') }}</button><button class="ghost" type="button" @click="close">{{ t('Cancelar') }}</button></div>
    </form>
    <p v-else-if="admin.pairing.phase === 'starting'" class="dim">{{ t('Preparando conexão segura…') }}</p>
    <div v-else-if="admin.pairing.phase === 'waiting'" class="pairing">
      <p>{{ method === 'code' ? t('No WhatsApp do celular, abra Configurações → Aparelhos conectados → Conectar um aparelho → Conectar com número de telefone.') : t('No WhatsApp do celular, abra Configurações → Aparelhos conectados → Conectar um aparelho e escaneie o QR code.') }}</p>
      <div class="code" v-if="admin.pairing.code">{{ admin.pairing.code }}</div><QRCode v-else-if="admin.pairing.qr" :text="admin.pairing.qr" /><p class="dim" v-else>{{ t('Solicitando código ao WhatsApp…') }}</p>
      <p class="hint">{{ t('A conexão só é concluída depois da confirmação no celular. Se você cancelar ou o código expirar, o cadastro incompleto será removido.') }}</p><button class="ghost" @click="close">{{ t('Cancelar conexão') }}</button>
    </div>
    <div v-else-if="admin.pairing.phase === 'done'" class="pairing"><p><strong>{{ t('Número conectado!') }}</strong></p><p class="dim">{{ t('As novas mensagens já podem começar a chegar. O histórico anterior é sincronizado aos poucos, conforme o WhatsApp disponibiliza.') }}</p><button class="primary" @click="close">{{ t('Concluir') }}</button></div>
  </section>
</template>
<style scoped>
.reading-mode { border: 1px solid var(--line); border-radius: 12px; padding: 16px; margin: 18px 0; }.reading-mode legend { padding: 0 6px; font-weight: 600; }.hint { color: var(--text-dim); font-size: 13px; line-height: 1.6; }.field { margin: 18px 0; }.choices { gap: 10px; }.pairing { overflow-wrap: anywhere; }.pairing :deep(svg), .pairing :deep(canvas) { max-width: 100%; }.row-actions { flex-wrap: wrap; }
</style>

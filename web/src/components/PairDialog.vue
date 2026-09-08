<script setup lang="ts">
import { computed, ref } from 'vue'

import { admin, cancelPairing, pair } from '../state/admin'
import { state } from '../state/archive'
import QRCode from './QRCode.vue'

// Linking a WhatsApp number, from the browser.
//
// The screen is mostly one decision: who gets the key. It is asked before the
// pairing starts because the answer has to be sealed into the request — the
// grants exist before the device row does — and because it cannot be quietly
// defaulted to "everybody". A key per device buys separation between operators,
// and handing every account a copy at pairing time would spend it.

const open = ref(false)
const method = ref<'code' | 'qr'>('code')
const phone = ref('')
const label = ref('')
const active = ref(false)
const grantTo = ref<string[]>([])

/** The signed-in account starts selected: pairing a device you cannot read is rare. */
function reset() {
  method.value = 'code'
  phone.value = ''
  label.value = ''
  active.value = false
  const me = admin.accounts.find((a) => a.email === state.account)
  grantTo.value = me ? [me.id] : []
}

function start() {
  open.value = true
  reset()
}

function close() {
  if (admin.pairing.phase === 'waiting') cancelPairing()
  open.value = false
}

const busy = computed(
  () => admin.pairing.phase === 'starting' || admin.pairing.phase === 'waiting',
)

// WhatsApp wants the number in full international form. Checked here only to
// catch the obvious slip — a missing country code, a phone typed as a name.
// The server validates properly.
const phoneLooksRight = computed(() => {
  const digits = phone.value.replace(/\D/g, '')
  return digits.length >= 10 && digits.length <= 15
})

const canStart = computed(
  () =>
    (method.value === 'qr' || phoneLooksRight.value) && grantTo.value.length > 0 && !busy.value,
)

function toggle(id: string) {
  const at = grantTo.value.indexOf(id)
  if (at >= 0) grantTo.value.splice(at, 1)
  else grantTo.value.push(id)
}

async function submit() {
  await pair({
    method: method.value,
    phone: phone.value.trim(),
    label: label.value.trim(),
    grantTo: grantTo.value,
    receiptMode: active.value ? 'active' : 'passive',
  })
}

function done() {
  open.value = false
  cancelPairing()
}
</script>

<template>
  <section class="console-panel">
    <div class="console-panel-head">
      <h2>Conectar um número</h2>
      <button class="primary small" v-if="!open" @click="start">Adicionar número</button>
    </div>

    <div v-if="!open" class="dim">
      Conecte com um QR code ou um código no celular. Você escolhe quais contas terão acesso às
      conversas, que permanecem protegidas por criptografia.
    </div>

    <form v-else-if="admin.pairing.phase === 'idle' || admin.pairing.phase === 'failed'" @submit.prevent="submit">
      <div class="alert" v-if="admin.pairing.error">{{ admin.pairing.error }}</div>

      <div class="field">
        <label>Como conectar</label>
        <div class="choices">
          <label class="choice">
            <input type="radio" value="code" v-model="method" />
            <span>Código de 8 caracteres (digitado no celular)</span>
          </label>
          <label class="choice">
            <input type="radio" value="qr" v-model="method" />
            <span>QR code (lido pela câmera do celular)</span>
          </label>
        </div>
      </div>

      <div class="field" v-if="method === 'code'">
        <label for="pair-phone">Número, com país e DDD</label>
        <input id="pair-phone" v-model="phone" placeholder="+5511999999999" autocomplete="off" />
        <div class="hint">É o número do celular que vai aparecer em Aparelhos conectados.</div>
      </div>

      <div class="field">
        <label for="pair-label">Nome interno (opcional)</label>
        <input id="pair-label" v-model="label" placeholder="Comercial" autocomplete="off" />
      </div>

      <div class="field">
        <label>Quem poderá ler este arquivo</label>
        <div class="choices">
          <label v-for="a in admin.accounts" :key="a.id" class="choice">
            <input type="checkbox" :checked="grantTo.includes(a.id)" @change="toggle(a.id)" />
            <span>{{ a.email }}</span>
            <span class="dim">{{ a.role }}</span>
          </label>
        </div>
        <div class="hint">
          Só quem estiver marcado recebe a chave. Dá para conceder depois, mas para isso alguém
          precisa já ter a chave — se ninguém tiver, o arquivo fica ilegível para sempre.
        </div>
      </div>

      <label class="choice">
        <input type="checkbox" v-model="active" />
        <span>Confirmar leitura no WhatsApp (sai do modo discreto)</span>
      </label>

      <div class="row-actions">
        <button class="primary" type="submit" :disabled="!canStart">Gerar código</button>
        <button class="ghost" type="button" @click="close">Cancelar</button>
      </div>
    </form>

    <div v-else-if="admin.pairing.phase === 'starting'" class="dim">Criando a chave…</div>

    <div v-else-if="admin.pairing.phase === 'waiting'" class="pairing">
      <p v-if="method === 'code'">
        No celular: <b>Configurações → Aparelhos conectados → Conectar um aparelho →
        Conectar com número de telefone</b>.
      </p>
      <p v-else>
        No celular: <b>Configurações → Aparelhos conectados → Conectar um aparelho</b>, e aponte a
        câmera aqui.
      </p>

      <div class="code" v-if="admin.pairing.code">{{ admin.pairing.code }}</div>
      <QRCode v-else-if="admin.pairing.qr" :text="admin.pairing.qr" />
      <div class="dim" v-else>Pedindo o código ao WhatsApp…</div>

      <div class="dim" v-if="admin.pairing.qr">
        O código se renova sozinho a cada poucos segundos até alguém ler.
      </div>

      <p class="dim">
        A chave deste aparelho já foi selada para
        {{ admin.pairing.grantedTo.join(', ') }} e não existe mais neste navegador.
      </p>
      <button class="ghost" @click="close">Cancelar</button>
    </div>

    <div v-else-if="admin.pairing.phase === 'done'" class="pairing">
      <p><b>Conectado.</b> As mensagens começam a chegar seladas a partir de agora.</p>
      <p class="dim">
        O histórico anterior vem aos poucos, conforme o WhatsApp entrega — pode levar horas.
      </p>
      <button class="primary" @click="done">Pronto</button>
    </div>
  </section>
</template>

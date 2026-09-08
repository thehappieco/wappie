<script setup lang="ts">
import { ref } from 'vue'

import { computed } from 'vue'

import type { KeyScope } from '../api/protocol'
import { admin, createKey, dismissMintedKey, revokeKey } from '../state/admin'
import { stamp } from '../ui/format'

// API keys, and what they are not.
//
// A key lets a program reach the archive as ciphertext: list devices, follow
// the stream, fetch sealed rows. It holds no grant, so none of it opens. That
// distinction is worth stating on the screen, because "API key" reads like
// "access" and here it is only reach.
//
// What a key may do beyond reading is its scope, chosen here and enforced on
// the server. The narrowest is the default: a key that can send as the paired
// number is a key whose leak is a message to somebody's customers.

const name = ref('')
const scope = ref<KeyScope>('read')
/** The service account the key acts as; empty for a key with no account. */
const actsAs = ref('')
const confirming = ref('')

// A key that acts as a service account carries that account's grants: the
// system opens them with the private key it registered with, and reaches only
// the devices an owner granted it. That is the way to give a third party the
// archive — not a device key sent by hand.
const services = computed(() => admin.accounts.filter((a) => a.role === 'service'))

const scopes: { value: KeyScope; label: string; hint: string }[] = [
  { value: 'read', label: 'ler', hint: 'lista, acompanha e baixa o arquivo cifrado' },
  { value: 'send', label: 'enviar', hint: 'e também envia mensagens e anexos como o número' },
  { value: 'full', label: 'operar', hint: 'e também pareia, para aparelhos e pede histórico' },
]

async function mint() {
  const wanted = name.value.trim()
  if (!wanted) return
  await createKey(wanted, scope.value, actsAs.value)
  name.value = ''
  scope.value = 'read'
  actsAs.value = ''
}

function scopeLabel(s: string | undefined) {
  return scopes.find((x) => x.value === s)?.label ?? s ?? ''
}

function when(iso: string | undefined) {
  return iso ? new Date(iso) : undefined
}

async function revoke(prefix: string) {
  confirming.value = ''
  await revokeKey(prefix)
}
</script>

<template>
  <section class="console-panel">
    <h2>Tokens de API</h2>
    <p class="dim">
      Conecte seus sistemas ao Wappie com acessos separados. Escolha o que cada token poderá fazer.
      O conteúdo das conversas continua protegido pelas chaves concedidas à conta da integração.
    </p>

    <div class="alert" v-if="admin.keysError">{{ admin.keysError }}</div>

    <div class="minted" v-if="admin.minted">
      <div class="minted-head">Copie agora. Esta é a única vez que a chave aparece.</div>
      <code class="secret">{{ admin.minted.key }}</code>
      <button class="ghost" @click="dismissMintedKey">Já copiei</button>
    </div>

    <form class="token-form" @submit.prevent="mint">
      <label class="token-name">Nome do token<input v-model="name" placeholder="Ex.: integração de atendimento" /></label>
      <label>Permissão<select v-model="scope" :title="scopes.find((s) => s.value === scope)?.hint">
        <option v-for="s in scopes" :key="s.value" :value="s.value">{{ s.label }}</option>
      </select></label>
      <label v-if="services.length">Conta da integração<select v-model="actsAs" title="Conta de serviço cujas concessões a chave carrega">
        <option value="">Sem conta (dados cifrados)</option>
        <option v-for="s in services" :key="s.id" :value="s.id">age como {{ s.email }}</option>
      </select></label>
      <button class="primary small" type="submit" :disabled="!name.trim()">Gerar</button>
    </form>
    <p class="dim" v-if="services.length">
      Uma chave que <strong>age como</strong> uma conta de serviço carrega as concessões dela: o
      sistema abre os aparelhos concedidos com a chave privada que registrou, e nenhum outro.
    </p>
    <p class="dim">
      <template v-for="s in scopes" :key="s.value">
        <strong>{{ s.label }}</strong>: {{ s.hint }}.
      </template>
    </p>

    <div v-if="admin.keys.length" class="token-table"><table class="grid">
      <thead><tr><th>Token</th><th>Atividade</th><th>Acesso</th></tr></thead>
      <tbody>
        <tr v-for="k in admin.keys" :key="k.prefix" :class="{ dead: k.revoked_at }">
          <td data-label="Token">
            <div>
              {{ k.name }} <span class="pill">{{ scopeLabel(k.scope) }}</span>
              <span class="pill" v-if="k.acts_as">age como {{ k.acts_as }}</span>
            </div>
            <div class="dim mono">{{ k.prefix }}</div>
          </td>
          <td class="dim" data-label="Atividade">
            criada {{ stamp(when(k.created_at)) }}
            <template v-if="k.created_by"> por {{ k.created_by }}</template>
            <div v-if="k.last_used_at">usada {{ stamp(when(k.last_used_at)) }}</div>
            <div v-else>nunca usada</div>
          </td>
          <td class="right" data-label="Acesso">
            <span v-if="k.revoked_at" class="pill">revogada</span>
            <template v-else-if="confirming === k.prefix">
              <button class="danger small" @click="revoke(k.prefix)">Revogar mesmo</button>
              <button class="ghost small" @click="confirming = ''">Não</button>
            </template>
            <button v-else class="ghost small" @click="confirming = k.prefix">Revogar</button>
          </td>
        </tr>
      </tbody>
    </table></div>
    <div v-else class="tokens-empty">Nenhum token criado. Gere um para conectar seu primeiro sistema.</div>
    <p class="dim">Ao revogar um token, as conexões que o utilizam são encerradas imediatamente.</p>
  </section>
</template>

<style scoped>
.token-form { display: flex; flex-wrap: wrap; align-items: end; gap: 12px; }
.token-form label { display: flex; flex-direction: column; gap: 8px; min-width: 0; font-size: 12px; }
.token-form .token-name { flex: 1 1 240px; }
.token-form input, .token-form select { width: 100%; }
.token-form button { min-height: 42px; }
.token-table { overflow-x: auto; border: 1px solid var(--console-border, var(--line)); border-radius: 10px; }
.token-table table { min-width: 560px; }
.token-table th { text-align: left; }
.tokens-empty { padding: 26px 16px; text-align: center; font-size: 13px; color: var(--text-dim); border: 1px dashed var(--console-border, var(--line)); border-radius: 10px; }
@media (max-width: 760px) { .token-form label, .token-form .token-name { flex: 1 1 100%; } .token-form button { width: 100%; } }
@media (max-width: 600px) {
  .token-table { border: 0; border-radius: 0; overflow: visible; }
  .token-table table { display: block; min-width: 0; }
  .token-table thead { display: none; }
  .token-table tbody { display: grid; gap: 12px; }
  .token-table tr { display: block; border: 1px solid var(--console-border, var(--line)); border-radius: 10px; padding: 8px 14px; }
  .console-panel .token-table td { display: grid; gap: 8px; border: 0; padding: 10px 0; font-size: 12px; text-align: left; white-space: normal; overflow-wrap: anywhere; }
  .token-table td::before { content: attr(data-label); font-size: 10px; color: var(--text-dim); }
  .token-table .right button { width: 100%; }
  .token-table .pill { display: inline-block; margin-top: 5px; }
}
</style>

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
    <h2>Chaves de API</h2>
    <p class="dim">
      Para programas, não para pessoas. Uma chave alcança o arquivo cifrado — lista aparelhos,
      acompanha o fluxo, baixa linhas seladas — e não abre nada: quem abre é uma conta com
      concessão. Revogar derruba na hora as conexões que estão usando a chave.
    </p>

    <div class="alert" v-if="admin.keysError">{{ admin.keysError }}</div>

    <div class="minted" v-if="admin.minted">
      <div class="minted-head">Copie agora. Esta é a única vez que a chave aparece.</div>
      <code class="secret">{{ admin.minted.key }}</code>
      <button class="ghost" @click="dismissMintedKey">Já copiei</button>
    </div>

    <form class="inline" @submit.prevent="mint">
      <input v-model="name" placeholder="Para que serve (ex.: exportador de faturamento)" />
      <select v-model="scope" :title="scopes.find((s) => s.value === scope)?.hint">
        <option v-for="s in scopes" :key="s.value" :value="s.value">{{ s.label }}</option>
      </select>
      <select v-model="actsAs" v-if="services.length" title="Conta de serviço cujas concessões a chave carrega">
        <option value="">sem conta (só ciphertext)</option>
        <option v-for="s in services" :key="s.id" :value="s.id">age como {{ s.email }}</option>
      </select>
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

    <table class="grid" v-if="admin.keys.length">
      <tbody>
        <tr v-for="k in admin.keys" :key="k.prefix" :class="{ dead: k.revoked_at }">
          <td>
            <div>
              {{ k.name }} <span class="pill">{{ scopeLabel(k.scope) }}</span>
              <span class="pill" v-if="k.acts_as">age como {{ k.acts_as }}</span>
            </div>
            <div class="dim mono">{{ k.prefix }}</div>
          </td>
          <td class="dim">
            criada {{ stamp(when(k.created_at)) }}
            <template v-if="k.created_by"> por {{ k.created_by }}</template>
            <div v-if="k.last_used_at">usada {{ stamp(when(k.last_used_at)) }}</div>
            <div v-else>nunca usada</div>
          </td>
          <td class="right">
            <span v-if="k.revoked_at" class="pill">revogada</span>
            <template v-else-if="confirming === k.prefix">
              <button class="danger small" @click="revoke(k.prefix)">Revogar mesmo</button>
              <button class="ghost small" @click="confirming = ''">Não</button>
            </template>
            <button v-else class="ghost small" @click="confirming = k.prefix">Revogar</button>
          </td>
        </tr>
      </tbody>
    </table>
  </section>
</template>

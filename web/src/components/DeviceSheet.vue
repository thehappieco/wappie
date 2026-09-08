<script setup lang="ts">
import { computed, ref } from 'vue'

import {
  admin,
  canAdminister,
  closeDetail,
  grantAccess,
  removeDevice,
  revokeAccess,
} from '../state/admin'
import { state } from '../state/archive'
import { bytes, count, since, stamp } from '../ui/format'

// One device in full, and the only place that can destroy one.
//
// The delete asks for six characters of the device id to be typed. It is not
// ceremony: this removes every message, chat and attachment that device
// archived, nothing on the server can undo it, and a mis-click in a list is
// otherwise indistinguishable from an intention.

const confirming = ref(false)
const typed = ref('')
const unlink = ref(true)

const device = computed(() => admin.detail?.device)
const stats = computed(() => admin.detail?.stats)

/** The fragment somebody has to type. Short enough to copy by eye. */
const fragment = computed(() => device.value?.id.slice(0, 6) ?? '')

const armed = computed(() => typed.value.trim().toLowerCase() === fragment.value.toLowerCase())

function when(iso: string | undefined) {
  return iso ? new Date(iso) : undefined
}

async function destroy() {
  if (!device.value || !armed.value) return
  await removeDevice(device.value.id, unlink.value)
  confirming.value = false
  typed.value = ''
}

// Granting needs the device key, which does not survive signing in — so the
// password is asked for again here. That is the design and not a nuisance:
// handing an archive to another person is worth proving you are still the
// person who unlocked it.
const granting = ref(false)
const password = ref('')
const chosen = ref<string[]>([])
const revoking = ref('')

const readerIDs = computed(() => new Set(admin.detail?.readers?.map((r) => r.user_id) ?? []))
const candidates = computed(() => admin.accounts.filter((a) => !readerIDs.value.has(a.id)))
const iCanGrant = computed(() =>
  admin.detail ? readerIDs.value.has(myID.value) && canAdminister() : false,
)
const myID = computed(() => admin.accounts.find((a) => a.email === state.account)?.id ?? '')

function toggle(id: string) {
  const at = chosen.value.indexOf(id)
  if (at >= 0) chosen.value.splice(at, 1)
  else chosen.value.push(id)
}

async function grant() {
  if (!device.value) return
  await grantAccess(device.value.id, chosen.value, password.value)
  password.value = ''
  if (!admin.grantError) {
    granting.value = false
    chosen.value = []
  }
}

async function revoke(userID: string) {
  if (!device.value) return
  revoking.value = ''
  await revokeAccess(device.value.id, userID)
}

function dismiss() {
  confirming.value = false
  typed.value = ''
  closeDetail()
}
</script>

<template>
  <div class="sheet-backdrop" @click.self="dismiss">
    <div class="sheet">
      <div class="alert" v-if="admin.detailError">{{ admin.detailError }}</div>

      <template v-if="device">
        <header class="sheet-head">
          <div class="grow">
            <h2>{{ device.label || 'sem nome' }}</h2>
            <div class="dim mono">{{ device.id }}</div>
          </div>
          <button class="icon-btn" @click="dismiss" title="Fechar">✕</button>
        </header>

        <dl class="facts">
          <div><dt>Estado</dt><dd>{{ device.status }}<template v-if="device.status_reason"> — {{ device.status_reason }}</template></dd></div>
          <div><dt>Supervisionado agora</dt><dd>{{ device.running ? 'sim' : 'não' }}</dd></div>
          <div><dt>Número</dt><dd>{{ device.pn || '—' }}</dd></div>
          <div><dt>LID</dt><dd class="mono">{{ device.lid || '—' }}</dd></div>
          <div><dt>Nome no WhatsApp</dt><dd>{{ device.push_name || '—' }}</dd></div>
          <div><dt>Recibos</dt><dd>{{ device.receipt_mode === 'active' ? 'ativo' : 'discreto' }}</dd></div>
          <div><dt>Criado</dt><dd>{{ stamp(when(device.created_at)) }}</dd></div>
          <div>
            <dt>Última conexão</dt>
            <dd>
              {{ stamp(when(device.last_connected_at)) }}
              <span class="dim" v-if="device.last_connected_at">
                ({{ since(when(device.last_connected_at)) }})
              </span>
            </dd>
          </div>
          <div><dt>Geração da chave</dt><dd>{{ admin.detail?.epoch || 'sem chave' }}</dd></div>
          <div><dt>Arquivado</dt><dd>
            {{ count(stats?.messages) }} mensagens · {{ count(stats?.chats) }} conversas ·
            {{ count(stats?.media) }} anexos
            <span class="dim" v-if="stats?.media_bytes"> ({{ bytes(stats.media_bytes) }})</span>
          </dd></div>
        </dl>

        <h3>Quem consegue abrir</h3>
        <p class="dim">
          Tirar alguém daqui impede que volte a <b>obter</b> a chave. Não alcança o navegador de
          quem já abriu uma vez — para isso é preciso girar a geração da chave e resselar tudo.
        </p>
        <div class="alert" v-if="admin.grantError">{{ admin.grantError }}</div>

        <table class="grid" v-if="admin.detail?.readers?.length">
          <tbody>
            <tr v-for="r in admin.detail.readers" :key="r.user_id">
              <td>{{ r.email }}</td>
              <td class="dim">
                geração {{ r.epoch }} · desde {{ stamp(when(r.granted_at)) }}
                <template v-if="r.granted_by"> · por {{ r.granted_by }}</template>
              </td>
              <td class="right" v-if="canAdminister()">
                <template v-if="revoking === r.user_id">
                  <button class="danger small" :disabled="admin.grantBusy" @click="revoke(r.user_id)">
                    Tirar mesmo
                  </button>
                  <button class="ghost small" @click="revoking = ''">Não</button>
                </template>
                <button v-else class="ghost small" @click="revoking = r.user_id">Tirar</button>
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else class="alert">
          Ninguém. As mensagens que este aparelho arquivar não poderão ser lidas por conta nenhuma.
        </p>

        <template v-if="canAdminister() && candidates.length">
          <template v-if="!granting">
            <button class="ghost" :disabled="!iCanGrant" @click="granting = true">
              Dar acesso a outra conta
            </button>
            <p class="dim" v-if="!iCanGrant">
              Só quem já consegue abrir este aparelho pode conceder — a chave não está no servidor,
              está com quem tem acesso.
            </p>
          </template>

          <form v-else class="grant-form" @submit.prevent="grant">
            <div class="choices">
              <label v-for="a in candidates" :key="a.id" class="choice">
                <input type="checkbox" :checked="chosen.includes(a.id)" @change="toggle(a.id)" />
                <span>{{ a.email }}</span>
                <span class="dim">{{ a.role }}</span>
              </label>
            </div>
            <div class="field">
              <label for="grant-password">Sua senha</label>
              <input id="grant-password" type="password" v-model="password" autocomplete="current-password" />
              <div class="hint">
                A chave deste aparelho não fica guardada depois do login. Ela é recuperada agora,
                selada para quem você escolheu, e apagada em seguida.
              </div>
            </div>
            <div class="row-actions">
              <button class="primary" type="submit" :disabled="admin.grantBusy || !chosen.length || !password">
                {{ admin.grantBusy ? 'Selando…' : 'Conceder' }}
              </button>
              <button class="ghost" type="button" @click="granting = false">Cancelar</button>
            </div>
          </form>
        </template>

        <template v-if="canAdminister()">
          <h3>Excluir</h3>
          <p class="dim">
            Apaga o aparelho e tudo que ele arquivou: {{ count(stats?.messages) }} mensagens,
            {{ count(stats?.chats) }} conversas e {{ count(stats?.media) }} anexos. Não há como
            desfazer — nem aqui, nem no servidor.
          </p>

          <template v-if="!confirming">
            <button class="danger" @click="confirming = true">Excluir aparelho</button>
          </template>
          <template v-else>
            <label class="choice">
              <input type="checkbox" v-model="unlink" />
              <span>Desconectar também no WhatsApp (some de Aparelhos conectados)</span>
            </label>
            <div class="field">
              <label for="confirm-id">Digite <code>{{ fragment }}</code> para confirmar</label>
              <input id="confirm-id" v-model="typed" autocomplete="off" />
            </div>
            <div class="row-actions">
              <button class="danger" :disabled="!armed" @click="destroy">
                Excluir definitivamente
              </button>
              <button class="ghost" @click="confirming = false">Cancelar</button>
            </div>
          </template>
        </template>
      </template>

      <div v-else-if="admin.detailLoading" class="dim">Carregando…</div>

      <button v-else class="ghost" @click="dismiss">Fechar</button>
    </div>
  </div>
</template>

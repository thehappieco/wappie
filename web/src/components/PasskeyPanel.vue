<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { listPasskeys, passkeysAvailable, registerPasskey, removePasskey, type PasskeyInfo } from '../api/passkeys'
import { passkeyError } from '../api/webauthn'
import { credential, state } from '../state/archive'
import AppIcon from './AppIcon.vue'
import PasswordInput from './PasswordInput.vue'

const keys = ref<PasskeyInfo[]>([])
const available = ref(false)
const loaded = ref(false)
const adding = ref(false)
const removing = ref<PasskeyInfo | null>(null)
const label = ref('Minha passkey')
const password = ref('')
const busy = ref(false)
const error = ref('')
const done = ref('')
const abort = new AbortController()

async function refresh() {
  const c = credential()
  if (!c || c.kind !== 'session') return
  keys.value = await listPasskeys(c.serverURL, c.token)
}

onMounted(async () => {
  const c = credential()
  if (!c || c.kind !== 'session') return
  available.value = await passkeysAvailable(c.serverURL)
  try { await refresh() } catch { /* Password and recovery remain usable on an older server. */ }
  loaded.value = true
})
onBeforeUnmount(() => { abort.abort(); password.value = '' })

function edit(key?: PasskeyInfo) {
  if (busy.value) return
  adding.value = !key
  removing.value = key ?? null
  password.value = ''; error.value = ''; done.value = ''
}
function cancel() { if (!busy.value) { adding.value = false; removing.value = null; password.value = '' } }

async function submit(event: SubmitEvent) {
  if (busy.value) return
  const c = credential()
  if (!c || c.kind !== 'session') return
  const fields = new FormData(event.currentTarget as HTMLFormElement)
  password.value = String(fields.get('password') ?? '')
  busy.value = true; error.value = ''; done.value = ''
  try {
    if (removing.value) {
      await removePasskey({ serverURL: c.serverURL, token: c.token, email: state.account, password: password.value, id: removing.value.id })
      keys.value = keys.value.filter(k => k.id !== removing.value!.id)
      done.value = 'Passkey removida. As sessões abertas com ela foram encerradas.'
    } else {
      await registerPasskey({ serverURL: c.serverURL, token: c.token, email: state.account, password: password.value,
        label: label.value, signal: abort.signal })
      done.value = 'Passkey cadastrada. Na próxima entrada, escolha Entrar com passkey.'
      await refresh()
    }
    adding.value = false; removing.value = null
  } catch (e) { error.value = passkeyError(e) }
  finally { password.value = ''; busy.value = false }
}

function date(value?: string) { return value ? new Date(value).toLocaleDateString('pt-BR') : 'Ainda não utilizada' }
</script>

<template>
  <section class="passkey-card" aria-labelledby="passkey-title">
    <div class="passkey-heading">
      <span class="passkey-emblem"><AppIcon name="key" :size="23" /></span>
      <div><h3 id="passkey-title">Passkeys</h3><p>Entre com sua biometria ou PIN, mantendo seus dados protegidos.</p></div>
    </div>
    <div v-if="!loaded" class="dim" role="status">Verificando disponibilidade…</div>
    <p v-else-if="!available" class="dim">O cadastro de passkeys não está disponível neste navegador ou instalação. A entrada por senha continua disponível.</p>
    <ul v-if="keys.length" class="passkey-list">
      <li v-for="key in keys" :key="key.id">
        <div><strong>{{ key.label }}</strong><small>Criada em {{ date(key.created_at) }} · {{ key.last_used_at ? 'Último uso em ' + date(key.last_used_at) : 'Ainda não utilizada' }}</small></div>
        <button class="ghost small" type="button" :disabled="busy" :aria-label="'Remover passkey ' + key.label" @click="edit(key)">Remover</button>
      </li>
    </ul>
    <p v-else-if="loaded && available && !adding" class="dim">Nenhuma passkey cadastrada. Adicione sua primeira para entrar com mais facilidade.</p>
    <div v-if="error" class="alert" role="alert">{{ error }}</div>
    <div v-if="done" class="passkey-success" role="status">{{ done }}</div>
    <form v-if="adding || removing" class="passkey-form" name="wappie-passkey" autocomplete="on" method="post" @submit.prevent="submit">
      <input name="username" :value="state.account" type="email" autocomplete="username" class="account-identifier" readonly tabindex="-1" aria-hidden="true" />
      <template v-if="adding"><label for="passkey-label">Nome da passkey</label><input id="passkey-label" name="passkey-label" v-model="label" required maxlength="80" autocomplete="off" placeholder="Ex.: Meu iPhone" /></template>
      <p v-if="removing" class="dim">Remover “{{ removing.label }}”? Você poderá continuar entrando com a senha ou outra passkey.</p>
      <label for="passkey-password">Confirme sua senha atual</label>
      <PasswordInput id="passkey-password" name="password" v-model="password" required autocomplete="current-password" :disabled="busy" />
      <p v-if="adding" class="dim">Confirme sua identidade para vincular a passkey à sua conta. Seu dispositivo pode solicitar duas confirmações.</p>
      <div class="passkey-buttons"><button type="submit" class="primary small" :disabled="busy">{{ busy ? 'Aguarde…' : removing ? 'Remover passkey' : 'Continuar no dispositivo' }}</button><button class="ghost small" type="button" :disabled="busy" @click="cancel">Cancelar</button></div>
    </form>
    <button v-else-if="available" type="button" class="ghost small passkey-add" @click="edit()"><AppIcon name="plus" :size="17" /> Adicionar passkey</button>
  </section>
</template>

<style scoped>
.passkey-card { border: 1px solid var(--line); border-radius: 16px; padding: 22px; margin-top: 22px; }
.passkey-heading { display: flex; gap: 13px; align-items: center; }
.passkey-emblem { display: grid; place-items: center; width: 46px; height: 46px; flex: none; border-radius: 14px; color: var(--accent); background: var(--accent-dim); }
h3 { margin: 0; font-size: 1.05rem; } p { color: var(--text-dim); line-height: 1.5; font-size: 13px; margin: 6px 0 16px; }
.passkey-heading p { margin-bottom: 0; }
.passkey-list { list-style: none; padding: 0; margin: 18px 0; }
.passkey-list li { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 14px 0; border-bottom: 1px solid var(--line); }
.passkey-list small { display: block; color: var(--text-dim); font-size: 12px; margin-top: 4px; }
.passkey-form { display: grid; gap: 10px; max-width: 480px; margin-top: 18px; }
.passkey-form label { font-weight: 600; font-size: 13px; }.passkey-form p { margin-bottom: 0; }
.passkey-buttons { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 6px; }.passkey-add { display: inline-flex; align-items: center; gap: 8px; margin-top: 14px; }
.passkey-success { color: var(--accent); padding: 12px 0; font-size: 13px; }
.account-identifier { position: absolute; width: 1px; height: 1px; opacity: 0; pointer-events: none; padding: 0; border: 0; }
@media (max-width: 600px) { .passkey-card { padding: 17px; } .passkey-list li { align-items: flex-start; } .passkey-form input { font-size: 16px; } }
</style>

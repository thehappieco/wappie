<script setup lang="ts">
import { ref } from 'vue'

import {
  createVault,
  forgetVault,
  openOnce,
  unlock,
  VaultError,
  type Session,
  type StoredVault,
} from '../crypto/vault'

// The escape hatch, not the front door.
//
// One archive key, typed in, for a machine that should hold no account or for
// the case where the accounts layer itself is what is broken. It is also
// exactly how the first archive of this project was lost, which is why signing
// in is the default and this is a link at the bottom of it.
const props = defineProps<{ stored: StoredVault | null }>()
const emit = defineEmits<{ opened: [Session]; accounts: [] }>()

const stored = ref<StoredVault | null>(props.stored)
const busy = ref(false)
const error = ref('')

// Enrolment
const label = ref('arquivo')
const serverURL = ref('')
const apiKey = ref('')
const archiveKey = ref('')
const passphrase = ref('')
const confirm = ref('')
const remember = ref(true)

async function doUnlock() {
  busy.value = true
  error.value = ''
  try {
    emit('opened', await unlock(passphrase.value))
  } catch (err) {
    error.value = describe(err)
  } finally {
    busy.value = false
  }
}

async function doEnrol() {
  busy.value = true
  error.value = ''
  try {
    if (remember.value && passphrase.value !== confirm.value) {
      throw new VaultError('as senhas não conferem', 'passphrase')
    }
    const session = remember.value
      ? await createVault({
          label: label.value,
          serverURL: serverURL.value,
          apiKey: apiKey.value,
          archiveKey: archiveKey.value,
          passphrase: passphrase.value,
        })
      : await openOnce({
          serverURL: serverURL.value,
          apiKey: apiKey.value,
          archiveKey: archiveKey.value,
        })
    // The key was handed to the session; nothing keeps the typed copy.
    archiveKey.value = ''
    passphrase.value = ''
    confirm.value = ''
    emit('opened', session)
  } catch (err) {
    error.value = describe(err)
  } finally {
    busy.value = false
  }
}

async function forget() {
  if (!window.confirm('Apagar a chave guardada neste navegador? Você precisará colá-la de novo.')) {
    return
  }
  await forgetVault()
  stored.value = null
}

function describe(err: unknown): string {
  if (err instanceof Error) return err.message
  return String(err)
}
</script>

<template>
  <div>
    <div>
      <template v-if="stored">
        <h1>{{ stored.label }}</h1>
        <p class="sub">A chave do arquivo está guardada neste navegador, selada por senha.</p>

        <div class="alert" v-if="error">{{ error }}</div>

        <form @submit.prevent="doUnlock">
          <div class="field">
            <label for="pass">Senha</label>
            <input
              id="pass"
              v-model="passphrase"
              type="password"
              autocomplete="current-password"
              autofocus
            />
          </div>
          <button class="primary" type="submit" :disabled="busy || !passphrase">
            {{ busy ? 'Abrindo…' : 'Abrir o arquivo' }}
          </button>
        </form>

        <button class="linkish" @click="forget">Esquecer esta chave neste navegador</button>
        <br />
        <button class="linkish" @click="emit('accounts')">Entrar com e-mail e senha</button>
      </template>

      <template v-else>
        <h1>Abrir o arquivo</h1>
        <p class="sub">
          O servidor guarda tudo selado e não consegue abrir nada. A chave privada vive aqui, neste
          navegador, e em nenhum outro lugar.
        </p>

        <div class="alert" v-if="error">{{ error }}</div>

        <form @submit.prevent="doEnrol">
          <div class="field">
            <label for="server">Servidor</label>
            <input id="server" v-model="serverURL" placeholder="mesma origem desta página" />
            <p class="hint">Deixe vazio para usar o servidor que serviu esta página.</p>
          </div>

          <div class="field">
            <label for="apikey">Chave de API</label>
            <input id="apikey" v-model="apiKey" type="password" autocomplete="off" />
          </div>

          <div class="field">
            <label for="archive">Chave do arquivo</label>
            <textarea
              id="archive"
              v-model="archiveKey"
              rows="2"
              autocomplete="off"
              spellcheck="false"
              placeholder="base64 ou hexadecimal, 32 bytes"
            />
            <p class="hint">
              É a chave de <strong>um aparelho</strong>, não do tenant: cada conta WhatsApp tem a
              sua, e quem tem uma não abre a outra. Nada no servidor consegue recuperá-la.
            </p>
          </div>

          <div class="field">
            <label>
              <input type="checkbox" v-model="remember" style="width: auto; margin-right: 8px" />
              Lembrar neste navegador, protegida por senha
            </label>
          </div>

          <template v-if="remember">
            <div class="field">
              <label for="label">Nome deste arquivo</label>
              <input id="label" v-model="label" />
            </div>
            <div class="field">
              <label for="new-pass">Senha</label>
              <input id="new-pass" v-model="passphrase" type="password" autocomplete="new-password" />
              <p class="hint">Mínimo de 8 caracteres. É o que protege a chave em repouso.</p>
            </div>
            <div class="field">
              <label for="confirm">Repita a senha</label>
              <input id="confirm" v-model="confirm" type="password" autocomplete="new-password" />
            </div>
          </template>

          <button class="primary" type="submit" :disabled="busy || !apiKey || !archiveKey">
            {{ busy ? 'Abrindo…' : remember ? 'Guardar e abrir' : 'Abrir só desta vez' }}
          </button>
        </form>

        <button class="linkish" @click="emit('accounts')">Entrar com e-mail e senha</button>

        <p class="note">
          Perder a chave é perder o arquivo, para todo mundo, inclusive para quem opera o servidor.
          Uma conta evita isso: a chave do aparelho fica selada para você, e há um código de
          recuperação atrás dela.
        </p>
      </template>
    </div>
  </div>
</template>

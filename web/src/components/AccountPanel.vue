<script setup lang="ts">
import { ref } from 'vue'

import { AuthError, changePassword, MinPassword, setRecovery } from '../api/auth'
import { credential, recoverySet, rotateCredential, state } from '../state/archive'

// The account: its password, and the one thing that survives forgetting it.
//
// Both operations ask for the current password again, even though the person
// is signed in. A tab somebody walked away from is not the same as knowing the
// password, and these two are exactly what an intruder at that tab would want.

const current = ref('')
const next = ref('')
const confirm = ref('')
const forCode = ref('')
const busy = ref(false)
const error = ref('')
const done = ref('')

/** Shown once after it is generated, and never retrievable again. */
const recoveryCode = ref('')
const acknowledged = ref(false)

function describe(err: unknown): string {
  if (err instanceof AuthError) return err.message
  if (err instanceof Error) return err.message
  return String(err)
}

async function rotatePassword() {
  const cred = credential()
  if (!cred) return
  error.value = ''
  done.value = ''
  if (next.value !== confirm.value) {
    error.value = 'as senhas não conferem'
    return
  }
  busy.value = true
  try {
    const fresh = await changePassword({
      serverURL: cred.serverURL,
      token: cred.token,
      email: state.account,
      current: current.value,
      next: next.value,
    })
    rotateCredential(fresh.token)
    current.value = ''
    next.value = ''
    confirm.value = ''
    done.value = 'Senha trocada. Toda outra sessão desta conta foi encerrada.'
  } catch (err) {
    error.value = describe(err)
  } finally {
    busy.value = false
  }
}

async function generateCode() {
  const cred = credential()
  if (!cred) return
  error.value = ''
  done.value = ''
  busy.value = true
  try {
    recoveryCode.value = await setRecovery({
      serverURL: cred.serverURL,
      token: cred.token,
      email: state.account,
      password: forCode.value,
    })
    forCode.value = ''
    acknowledged.value = false
    recoverySet()
  } catch (err) {
    error.value = describe(err)
  } finally {
    busy.value = false
  }
}

async function copyCode() {
  try {
    await navigator.clipboard.writeText(recoveryCode.value)
  } catch {
    // Clipboard refused. The code is on screen; it can be typed.
  }
}
</script>

<template>
  <section class="console-panel" v-if="state.account">
    <h2>Conta</h2>
    <p class="dim">{{ state.account }}</p>

    <div class="alert" v-if="error">{{ error }}</div>
    <div class="removed" v-if="done">{{ done }}</div>

    <div class="minted" v-if="recoveryCode">
      <div class="minted-head">Guarde este código. É a única forma de voltar sem a senha.</div>
      <code class="secret">{{ recoveryCode }}</code>
      <button class="ghost small" @click="copyCode">Copiar</button>
      <label class="dim">
        <input type="checkbox" v-model="acknowledged" style="width: auto; margin-right: 8px" />
        Anotei em um lugar seguro
      </label>
      <button class="ghost small" :disabled="!acknowledged" @click="recoveryCode = ''">Fechar</button>
    </div>

    <div class="alert" v-else-if="!state.hasRecovery">
      Esta conta não tem um código de recuperação que funcione. Se a senha for esquecida, o arquivo
      fica ilegível — para todo mundo, inclusive quem opera o servidor. Gere um agora.
    </div>

    <form class="inline" @submit.prevent="generateCode" v-if="!recoveryCode">
      <input
        v-model="forCode"
        type="password"
        autocomplete="current-password"
        placeholder="Senha atual"
      />
      <button class="primary small" type="submit" :disabled="busy || !forCode">
        {{ state.hasRecovery ? 'Gerar um novo código de recuperação' : 'Gerar código de recuperação' }}
      </button>
    </form>

    <h3>Trocar a senha</h3>
    <p class="dim">
      Mínimo de {{ MinPassword }} caracteres. A troca encerra toda sessão aberta desta conta, em
      qualquer navegador, inclusive esta — que é reaberta com a senha nova.
    </p>
    <form class="stack" @submit.prevent="rotatePassword">
      <input v-model="current" type="password" autocomplete="current-password" placeholder="Senha atual" />
      <input v-model="next" type="password" autocomplete="new-password" placeholder="Nova senha" />
      <input v-model="confirm" type="password" autocomplete="new-password" placeholder="Repita a nova senha" />
      <button class="primary small" type="submit" :disabled="busy || !current || !next || !confirm">
        {{ busy ? 'Derivando…' : 'Trocar a senha' }}
      </button>
    </form>
  </section>
</template>

<style scoped>
.stack {
  display: grid;
  gap: 8px;
  max-width: 420px;
}
h3 {
  margin: 20px 0 4px;
  font-size: 1rem;
}
</style>

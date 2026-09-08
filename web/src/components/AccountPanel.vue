<script setup lang="ts">
import { ref } from 'vue'

import { AuthError, changePassword, MinPassword, setRecovery } from '../api/auth'
import { credential, recoverySet, rotateCredential, state } from '../state/archive'
import PasswordInput from './PasswordInput.vue'
import PasskeyPanel from './PasskeyPanel.vue'

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

async function rotatePassword(event: SubmitEvent) {
  if (busy.value) return
  const fields = new FormData(event.currentTarget as HTMLFormElement)
  current.value = String(fields.get('password') ?? '')
  next.value = String(fields.get('new-password') ?? '')
  confirm.value = String(fields.get('confirm-password') ?? '')
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

async function generateCode(event: SubmitEvent) {
  if (busy.value) return
  forCode.value = String(new FormData(event.currentTarget as HTMLFormElement).get('password') ?? '')
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
  <section class="console-panel account-settings" v-if="state.account">
    <h2>Acesso e segurança</h2>
    <p class="dim">Gerencie as formas de entrar na conta {{ state.account }}.</p>
    <PasskeyPanel />

    <div class="alert" v-if="error" role="alert">{{ error }}</div>
    <div class="removed" v-if="done" role="status">{{ done }}</div>

    <section class="security-card">
      <h3>Código de recuperação</h3>
      <p class="dim">Uma forma de recuperar o acesso caso você perca sua senha e suas passkeys. Guarde-o em um lugar seguro.</p>
      <div class="minted" v-if="recoveryCode">
        <div class="minted-head">Anote este código. Ele não será mostrado novamente.</div>
        <code class="secret">{{ recoveryCode }}</code>
        <button class="ghost small" type="button" @click="copyCode">Copiar</button>
        <label class="dim"><input type="checkbox" v-model="acknowledged" style="width: auto; margin-right: 8px" /> Anotei em um lugar seguro</label>
        <button class="ghost small" type="button" :disabled="!acknowledged" @click="recoveryCode = ''">Fechar</button>
      </div>
      <div class="alert" v-else-if="!state.hasRecovery">Sua conta ainda não tem um código de recuperação. Gere um para proteger seu acesso.</div>
      <form class="security-form" name="wappie-recovery" method="post" autocomplete="on" @submit.prevent="generateCode" v-if="!recoveryCode">
        <input name="username" :value="state.account" type="email" autocomplete="username" class="account-identifier" readonly tabindex="-1" aria-hidden="true" />
        <label for="recovery-password">Confirme sua senha atual</label>
        <PasswordInput id="recovery-password" name="password" v-model="forCode" required autocomplete="current-password" :disabled="busy" />
        <button class="ghost small" type="submit" :disabled="busy">{{ busy ? 'Aguarde…' : state.hasRecovery ? 'Gerar novo código' : 'Gerar código de recuperação' }}</button>
      </form>
    </section>

    <section class="security-card">
      <h3>Senha</h3>
      <p class="dim">Use pelo menos {{ MinPassword }} caracteres. Ao trocar a senha, suas outras sessões serão encerradas. As passkeys cadastradas continuam válidas.</p>
      <form class="security-form" name="wappie-password-change" method="post" autocomplete="on" @submit.prevent="rotatePassword">
        <input name="username" :value="state.account" type="email" autocomplete="username" class="account-identifier" readonly tabindex="-1" aria-hidden="true" />
        <label for="current-password">Senha atual</label>
        <PasswordInput id="current-password" name="password" v-model="current" required autocomplete="current-password" :disabled="busy" />
        <label for="new-password">Nova senha</label>
        <PasswordInput id="new-password" name="new-password" v-model="next" required :minlength="MinPassword" autocomplete="new-password" :disabled="busy" />
        <label for="confirm-password">Repita a nova senha</label>
        <PasswordInput id="confirm-password" name="confirm-password" v-model="confirm" required autocomplete="new-password" :disabled="busy" />
        <button class="primary small" type="submit" :disabled="busy">{{ busy ? 'Atualizando…' : 'Atualizar senha' }}</button>
      </form>
    </section>
  </section>
</template>

<style scoped>
.security-card { border: 1px solid var(--line); border-radius: 16px; padding: 22px; margin-top: 20px; }
.security-card h3 { margin: 0 0 8px; font-size: 1.05rem; }
.security-card p { line-height: 1.6; margin: 0 0 18px; }
.security-form { display: grid; gap: 10px; max-width: 480px; }
.security-form label { font-size: 13px; font-weight: 600; }
.security-form button { justify-self: start; margin-top: 4px; }
.account-identifier { position: absolute; width: 1px; height: 1px; opacity: 0; pointer-events: none; padding: 0; border: 0; }
@media (max-width: 600px) { .security-card { padding: 17px; } }
</style>

<script setup lang="ts">
import { t } from '../ui/i18n'
import AppearanceMenu from './AppearanceMenu.vue'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

import { AuthError, joinInvitedWorkspace, recover, registerService, sendSignupVerification, signIn, signOut, signUp, signupConfig, type SignedIn, type SignInStep } from '../api/auth'
import { loadVault, type StoredVault } from '../crypto/vault'
import { fromAccount, type Session } from '../state/session'
import PastedKeyView from './PastedKeyView.vue'
import PasswordInput from './PasswordInput.vue'
import AppIcon from './AppIcon.vue'
import { passkeysAvailable, signInWithPasskey } from '../api/passkeys'
import { passkeyError } from '../api/webauthn'
import { signupLink } from '../ui/signupLink'

const emit = defineEmits<{ opened: [Session] }>()

type Mode = 'sign-in' | 'sign-up' | 'recover' | 'service' | 'pasted-key'

const mode = ref<Mode>('sign-in')
const busy = ref(false)
const error = ref('')
const passkeyAvailable = ref(false)
const passkeyBusy = ref(false)
const passkeyAbort = new AbortController()
const loginStep = ref<SignInStep>('checking')
const loginDetail = computed(() => {
  switch (loginStep.value) {
    case 'checking': return t('Conectando à sua conta…')
    case 'unlocking': return t('Desbloqueando sua conta…')
    case 'authenticating': return t('Confirmando seu acesso…')
    case 'passkey': return t('Confirme no seu dispositivo…')
    case 'opening': return t('Preparando sua sessão…')
  }
})

const serverURL = ref('')
const hosted = typeof location !== 'undefined' && ['app.wappie.thehappie.co','console.wappie.thehappie.co'].includes(location.hostname)
const selectedWorkspace = typeof location === 'undefined' ? undefined : new URLSearchParams(location.search).get('workspace') || undefined
const email = ref('')
const password = ref('')
const confirm = ref('')
const invite = ref('')
const displayName = ref('')
const verification = ref('')
const signupEnabled = ref(false)
const sendingVerification = ref(false)
const verificationSent = ref(false)
if (typeof location !== 'undefined') {
  const linked = signupLink(location.href)
  if (linked.signup) mode.value = 'sign-up'
  invite.value = linked.invite
  email.value = linked.email
  verification.value = linked.verification
  if (linked.invite || linked.verification) history.replaceState(history.state, '', linked.cleanURL)
}
/** The recovery code somebody is typing back, on the way in. */
const code = ref('')
/** A system registering: its name and the public half of its keypair. */
const serviceName = ref('')
const servicePublicKey = ref('')
const registered = ref('')

/** Shown once, after signing up, and never retrievable again. */
const recoveryCode = ref('')
const pending = ref<Session | null>(null)
const acknowledged = ref(false)

const storedKey = ref<StoredVault | null>(null)

onMounted(async () => {
  void refreshPasskeyAvailability()
  void refreshSignupConfig()
  try {
    storedKey.value = await loadVault()
    // A browser that already holds a pasted key goes straight to that screen:
    // whoever set it up chose it deliberately.
    if (storedKey.value && mode.value === 'sign-in') mode.value = 'pasted-key'
  } catch {
    // No vault, or no IndexedDB. Signing in does not need one.
  }
})
onBeforeUnmount(() => passkeyAbort.abort())

async function refreshPasskeyAvailability() {
  const server = serverURL.value
  const available = await passkeysAvailable(server)
  if (serverURL.value === server) passkeyAvailable.value = available
}

async function refreshSignupConfig() {
  const server = serverURL.value
  try { const config = await signupConfig(server); if (serverURL.value === server) signupEnabled.value = config.enabled }
  catch { if (serverURL.value === server) signupEnabled.value = false }
}

async function requestVerification() {
  if (sendingVerification.value || busy.value) return
  sendingVerification.value = true; error.value = ''; verificationSent.value = false
  try { await sendSignupVerification(serverURL.value, email.value); verificationSent.value = true }
  catch (err) { error.value = describe(err) }
  finally { sendingVerification.value = false }
}

async function acceptPendingInvite(signed: SignedIn): Promise<SignedIn> {
  if (!invite.value.trim()) return signed
  try {
    const joined = await joinInvitedWorkspace(serverURL.value, signed, invite.value)
    invite.value = ''
    await signOut(serverURL.value, signed.token)
    return joined
  } catch (err) { await signOut(serverURL.value, signed.token); throw err }
}

async function openWithPasskey() {
  if (busy.value) return
  busy.value = true; passkeyBusy.value = true; error.value = ''
  loginStep.value = 'checking'
  try {
    const signedIn = await acceptPendingInvite(await signInWithPasskey({ serverURL: serverURL.value, tenantID: selectedWorkspace, signal: passkeyAbort.signal,
      onProgress: step => { loginStep.value = step } }))
    password.value = ''
    emit('opened', fromAccount(signedIn, serverURL.value))
  } catch (e) { error.value = passkeyError(e) }
  finally { busy.value = false; passkeyBusy.value = false }
}

const title = computed(() => {
  switch (mode.value) {
    case 'sign-up':
      return t('Criar conta')
    case 'recover':
      return t('Recuperar a conta')
    case 'service':
      return t('Registrar um sistema')
    default:
      return t('Entrar')
  }
})

function submit(event: SubmitEvent) {
  if (busy.value) return
  // Safari and Chrome can autofill without a Vue input event. Read the named
  // native fields at submit time, and let native validation handle emptiness.
  const form = event.currentTarget as HTMLFormElement
  const values = new FormData(form)
  if (values.has('username')) email.value = String(values.get('username') ?? '')
  if (values.has('password')) password.value = String(values.get('password') ?? '')
  if (values.has('confirm-password')) confirm.value = String(values.get('confirm-password') ?? '')
  if (values.has('display-name')) displayName.value = String(values.get('display-name') ?? '')
  if (values.has('email-verification')) verification.value = String(values.get('email-verification') ?? '')
  if (values.has('invite')) invite.value = String(values.get('invite') ?? '')
  if (mode.value === 'sign-up') return doSignUp()
  if (mode.value === 'recover') return doRecover()
  if (mode.value === 'service') return doRegisterService()
  return doSignIn()
}

/**
 * doRegisterService sends a name and a public key, and nothing else. There is
 * no session to open afterwards: the system reads through an API key an
 * owner mints for it once the devices have been granted.
 */
async function doRegisterService() {
  busy.value = true
  error.value = ''
  try {
    const result = await registerService({
      serverURL: serverURL.value,
      invite: invite.value,
      name: serviceName.value,
      publicKey: servicePublicKey.value,
    })
    registered.value = result.name
    invite.value = ''
    servicePublicKey.value = ''
  } catch (err) {
    error.value = describe(err)
  } finally {
    busy.value = false
  }
}

function switchTo(next: Mode) {
  if (busy.value) return
  mode.value = next
  error.value = ''
}

async function doSignIn() {
  busy.value = true
  loginStep.value = 'checking'
  error.value = ''
  try {
    const signedIn = await acceptPendingInvite(await signIn({
      tenantID: selectedWorkspace,
      serverURL: serverURL.value,
      email: email.value,
      password: password.value,
      onProgress: step => { loginStep.value = step },
    }))
    password.value = ''
    emit('opened', fromAccount(signedIn, serverURL.value))
  } catch (err) {
    error.value = describe(err)
  } finally {
    busy.value = false
  }
}

async function doSignUp() {
  busy.value = true
  error.value = ''
  try {
    if (password.value !== confirm.value) {
      throw new AuthError('password', t('as senhas não conferem'))
    }
    const result = await signUp({
      serverURL: serverURL.value,
      invite: invite.value,
      email: email.value,
      password: password.value,
      displayName: displayName.value,
      emailVerificationToken: verification.value,
    })
    password.value = ''
    confirm.value = ''
    // Held back until the recovery code has been seen. Handing somebody the
    // application first is how the code gets closed without being written
    // down, and that is the failure this whole layer exists to prevent.
    recoveryCode.value = result.recoveryCode
    pending.value = fromAccount(result.session, serverURL.value)
  } catch (err) {
    error.value = describe(err)
  } finally {
    busy.value = false
  }
}

/**
 * doRecover trades a recovery code for a new password.
 *
 * The code is spent by being typed here, so a new one comes back and is shown
 * the same way the first was: before the archive, with nothing else on screen.
 */
async function doRecover() {
  busy.value = true
  error.value = ''
  try {
    if (password.value !== confirm.value) {
      throw new AuthError('password', t('as senhas não conferem'))
    }
    const result = await recover({
      serverURL: serverURL.value,
      email: email.value,
      code: code.value,
      password: password.value,
    })
    password.value = ''
    confirm.value = ''
    code.value = ''
    recoveryCode.value = result.recoveryCode
    pending.value = fromAccount(result.session, serverURL.value)
  } catch (err) {
    error.value = describe(err)
  } finally {
    busy.value = false
  }
}

function enter() {
  if (!pending.value) return
  emit('opened', pending.value)
}

async function copyCode() {
  try {
    await navigator.clipboard.writeText(recoveryCode.value)
  } catch {
    // Clipboard refused. The code is on screen; it can be typed.
  }
}

function describe(err: unknown): string {
  if (err instanceof AuthError) return err.message
  if (err instanceof Error) return err.message
  return String(err)
}
</script>

<template>
  <div class="unlock">
    <div v-if="busy && mode === 'sign-in'" class="unlock-card auth-progress" role="status" aria-live="polite" :data-step="loginStep">
      <div class="loading-spinner" aria-hidden="true" />
      <h1>{{ t('Entrando com segurança…') }}</h1>
      <p class="sub">{{ loginDetail }}</p>
    </div>
    <!-- The recovery code. Nothing else is on screen while it is. -->
    <div class="unlock-card" v-else-if="recoveryCode">
      <h1>{{ t('Guarde este código') }}</h1>
      <p class="sub"> {{ t('Use este código para recuperar sua conta se perder a senha e suas passkeys. Ele não pode ser mostrado de novo.') }} </p>

      <div class="recovery">{{ recoveryCode }}</div>

      <button class="ghost" style="width: 100%; margin-bottom: 14px" @click="copyCode"> {{ t('Copiar') }} </button>

      <div class="field">
        <label>
          <input type="checkbox" v-model="acknowledged" style="width: auto; margin-right: 8px" /> {{ t('Anotei em um lugar seguro') }} </label>
      </div>

      <button class="primary" :disabled="!acknowledged" @click="enter">{{ t('Continuar') }}</button>

      <p class="note"> {{ t('Guarde uma cópia em um lugar seguro, separado dos dispositivos que você usa para entrar.') }} </p>
    </div>

    <div class="unlock-card" v-else-if="mode === 'pasted-key'">
      <PastedKeyView
        :stored="storedKey"
        @opened="(s: Session) => emit('opened', s)"
        @accounts="mode = 'sign-in'"
      />
    </div>

    <div class="unlock-card" v-else-if="registered">
      <h1>{{ t('Sistema registrado') }}</h1>
      <p class="sub">
        <strong>{{ registered }}</strong> {{ t('agora existe nesta instalação, com a chave pública que você colou. Ele ainda não lê nada: peça a um administrador que conceda os aparelhos a ele no console e gere uma chave de API que') }} <em>{{ t('aja como') }}</em> {{ t('essa conta. As concessões abrem só com a chave privada que ficou no sistema.') }} </p>
      <button class="primary" @click="((registered = ''), switchTo('sign-in'))">{{ t('Voltar') }}</button>
    </div>

    <div class="unlock-card" v-else>
      <div class="auth-appearance"><AppearanceMenu /></div>
      <div class="auth-wordmark">{{ t('wappie') }}<span>●</span></div>
      <h1>{{ title }}</h1>
      <p class="sub" v-if="mode === 'service'"> {{ t('Um sistema não tem senha: tem um par de chaves. Gere-o com') }} <code>wsctl service-key</code>{{ t(', guarde a metade privada onde o sistema guarda segredos, e cole aqui a pública. O servidor sela para ela as chaves dos aparelhos que um administrador conceder.') }} </p>
      <p class="sub" v-else-if="mode === 'recover'"> {{ t('O código de recuperação abre a mesma chave que a senha abria. Ele é gasto ao ser digitado aqui: a conta ganha uma senha nova e um código novo, e toda sessão aberta é encerrada.') }} </p>
      <p class="sub" v-else-if="mode === 'sign-up'">{{ t('Sua conta inclui um workspace Pessoal. Depois você pode criar ou participar de workspaces Team.') }}</p>
      <p class="sub" v-else> {{ t('Suas conversas e seus espaços de trabalho, em um só lugar. Entre para continuar com seus dados protegidos.') }} </p>
      <p v-if="mode === 'sign-in' && invite" class="hint">{{ t('Ao entrar com o email convidado, você também aceita o convite para o workspace Team.') }}</p>

      <div class="alert" v-if="error">{{ error }}</div>

      <form :name="mode === 'sign-in' ? 'wappie-login' : 'wappie-account'" method="post" autocomplete="on" @submit.prevent="submit">
        <div class="field" v-if="mode === 'sign-up' || mode === 'service'">
          <label for="invite">{{ t('Código de convite') }}</label>
          <input id="invite" name="invite" v-model="invite" :required="mode === 'service' || !signupEnabled" autocomplete="off" spellcheck="false" />
          <p v-if="mode === 'sign-up' && signupEnabled" class="hint">{{ t('Opcional. Um convite vincula também o workspace Team à sua nova conta.') }}</p>
          <p class="hint"> {{ t('Use o convite que você recebeu do administrador do espaço. Vale uma vez só.') }} <template v-if="mode === 'service'"> {{ t('Para um sistema, emitido com') }} <code>-role service</code>.</template>
          </p>
        </div>

        <template v-if="mode === 'service'">
          <div class="field">
            <label for="service-name">{{ t('Nome do sistema') }}</label>
            <input id="service-name" name="service-name" v-model="serviceName" required autocomplete="off" spellcheck="false" :placeholder="t('erp-sync')" />
            <p class="hint">{{ t('Minúsculas, dígitos, ponto, traço ou sublinhado. É como ele aparece no console.') }}</p>
          </div>
          <div class="field">
            <label for="service-key">{{ t('Chave pública') }}</label>
            <input id="service-key" name="service-key" v-model="servicePublicKey" required autocomplete="off" spellcheck="false" />
            <p class="hint">{{ t('A linha') }} <code>public</code> {{ t('que') }} <code>wsctl service-key</code> {{ t('imprimiu. Nunca a privada.') }}</p>
          </div>
        </template>

        <div class="field" v-if="mode === 'sign-up'">
          <label for="display-name">{{ t('Seu nome') }}</label>
          <input id="display-name" name="display-name" v-model="displayName" required maxlength="80" autocomplete="name" />
        </div>

        <div class="field" v-if="mode !== 'service'">
          <label for="email">{{ t('E-mail') }}</label>
          <input id="email" name="username" v-model="email" type="email" autocomplete="username" required autocapitalize="off" spellcheck="false" inputmode="email" />
        </div>

        <div v-if="mode === 'sign-up' && signupEnabled && !invite.trim()" class="verification-box">
          <p class="hint">{{ t('Confirme seu email para criar sua conta com segurança.') }}</p>
          <button type="button" class="ghost" :disabled="sendingVerification || !email.includes('@')" @click="requestVerification">{{ sendingVerification ? t('Enviando…') : t('Enviar código de confirmação') }}</button>
          <p v-if="verificationSent" class="hint" role="status">{{ t('Se este email puder criar uma conta, você receberá um link e um código. Confira também a pasta de spam. Se já tem conta, entre normalmente.') }}</p>
          <label for="email-verification">{{ t('Código de confirmação do email') }}</label>
          <input id="email-verification" name="email-verification" v-model="verification" required autocomplete="one-time-code" autocapitalize="off" spellcheck="false" />
        </div>

        <div class="field" v-if="mode === 'recover'">
          <label for="code">{{ t('Código de recuperação') }}</label>
          <input id="code" name="recovery-code" v-model="code" required autocomplete="one-time-code" spellcheck="false" />
          <p class="hint">{{ t('Os seis grupos de cinco caracteres. Maiúsculas e traços não importam.') }}</p>
        </div>

        <div class="field" v-if="mode !== 'service'">
          <label for="password">{{ mode === 'recover' ? t('Nova senha') : t('Senha') }}</label>
          <PasswordInput
            id="password"
            name="password"
            v-model="password"
            required
            :minlength="mode === 'sign-in' ? undefined : 10"
            :autocomplete="mode === 'sign-in' ? 'current-password' : 'new-password'"
          />
          <p class="hint" v-if="mode !== 'sign-in'"> {{ t('Use pelo menos 10 caracteres.') }} </p>
        </div>

        <div class="field" v-if="mode !== 'sign-in' && mode !== 'service'">
          <label for="confirm">{{ t('Repita a senha') }}</label>
          <PasswordInput id="confirm" name="confirm-password" v-model="confirm" required autocomplete="new-password" />
        </div>

        <div class="field" v-if="!hosted">
          <label for="server">{{ t('Servidor') }}</label>
          <input id="server" v-model="serverURL" :placeholder="t('mesma origem desta página')" @blur="refreshPasskeyAvailability(); refreshSignupConfig()" />
        </div>

        <button class="primary" type="submit" :disabled="busy">
          {{ busy ? (mode === 'service' ? t('Registrando…') : t('Entrando com segurança…')) : title }}
        </button>
      </form>

      <template v-if="mode === 'sign-in' && passkeyAvailable">
        <div class="auth-divider"><span>{{ t('ou') }}</span></div>
        <button class="passkey-login" type="button" :disabled="busy" @click="openWithPasskey">
          <AppIcon name="key" :size="20" /> {{ passkeyBusy ? t('Confirme no seu dispositivo…') : t('Entrar com passkey') }}
        </button>
      </template>

      <button class="linkish" @click="switchTo(mode === 'sign-in' ? 'sign-up' : 'sign-in')">
        {{ mode === 'sign-in' ? (signupEnabled ? t('Criar conta') : t('Tenho um código de convite')) : t('Já tenho conta') }}
      </button>
      <br />
      <button class="linkish" v-if="mode === 'sign-in'" @click="switchTo('recover')"> {{ t('Esqueci a senha, tenho o código de recuperação') }} </button>
      <details class="auth-options"><summary>{{ t('Outras formas de acesso') }}</summary>
        <button class="linkish" v-if="mode === 'sign-in'" @click="switchTo('service')">{{ t('Registrar um sistema com chave pública') }}</button>
        <button class="linkish" @click="switchTo('pasted-key')">{{ t('Abrir com uma chave do histórico, sem conta') }}</button>
      </details>
    </div>
  </div>
</template>

<style scoped>
.auth-progress { text-align: center; }
.verification-box { display: grid; gap: 12px; padding: 16px; margin-bottom: 18px; border: 1px solid var(--line); border-radius: 12px; background: var(--bg-raised); }
.auth-progress .loading-spinner { margin: 8px auto 24px; }
.auth-progress .sub { margin-bottom: 0; }
.auth-appearance { display: flex; justify-content: flex-end; margin-bottom: 8px; }
.auth-wordmark { color: var(--accent); font-size: 25px; font-weight: 800; letter-spacing: -1.1px; margin-bottom: 26px; }
.auth-wordmark span { font-size: 9px; margin-left: 3px; vertical-align: middle; }
.auth-divider { display: flex; align-items: center; gap: 12px; color: var(--text-dim); font-size: 12px; margin: 20px 0; }.auth-divider::before, .auth-divider::after { content: ''; flex: 1; height: 1px; background: var(--line); }
.passkey-login { width: 100%; min-height: 46px; display: flex; align-items: center; justify-content: center; gap: 10px; border: 1px solid var(--line); border-radius: 12px; color: var(--text); background: var(--bg-raised); font-weight: 600; cursor: pointer; }.passkey-login:hover { background: var(--bg-hover); }
.auth-options { margin-top: 22px; padding-top: 17px; border-top: 1px solid var(--line); color: var(--text-dim); font-size: 12px; }.auth-options summary { cursor: pointer; }.auth-options .linkish { display: block; }
.unlock-card { border-radius: 22px; box-shadow: 0 18px 70px #0000000d; }
input:-webkit-autofill { -webkit-text-fill-color: var(--text); box-shadow: 0 0 0 1000px var(--bg-input) inset; caret-color: var(--text); }
form .primary { min-height: 46px; border-radius: 12px; }
@media (max-width: 600px) { .unlock-card { padding: 26px 22px; } input { font-size: 16px; } }
</style>

import { AuthError, authRequest, finishSession, signOut, type MeReply, type SessionReply, type SignedIn } from './auth'
import { derive, unwrapPrivateKey, type KDFParams } from '../crypto/account'
import { fromBase64, toBase64, type Bytes } from '../crypto/bytes'
import { unwrapPasskey, wrapPasskey } from '../crypto/passkey'
import { endpoint } from './endpoint'
import { base64url, credentialJSON, creationOptions, prfOutput, publicCredential, requestOptions,
  supportsPasskeys, type CreationJSON, type RequestJSON } from './webauthn'

export interface PasskeyInfo { id: string; label: string; created_at: string; last_used_at?: string; }
interface Flow<T> { flow_id: string; rp_id: string; prf_salt: string; publicKey: T; user_id?: string }
const unsupported = 'Esta passkey não oferece o desbloqueio dos dados criptografados. Use a senha ou escolha outro autenticador.'

export async function passkeysAvailable(serverURL: string): Promise<boolean> {
  if (!supportsPasskeys()) return false
  try {
    const config = await authRequest<{ enabled: boolean; origins?: string[] }>(serverURL, '/v1/auth/passkeys/config', undefined)
    return config.enabled && (!config.origins || config.origins.includes(location.origin))
  }
  catch { return false }
}

export async function listPasskeys(serverURL: string, token: string): Promise<PasskeyInfo[]> {
  const result = await authRequest<{ passkeys: PasskeyInfo[] }>(serverURL, '/v1/auth/passkeys', undefined, token)
  return result.passkeys ?? []
}

async function passwordProof(serverURL: string, email: string, password: string) {
  const challenge = await authRequest<{ salt: string; params: KDFParams }>(serverURL, '/v1/auth/challenge', { email })
  return derive(password, fromBase64(challenge.salt), challenge.params)
}

export async function registerPasskey(input: { serverURL: string; token: string; email: string; password: string; label: string; signal?: AbortSignal }): Promise<void> {
  input.signal?.throwIfAborted()
  if (!supportsPasskeys()) throw new Error('Este navegador não oferece passkeys. Abra o Wappie por HTTPS em um navegador compatível.')
  const derived = await passwordProof(input.serverURL, input.email, input.password)
  const me = await authRequest<MeReply>(input.serverURL, '/v1/auth/me', undefined, input.token)
  const { privateKey } = await unwrapPrivateKey(fromBase64(me.user.wrapped_usk), derived.wrapKey, input.email)
  let prf: Bytes | undefined
  try {
    input.signal?.throwIfAborted()
    const flow = await authRequest<Flow<CreationJSON>>(input.serverURL, '/v1/auth/passkeys/register/options',
      { auth_key: derived.authKey, label: input.label.trim() }, input.token)
    input.signal?.throwIfAborted()
    const salt = fromBase64(flow.prf_salt)
    const credential = publicCredential(await navigator.credentials.create({ publicKey: creationOptions(flow.publicKey, salt), signal: input.signal }))
    prf = prfOutput(credential)
    input.signal?.throwIfAborted()
    if (!prf) {
      // Some authenticators can evaluate PRF only during get(), after create().
      const assertion = publicCredential(await navigator.credentials.get({ signal: input.signal, publicKey: {
        ...requestOptions({ challenge: base64url(crypto.getRandomValues(new Uint8Array(32))), rpId: flow.rp_id,
          userVerification: 'required', allowCredentials: [{ type: 'public-key', id: base64url(new Uint8Array(credential.rawId)) }], timeout: 120000 }, salt),
      } }))
      if (base64url(new Uint8Array(assertion.rawId)) !== base64url(new Uint8Array(credential.rawId))) throw new Error(unsupported)
      prf = prfOutput(assertion)
    }
    if (!prf) throw new Error(unsupported)
    input.signal?.throwIfAborted()
    const wrapped = await wrapPasskey(privateKey, prf, { rpID: flow.rp_id, userID: flow.user_id ?? me.user.id,
      credentialID: base64url(new Uint8Array(credential.rawId)) })
    input.signal?.throwIfAborted()
    await authRequest(input.serverURL, '/v1/auth/passkeys/register/finish', {
      flow_id: flow.flow_id, credential: credentialJSON(credential), wrapped_usk: toBase64(wrapped),
    }, input.token)
  } finally { privateKey.fill(0); prf?.fill(0) }
}

export async function signInWithPasskey(input: { serverURL: string; tenantID?: string; signal?: AbortSignal }): Promise<SignedIn> {
  input.signal?.throwIfAborted()
  if (!supportsPasskeys()) throw new Error('Este navegador não oferece passkeys. Você pode entrar com a senha.')
  const flow = await authRequest<Flow<RequestJSON>>(input.serverURL, '/v1/auth/passkeys/login/options', {})
  input.signal?.throwIfAborted()
  const credential = publicCredential(await navigator.credentials.get({ publicKey: requestOptions(flow.publicKey, fromBase64(flow.prf_salt)), signal: input.signal }))
  const prf = prfOutput(credential)
  if (!prf) throw new Error(unsupported)
  let reply: SessionReply | undefined
  let privateKey: Bytes | undefined
  try {
    input.signal?.throwIfAborted()
    const login = await authRequest<SessionReply & { passkey: { wrapped_usk: string } }>(input.serverURL, '/v1/auth/passkeys/login/finish',
      { flow_id: flow.flow_id, credential: credentialJSON(credential) })
    reply = login
    input.signal?.throwIfAborted()
    privateKey = await unwrapPasskey(fromBase64(login.passkey.wrapped_usk), prf, { rpID: flow.rp_id, userID: login.user.id,
      credentialID: base64url(new Uint8Array(credential.rawId)) })
    input.signal?.throwIfAborted()
    if (input.tenantID && input.tenantID !== reply.user.tenant_id) {
      const previous = reply.token
      reply = await authRequest<SessionReply>(input.serverURL, '/v1/auth/workspaces/session', { tenant_id: input.tenantID }, previous)
      await signOut(input.serverURL, previous)
      input.signal?.throwIfAborted()
    }
    const signedIn = await finishSession(input.serverURL, reply, privateKey)
    input.signal?.throwIfAborted()
    return signedIn
  } catch (error) {
    if (reply) await signOut(input.serverURL, reply.token)
    throw error
  } finally { prf.fill(0); privateKey?.fill(0) }
}

export async function removePasskey(input: { serverURL: string; token: string; email: string; password: string; id: string }): Promise<void> {
  const derived = await passwordProof(input.serverURL, input.email, input.password)
  const response = await fetch(endpoint(input.serverURL, '/v1/auth/passkeys/' + encodeURIComponent(input.id)), {
    method: 'DELETE', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + input.token },
    body: JSON.stringify({ auth_key: derived.authKey }), cache: 'no-store',
  })
  if (!response.ok) {
    const error = await response.json().catch(() => ({})) as { code?: string; message?: string }
    throw new AuthError(error.code ?? 'request_failed', error.message ?? 'Não foi possível remover esta passkey.')
  }
}

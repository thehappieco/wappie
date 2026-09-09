import { t } from '../ui/i18n'
// Signing up and signing in, and turning what that returns into archive keys.
//
// The shape of the exchange matters more than the endpoints. The server is
// asked for a salt, the browser does the expensive derivation locally, and only
// the auth branch is ever sent. What comes back is the account's own private
// key — still wrapped, still opaque to the server — and a list of grants. Each
// grant is one device's archive key sealed to this account. Opening them here
// is the moment a sealed archive becomes a readable one.

import {
  derive,
  freshSalt,
  generateAccountKeys,
  newRecoveryCode,
  recoveryKey,
  recoveryProof,
  unwrapPrivateKey,
  wrapPrivateKey,
  type KDFParams,
} from '../crypto/account'
import { fromBase64, parseUUID, toBase64, type Bytes } from '../crypto/bytes'
import { importArchiveKey, type PrivateKey } from '../crypto/hpke'
import { grantRow, Kind, openDirect } from '../crypto/seal'
import { endpoint } from './endpoint'
import type { BrowserLogin } from '../state/sessionVault'

export class AuthError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message)
    this.name = 'AuthError'
  }
}

interface ChallengeReply {
  salt: string
  params: KDFParams
}

interface Account {
  id: string
  tenant_id: string
  email: string
  role: string
  wrapped_usk: string
  public_key: string
  has_recovery: boolean
}

export interface SessionReply {
  token: string
  expires_at: string
  user: Account
}

interface GrantReply {
  device_id: string
  label: string
  epoch: number
  sealed_dsk: string
}

export interface MeReply {
  user: Account
  grants: GrantReply[]
  expires_at?: string
}

/** Readable is one WhatsApp account this person may open, and the key for it. */
export interface Readable {
  deviceID: string
  label: string
  epoch: number
  archive: PrivateKey
}

/** SignedIn is everything a session needs after the exchange. */
export interface SignedIn {
  token: string
  expiresAt: Date
  email: string
  role: string
  tenantID: string
  userID: string
  hasRecovery: boolean
  /** Devices with a grant. An empty list means an account that can read nothing. */
  readable: Readable[]
  /** A non-extractable key handle; raw account key bytes are wiped after sign-in. */
  accountKey?: PrivateKey
  /** Restoration keeps the base login while each tab selects its own workspace. */
  browserLogin?: BrowserLogin
  notice?: string
}

async function call<T>(serverURL: string, path: string, body: unknown, token?: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(endpoint(serverURL, path), {
    method: body === undefined ? 'GET' : 'POST',
    headers: {
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: 'no-store',
    ...(signal ? { signal } : {}),
  })
  if (response.status === 204) return undefined as T
  const text = await response.text()
  let parsed: unknown
  try {
    parsed = text ? JSON.parse(text) : {}
  } catch {
    throw new AuthError('internal', t('o servidor respondeu {v0}', { v0: response.status }))
  }
  if (!response.ok) {
    const err = parsed as { code?: string; message?: string }
    throw new AuthError(err.code ?? 'internal', authErrorMessage(err.code) ?? err.message ?? t('Não foi possível concluir ({status}).', { status: response.status }))
  }
  return parsed as T
}

/**
 * signUp creates an account.
 *
 * Everything secret is produced here: the keypair, the wrap, the recovery code.
 * The server receives a public key, two opaque blobs and a hash input.
 */
export async function signUp(input: {
  serverURL: string
  invite: string
  email: string
  password: string
}): Promise<{ session: SignedIn; recoveryCode: string }> {
  if (input.password.length < MinPassword) {
    throw new AuthError('weak_password', t('a senha precisa de pelo menos {v0} caracteres', { v0: MinPassword }))
  }

  const salt = freshSalt()
  const params: KDFParams = { alg: 'argon2id', m: 64 * 1024, t: 3, p: 1 }
  const derived = await derive(input.password, salt, params)

  const email = input.email.trim()
  const keys = await generateAccountKeys()
  const wrapped = await wrapPrivateKey(keys.privateKey, derived.wrapKey, email)

  // The second way back. Generated whether or not anyone writes it down —
  // an account with only one access path is one forgotten password from being
  // an archive nobody can read, which is the failure this whole layer exists
  // to prevent.
  const code = newRecoveryCode()
  const recoveryWrap = await wrapPrivateKey(keys.privateKey, await recoveryKey(code), email)

  const reply = await call<SessionReply>(input.serverURL, '/v1/auth/signup', {
    invite: input.invite.trim(),
    email,
    auth_key: derived.authKey,
    kdf_salt: toBase64(salt),
    kdf_params: params,
    public_key: toBase64(keys.publicKey),
    wrapped_usk: toBase64(wrapped),
    recovery_wrap: toBase64(recoveryWrap),
    recovery_proof: await recoveryProof(code),
  })

  const session = await finish(input.serverURL, reply, keys.privateKey)
  keys.privateKey.fill(0)
  return { session, recoveryCode: code }
}

/**
 * registerService registers a system's public key against a service invite.
 *
 * Nothing secret leaves the system: it generated its keypair elsewhere
 * (`wsctl service-key`) and pastes the public half here. No session comes
 * back — a service never signs in; an owner grants it devices and mints an
 * API key that acts as it.
 */
export async function registerService(input: {
  serverURL: string
  invite: string
  name: string
  publicKey: string
}): Promise<{ id: string; name: string }> {
  const raw = fromBase64(input.publicKey.trim())
  if (raw.length !== 32) {
    throw new AuthError('bad_key', t('uma chave pública X25519 tem 32 bytes, esta tem {v0}', { v0: raw.length }))
  }
  const reply = await call<SessionReply>(input.serverURL, '/v1/auth/signup', {
    invite: input.invite.trim(),
    name: input.name.trim(),
    public_key: toBase64(raw),
  })
  return { id: reply.user.id, name: reply.user.email }
}

/** signIn exchanges a password for a session and the keys it unlocks. */
export async function signIn(input: {
  serverURL: string
  email: string
  password: string
  tenantID?: string
}): Promise<SignedIn> {
  const challenge = await call<ChallengeReply>(input.serverURL, '/v1/auth/challenge', {
    email: input.email.trim(),
  })
  const derived = await derive(input.password, fromBase64(challenge.salt), challenge.params)

  let reply = await call<SessionReply>(input.serverURL, '/v1/auth/login', {
    email: input.email.trim(),
    auth_key: derived.authKey,
  })

  // The account's own key, opened with the branch that never left this page.
  const email = input.email.trim()
  const opened = await unwrapPrivateKey(fromBase64(reply.user.wrapped_usk), derived.wrapKey, email)
  if (opened.stale) {
    // A wrap from before the binding existed. Re-wrapped now, under the
    // same key, so the next sign-in opens a bound one; best effort, because
    // a sign-in that works is worth more than an upgrade that happened.
    try {
      await call<void>(
        input.serverURL,
        '/v1/auth/rewrap',
        {
          auth_key: derived.authKey,
          wrapped_usk: toBase64(await wrapPrivateKey(opened.privateKey, derived.wrapKey, email)),
        },
        reply.token,
      )
    } catch {
      // Next time.
    }
  }
  try {
    if (input.tenantID && input.tenantID !== reply.user.tenant_id) {
      const previous = reply.token
      reply = await call<SessionReply>(input.serverURL, '/v1/auth/workspaces/session', { tenant_id: input.tenantID }, previous)
      await signOut(input.serverURL, previous)
    }
    return await finish(input.serverURL, reply, opened.privateKey)
  } catch (error) {
    await signOut(input.serverURL, reply.token)
    throw error
  } finally {
    opened.privateKey.fill(0)
  }
}

/** MinPassword is what signUp, recover and changePassword all insist on. */
export const MinPassword = 10

/**
 * rekeyed produces everything a new password protects, ready for the wire.
 *
 * The private key is the one that was there before: grants are sealed to its
 * public half, and a recovery that produced a new keypair would strand every
 * device. Only the wrapping changes.
 */
async function rekeyed(
  privateKey: Bytes,
  email: string,
  password: string,
  withRecovery: boolean,
): Promise<{ body: Record<string, unknown>; recoveryCode: string }> {
  if (password.length < MinPassword) {
    throw new AuthError('weak_password', t('a senha precisa de pelo menos {v0} caracteres', { v0: MinPassword }))
  }
  const salt = freshSalt()
  const params: KDFParams = { alg: 'argon2id', m: 64 * 1024, t: 3, p: 1 }
  const derived = await derive(password, salt, params)
  const body: Record<string, unknown> = {
    auth_key: derived.authKey,
    kdf_salt: toBase64(salt),
    kdf_params: params,
    wrapped_usk: toBase64(await wrapPrivateKey(privateKey, derived.wrapKey, email)),
  }
  let recoveryCode = ''
  if (withRecovery) {
    recoveryCode = newRecoveryCode()
    body.recovery_wrap = toBase64(
      await wrapPrivateKey(privateKey, await recoveryKey(recoveryCode), email),
    )
    body.recovery_proof = await recoveryProof(recoveryCode)
  }
  return { body, recoveryCode }
}

/**
 * recover is the way back from a forgotten password.
 *
 * The code proves itself to the server, the wrap comes back, the branch that
 * never left this page opens it, and everything the old password protected is
 * derived again under the new one. The code is spent by being typed here, so a
 * new one is generated and returned to be written down.
 */
export async function recover(input: {
  serverURL: string
  email: string
  code: string
  password: string
}): Promise<{ session: SignedIn; recoveryCode: string }> {
  const email = input.email.trim()
  const proof = await recoveryProof(input.code)
  const opened = await call<{ recovery_wrap: string; public_key: string }>(
    input.serverURL,
    '/v1/auth/recover/open',
    { email, recovery_proof: proof },
  )
  let privateKey: Bytes
  try {
    privateKey = (
      await unwrapPrivateKey(fromBase64(opened.recovery_wrap), await recoveryKey(input.code), email)
    ).privateKey
  } catch {
    // The server accepted the proof and the wrap still did not open: the
    // stored wrap is not the one this code made. Corruption, or a swap.
    throw new AuthError('recovery', t('o código foi aceito, mas a chave guardada não abriu com ele'))
  }
  try {
    const next = await rekeyed(privateKey, email, input.password, true)
    const reply = await call<SessionReply>(input.serverURL, '/v1/auth/recover/finish', {
      email,
      recovery_proof: proof,
      new: next.body,
    })
    const session = await finish(input.serverURL, reply, privateKey)
    return { session, recoveryCode: next.recoveryCode }
  } finally {
    privateKey.fill(0)
  }
}

/**
 * changePassword re-wraps under a new password and signs in again.
 *
 * Every session is ended by the change, including this one, which is why a
 * new token comes back: the reason somebody changes a password is usually
 * that they stopped trusting where the old one was typed.
 */
export async function changePassword(input: {
  serverURL: string
  token: string
  email: string
  current: string
  next: string
}): Promise<{ token: string; expiresAt: Date }> {
  const challenge = await call<ChallengeReply>(input.serverURL, '/v1/auth/challenge', {
    email: input.email,
  })
  const derived = await derive(input.current, fromBase64(challenge.salt), challenge.params)
  const me = await call<MeReply>(input.serverURL, '/v1/auth/me', undefined, input.token)
  const { privateKey } = await unwrapPrivateKey(
    fromBase64(me.user.wrapped_usk),
    derived.wrapKey,
    input.email,
  )
  try {
    const next = await rekeyed(privateKey, input.email, input.next, false)
    const reply = await call<SessionReply>(
      input.serverURL,
      '/v1/auth/password',
      { auth_key: derived.authKey, new: next.body },
      input.token,
    )
    return { token: reply.token, expiresAt: new Date(reply.expires_at) }
  } finally {
    privateKey.fill(0)
  }
}

/**
 * setRecovery generates a new recovery code for an account that is signed in.
 *
 * For accounts from before recovery could be redeemed — they hold a wrap the
 * server cannot hand back, because there is no proof to hand it back against
 * — and for anybody who wants to retire a code they may have exposed.
 */
export async function setRecovery(input: {
  serverURL: string
  token: string
  email: string
  password: string
}): Promise<string> {
  const challenge = await call<ChallengeReply>(input.serverURL, '/v1/auth/challenge', {
    email: input.email,
  })
  const derived = await derive(input.password, fromBase64(challenge.salt), challenge.params)
  const me = await call<MeReply>(input.serverURL, '/v1/auth/me', undefined, input.token)
  const { privateKey } = await unwrapPrivateKey(
    fromBase64(me.user.wrapped_usk),
    derived.wrapKey,
    input.email,
  )
  try {
    const code = newRecoveryCode()
    await call<void>(
      input.serverURL,
      '/v1/auth/recovery',
      {
        auth_key: derived.authKey,
        recovery_wrap: toBase64(
          await wrapPrivateKey(privateKey, await recoveryKey(code), input.email),
        ),
        recovery_proof: await recoveryProof(code),
      },
      input.token,
    )
    return code
  } finally {
    privateKey.fill(0)
  }
}

/** signOut revokes the session server-side. Best effort: the tab is closing. */
export async function signOut(serverURL: string, token: string, allRelated = false): Promise<void> {
  try {
    await call<void>(serverURL, '/v1/auth/logout', allRelated ? { all_related: true } : {}, token)
  } catch {
    // A session that cannot be revoked still expires, and there is nothing
    // useful to show somebody who is already leaving.
  }
}

/**
 * withDeviceKey lends a device's archive key to one operation.
 *
 * Granting somebody access means sealing the device key to their public key,
 * and only somebody who already holds that key can do it — the server never
 * has it. But the key does not survive signing in: it is imported as a
 * non-extractable CryptoKey and the bytes are dropped, so that a script
 * injected into this page can decrypt while the tab is open and cannot walk
 * away with anything.
 *
 * So the bytes are recovered on demand, by asking for the password again. That
 * is not a workaround for the above; it is the better arrangement. Handing an
 * archive to another person is exactly the kind of act worth proving you are
 * still the person who unlocked it, and the cost is one derivation.
 *
 * The key exists only inside `use`, and is overwritten before this returns —
 * which is why the shape is a callback rather than a getter. A getter would
 * make the caller responsible for the erasing, and callers forget.
 */
export async function withDeviceKey<T>(
  input: {
    serverURL: string
    email: string
    password: string
    token: string
    deviceID: string
  },
  use: (deviceKey: Bytes, epoch: number) => Promise<T>,
): Promise<T> {
  const challenge = await call<ChallengeReply>(input.serverURL, '/v1/auth/challenge', {
    email: input.email,
  })
  const derived = await derive(input.password, fromBase64(challenge.salt), challenge.params)
  const me = await call<MeReply>(input.serverURL, '/v1/auth/me', undefined, input.token)

  // A wrong password fails here and nowhere else: the server compared a hash
  // at sign-in, and this compares nothing — it simply does not open.
  const { privateKey: accountPrivate } = await unwrapPrivateKey(
    fromBase64(me.user.wrapped_usk),
    derived.wrapKey,
    input.email,
  )
  try {
    const grant = (me.grants ?? []).find((g) => g.device_id === input.deviceID)
    if (!grant) {
      throw new AuthError(
        'no_grant',
        t('sua conta não tem a chave deste aparelho, então não há o que conceder'),
      )
    }
    const account = await importArchiveKey(accountPrivate)
    const row = await grantRow(
      parseUUID(me.user.tenant_id),
      parseUUID(input.deviceID),
      parseUUID(me.user.id),
      grant.epoch,
    )
    const deviceKey = await openDirect(
      account,
      Kind.DeviceGrant,
      parseUUID(me.user.tenant_id),
      row,
      fromBase64(grant.sealed_dsk),
    )
    try {
      return await use(deviceKey, grant.epoch)
    } finally {
      deviceKey.fill(0)
    }
  } finally {
    accountPrivate.fill(0)
  }
}

/**
 * finish fetches the grants and opens each one.
 *
 * A grant that does not open is left out rather than reported: it means the
 * blob beside that row is not the one sealed for this account, which is either
 * corruption or an attempt to hand somebody a key they should not have. Either
 * way the honest result is that the device is not readable.
 */
async function finish(
  serverURL: string,
  reply: SessionReply,
  accountPrivate: Bytes,
): Promise<SignedIn> {
  return finishWithKey(serverURL, reply, await importArchiveKey(accountPrivate))
}

/** Validates authorization again before opening any persisted key or grant. */
export async function restoreSignIn(login: BrowserLogin, workspace?: string): Promise<SignedIn> {
  if (login.expiresAt <= Date.now()) throw new AuthError('unauthorized', t('Sua sessão expirou. Entre novamente.'))
  const controller = new AbortController()
  const deadline = setTimeout(() => controller.abort(), 15_000)
  try {
    const me = await call<MeReply>(login.serverURL, '/v1/auth/me', undefined, login.token, controller.signal)
    if (me.user.id !== login.userID || me.user.tenant_id !== login.tenantID) {
      throw new AuthError('unauthorized', t('Sua sessão expirou. Entre novamente.'))
    }
    let reply: SessionReply = { token: login.token, expires_at: me.expires_at ?? new Date(login.expiresAt).toISOString(), user: me.user }
    let grants = me
    let notice = ''
    if (workspace && workspace !== me.user.tenant_id) {
      try {
        const selected = await call<SessionReply>(login.serverURL, '/v1/auth/workspaces/session', { tenant_id: workspace }, login.token, controller.signal)
        grants = await call<MeReply>(login.serverURL, '/v1/auth/me', undefined, selected.token, controller.signal)
        reply = selected
      } catch (error) {
        if (!(error instanceof AuthError) || !['bad_request', 'not_authorized', 'not_found'].includes(error.code)) throw error
        notice = t('Este espaço não está disponível. Abrimos seu espaço atual para você escolher outro.')
      }
    }
    const signed = await finishWithKey(login.serverURL, reply, login.accountKey, grants)
    signed.browserLogin = login
    signed.notice = notice
    return signed
  } finally { clearTimeout(deadline) }
}

async function finishWithKey(serverURL: string, reply: SessionReply, account: PrivateKey, supplied?: MeReply): Promise<SignedIn> {
  const me = supplied ?? await call<MeReply>(serverURL, '/v1/auth/me', undefined, reply.token)
  const publicKey = fromBase64(me.user.public_key)
  if (me.user.id !== reply.user.id || me.user.tenant_id !== reply.user.tenant_id
    || publicKey.length !== account.publicRaw.length || !publicKey.every((byte, index) => byte === account.publicRaw[index])) {
    throw new AuthError('unauthorized', t('Sua sessão expirou. Entre novamente.'))
  }

  const tenant = parseUUID(me.user.tenant_id)
  const user = parseUUID(me.user.id)

  const readable: Readable[] = []
  for (const g of me.grants ?? []) {
    try {
      const device = parseUUID(g.device_id)
      const row = await grantRow(tenant, device, user, g.epoch)
      const raw = await openDirect(account, Kind.DeviceGrant, tenant, row, fromBase64(g.sealed_dsk))
      try {
        readable.push({ deviceID: g.device_id, label: g.label || g.device_id.slice(0, 8), epoch: g.epoch, archive: await importArchiveKey(raw) })
      } finally { raw.fill(0) }
    } catch {
      // Not readable. Said plainly by its absence rather than by a warning
      // nobody can act on.
    }
  }

  return {
    token: reply.token,
    expiresAt: new Date(reply.expires_at),
    email: me.user.email,
    role: me.user.role,
    tenantID: me.user.tenant_id,
    userID: me.user.id,
    hasRecovery: me.user.has_recovery,
    readable, accountKey: account,
  }
}

export { call as authRequest, finish as finishSession }

function authErrorMessage(code?: string): string | undefined {
  switch (code) {
    case 'bad_credentials': return t('Os dados de acesso não conferem. Verifique sua senha, passkey ou código de recuperação.')
    case 'unauthorized': return t('Sua sessão expirou. Entre novamente.')
    case 'email_taken': return t('Este email já tem uma conta. Entre com ela ou recupere o acesso.')
    case 'invite_invalid': return t('Este convite não é válido, já foi utilizado ou expirou.')
    case 'not_authorized': return t('Você não tem permissão para realizar esta ação.')
    case 'rate_limited': return t('Muitas tentativas. Aguarde um pouco e tente novamente.')
    case 'passkeys_disabled': return t('Este servidor ainda não oferece passkeys. Use sua senha.')
    case 'origin_not_allowed': return t('Passkeys não estão disponíveis neste endereço. Acesse o endereço seguro do Wappie.')
    case 'prf_unsupported': return t('Esta passkey não oferece o desbloqueio dos dados criptografados. Use a senha ou escolha outro autenticador.')
    case 'passkey_limit': return t('Você atingiu o limite de passkeys. Remova uma antiga antes de adicionar outra.')
    case 'passkey_not_saved': return t('A passkey não foi salva. Entre novamente e repita o cadastro.')
    default: return undefined
  }
}

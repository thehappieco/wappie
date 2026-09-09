// An open session: how to reach the server, and which archives can be read.
//
// Two ways to have one, and they are not equivalent.
//
// An account is the ordinary way. The password derives the key that unwraps the
// account's own private key, which opens a grant per device, and each grant is
// that device's archive key. An authorized browser remembers a non-extractable
// account CryptoKey and an encrypted session token until logout or expiration.
// A forgotten password has a recovery code behind it, and access can be granted and revoked per WhatsApp
// account without anybody re-keying anything.
//
// A pasted key is the escape hatch: an API key and one device's archive key,
// typed in. It exists for a machine that should hold no account, and for the
// case where the accounts layer itself is what is broken. It is also exactly
// how the first archive of this project was lost, so it is not the default.

import type { PrivateKey } from '../crypto/hpke'
import { AuthError, restoreSignIn, signOut, type SignedIn } from '../api/auth'
import { origin } from '../api/endpoint'
import { beginBrowserSessionEpoch, bridgeOrigin, browserSessionWasCleared, forgetBrowserSession, readBrowserSession, rememberBrowserSession, sharedBrowserOrigin } from './sessionBridge'
import type { BrowserLogin } from './sessionVault'

/** Credential is what the websocket and the media endpoint authenticate with. */
export interface Credential {
  kind: 'api_key' | 'session'
  token: string
}

export interface Readable {
  deviceID: string
  label: string
}

export interface Session {
  /** Shown in the sidebar so several profiles are tellable apart. */
  label: string
  serverURL: string
  credential: Credential

  /**
   * archiveFor returns the key that opens one device, or undefined.
   *
   * Undefined is a real answer, not a failure: an account with no grant for a
   * device cannot read it, and saying so beats rendering ciphertext.
   */
  archiveFor(deviceID: string): PrivateKey | undefined

  /**
   * readable lists the devices this session knows it can open.
   *
   * Empty means "unknown, try anything" — which is the pasted-key case, where
   * nobody has told the client which device the key belongs to.
   */
  readable: Readable[]

  /**
   * account is the person signed in, when one is. Absent for a pasted key.
   * hasRecovery says whether a recovery code can be redeemed; an account from
   * before that was possible holds a wrap nothing can hand back, and is
   * nudged to generate a new code.
   */
  account?: { email: string; hasRecovery: boolean; tenantID?: string }

  close(): Promise<void>
  /** Dispose memory and connections without signing out on normal navigation. */
  dispose?(): void
  persistenceID?: string
  persistenceEpoch?: string
  expiresAt?: Date
  notice?: string
  remember?(): Promise<void>
  rotate?(token: string, expiresAt: Date): Promise<void>
}

/** fromAccount builds a session from a completed sign-in. */
export function fromAccount(signedIn: SignedIn, serverURL: string): Session {
  const credential: Credential = { kind: 'session', token: signedIn.token }
  const keys = new Map<string, PrivateKey>()
  const tenantID = signedIn.tenantID
  for (const r of signedIn.readable) keys.set(r.deviceID, r.archive)
  let saved: BrowserLogin | undefined = signedIn.browserLogin ?? (signedIn.accountKey ? {
    id: crypto.randomUUID(), realm: sharedBrowserOrigin() ? bridgeOrigin : origin(serverURL).origin,
    serverURL: sharedBrowserOrigin() ? '' : serverURL, token: signedIn.token, expiresAt: signedIn.expiresAt.getTime(),
    userID: signedIn.userID, tenantID: signedIn.tenantID, accountKey: signedIn.accountKey, epoch: beginBrowserSessionEpoch(),
  } : undefined)
  let closed = false

  return {
    label: signedIn.email,
    serverURL,
    credential,
    archiveFor: (deviceID) => keys.get(deviceID),
    readable: signedIn.readable.map((r) => ({ deviceID: r.deviceID, label: r.label })),
    account: { email: signedIn.email, hasRecovery: signedIn.hasRecovery, tenantID: signedIn.tenantID },
    persistenceID: saved?.id,
    persistenceEpoch: saved?.epoch,
    expiresAt: signedIn.expiresAt,
    notice: signedIn.notice,
    remember: async () => { if (!closed && saved) await rememberBrowserSession(saved) },
    rotate: async (token, expiresAt) => {
      credential.token = token
      if (!closed && saved) {
        // Password rotation authenticates a new family in the current space.
        saved = { ...saved, token, expiresAt: expiresAt.getTime(), tenantID }
        await rememberBrowserSession(saved)
      }
    },
    dispose: () => { closed = true; keys.clear(); saved = undefined },
    close: async () => {
      closed = true
      keys.clear()
      const savedID = saved?.id
      const epoch = saved?.epoch
      saved = undefined
      await Promise.allSettled([...(savedID ? [forgetBrowserSession(savedID, epoch)] : []), signOut(serverURL, credential.token, true)])
    },
  }
}

/** Missing or revoked sessions lock the page; transient outages preserve the vault for retry. */
export async function restoreAccountSession(workspace?: string, pending?: (id: string) => void): Promise<Session | null> {
  let login: BrowserLogin | null
  try { login = await readBrowserSession() } catch { return null }
  if (!login) return null
  if (browserSessionWasCleared(login.id, login.epoch)) return null
  pending?.(login.id)
  const expectedRealm = sharedBrowserOrigin() ? bridgeOrigin : origin(login.serverURL).origin
  if (login.realm !== expectedRealm) { await forgetBrowserSession(login.id); return null }
  try {
    const signed = await restoreSignIn(login, workspace)
    // Logout or another account may have won while authorization/grants loaded.
    const current = await readBrowserSession()
    if (current?.id !== login.id || browserSessionWasCleared(login.id, login.epoch)) return null
    return fromAccount(signed, login.serverURL)
  }
  catch (error) {
    if (error instanceof AuthError && ['unauthorized', 'bad_credentials'].includes(error.code)) {
      await forgetBrowserSession(login.id, login.epoch)
      return null
    }
    throw error
  }
}

/**
 * fromPastedKey builds a session around one archive key.
 *
 * The same key is offered for every device, because nobody has said which one
 * it belongs to. The wrong device then fails to open its content keys, and the
 * client reports that rather than pretending.
 */
export function fromPastedKey(input: {
  label: string
  serverURL: string
  apiKey: string
  archive: PrivateKey
}): Session {
  return {
    label: input.label,
    serverURL: input.serverURL,
    credential: { kind: 'api_key', token: input.apiKey },
    archiveFor: () => input.archive,
    readable: [],
    close: async () => {},
  }
}

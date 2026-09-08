// An open session: how to reach the server, and which archives can be read.
//
// Two ways to have one, and they are not equivalent.
//
// An account is the ordinary way. The password derives the key that unwraps the
// account's own private key, which opens a grant per device, and each grant is
// that device's archive key. Nothing is written down, a forgotten password has
// a recovery code behind it, and access can be granted and revoked per WhatsApp
// account without anybody re-keying anything.
//
// A pasted key is the escape hatch: an API key and one device's archive key,
// typed in. It exists for a machine that should hold no account, and for the
// case where the accounts layer itself is what is broken. It is also exactly
// how the first archive of this project was lost, so it is not the default.

import type { PrivateKey } from '../crypto/hpke'
import { signOut, type SignedIn } from '../api/auth'

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
}

/** fromAccount builds a session from a completed sign-in. */
export function fromAccount(signedIn: SignedIn, serverURL: string): Session {
  const keys = new Map<string, PrivateKey>()
  for (const r of signedIn.readable) keys.set(r.deviceID, r.archive)

  return {
    label: signedIn.email,
    serverURL,
    credential: { kind: 'session', token: signedIn.token },
    archiveFor: (deviceID) => keys.get(deviceID),
    readable: signedIn.readable.map((r) => ({ deviceID: r.deviceID, label: r.label })),
    account: { email: signedIn.email, hasRecovery: signedIn.hasRecovery, tenantID: signedIn.tenantID },
    close: async () => {
      keys.clear()
      await signOut(serverURL, signedIn.token)
    },
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

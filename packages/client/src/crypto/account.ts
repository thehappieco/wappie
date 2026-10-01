import { t } from '../messages.js'
// An account: what a password turns into, and what that opens.
//
// The password never leaves the browser. Argon2id turns it into a master key,
// which is split into two independent branches:
//
//   auth — sent to the server and stored there only as a slow hash. Proves who
//          you are. Useless for opening anything.
//   wrap — never transmitted. Unwraps the account's X25519 private key.
//
// That private key opens key grants, and each grant is one device's archive key.
// So signing in is what turns a sealed archive into a readable one, and nobody
// has to keep 32 bytes in a text file — which is precisely how the first
// archive this project stored was lost.
//
// The scheme is the shared kit's (@thehappieco/kit/account), which started as
// this file and which id.thehappie.co uses with its own labels. Wappie's
// profile keeps the labels, the wrap byte and the email binding every stored
// wrap was made with, and still opens version 1 wraps (no binding) as stale,
// so a client that opens one re-wraps it on the way in. Argon2id runs in the
// kit's worker (its kdf.worker.js), off the main thread where there is one.
//
// The kit's errors carry codes; the messages below are the ones this client
// has always shown for them. The console translates them by their source
// text, so they stay exactly as they were.

import * as kit from '@thehappieco/kit/account'
import { accountWrapAAD, wappieAccount } from '@thehappieco/kit/profiles/wappie'
import { fromBase64, toBase64, type Bytes } from './bytes.js'

export {
  AccountError,
  defaultKDFParams,
  freshSalt,
  generateAccountKeys,
  newRecoveryCode,
  type AccountKeys,
  type Derived,
  type KDFParams,
  type Unwrapped,
} from '@thehappieco/kit/account'

const account = kit.bind(wappieAccount)

function message(reason: kit.AccountErrorReason): string | undefined {
  switch (reason) {
    case 'unsupported_alg':
      return t('Esta conta usa uma proteção que esta versão ainda não reconhece.')
    case 'kdf_failed':
      return t('Não foi possível preparar a proteção da conta. Tente novamente.')
    case 'truncated':
      return t('a chave guardada está truncada')
    case 'wrong_key':
      return t('senha incorreta')
    case 'recovery_length':
      return t('um código de recuperação tem {count} caracteres', { count: 30 })
    default:
      // KDF bounds and password preparation: Wappie's profile has neither.
      return undefined
  }
}

function translated(err: unknown): unknown {
  if (!(err instanceof kit.AccountError)) return err
  const text = message(err.reason)
  return text === undefined ? err : new kit.AccountError(text, err.code, err.reason)
}

/**
 * derive turns a password into the two branches.
 *
 * The split is HKDF with distinct labels rather than two halves of one output,
 * so the branches stay independent of each other even if the Argon2id output
 * length ever changes.
 */
export async function derive(password: string, salt: Bytes, params: kit.KDFParams): Promise<kit.Derived> {
  try {
    return await account.derive(password, salt, params)
  } catch (err) {
    throw translated(err)
  }
}

/**
 * wrapPrivateKey seals the account private key under a derived key, bound to
 * the address the account signed up with: version 2, a byte, the nonce and
 * the ciphertext, with the AAD "whatserver2/usk|" and the trimmed, lower-cased
 * email. Whoever can write the users table cannot swap one person's wrap for
 * another's without the tag objecting.
 */
export async function wrapPrivateKey(privateKey: Bytes, under: CryptoKey, email: string): Promise<Bytes> {
  return account.wrapPrivateKey(privateKey, under, accountWrapAAD(email))
}

/**
 * unwrapPrivateKey reverses it. A wrong password fails here and nowhere else.
 *
 * A version 2 blob is tried under its binding first; a blob that does not
 * open that way is tried as version 1. A version 1 blob whose first byte
 * happens to be the version marker costs one extra failed decryption and
 * nothing else.
 */
export async function unwrapPrivateKey(blob: Bytes, under: CryptoKey, email: string): Promise<kit.Unwrapped> {
  try {
    return await account.unwrapPrivateKey(blob, under, accountWrapAAD(email))
  } catch (err) {
    throw translated(err)
  }
}

/** normaliseRecoveryCode accepts what somebody actually types back. */
export function normaliseRecoveryCode(code: string): string {
  try {
    return account.normaliseRecoveryCode(code)
  } catch (err) {
    throw translated(err)
  }
}

/**
 * recoveryKey derives the wrapping key for a recovery code.
 *
 * Cheaper than the password derivation on purpose: the code is 150 random bits,
 * so there is nothing to slow an attacker down for. Two branches, like the
 * password: this one never leaves the page, and recoveryProof travels.
 */
export async function recoveryKey(code: string): Promise<CryptoKey> {
  try {
    return await account.recoveryKey(code)
  } catch (err) {
    throw translated(err)
  }
}

/**
 * recoveryProof is the branch of the code that is sent to the server: what
 * the server hands the recovery wrap back against.
 */
export async function recoveryProof(code: string): Promise<string> {
  try {
    return await account.recoveryProof(code)
  } catch (err) {
    throw translated(err)
  }
}

export { toBase64, fromBase64 }

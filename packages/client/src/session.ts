import type { PrivateKey } from './crypto/hpke.js'
import type { BrowserKeyEnvelope } from './crypto/browserAccount.js'

/** An authorized browser session, never a password or an exportable private key. */
export interface BrowserLogin {
  id: string
  realm: string
  serverURL: string
  token: string
  expiresAt: number
  userID: string
  tenantID: string
  accountKey: PrivateKey
  accountEnvelope?: BrowserKeyEnvelope
  /** Public browser generation; it grants no authorization. */
  epoch?: string
}

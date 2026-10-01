// The account key at rest in this browser: ciphertext under a non-extractable
// AES key, because WebKit loses IndexedDB records containing an X25519
// CryptoKey. The envelope is the shared kit's (@thehappieco/kit/browserAccount),
// bound to Wappie's AAD tag.

import { bind } from '@thehappieco/kit/browserAccount'
import { wappieBrowserAccount } from '@thehappieco/kit/profiles/wappie'

export { validBrowserKeyEnvelope, type BrowserKeyEnvelope } from '@thehappieco/kit/browserAccount'

const browserAccount = bind(wappieBrowserAccount)

/** Called only while sign-in already holds the decrypted raw key. Never
 * exports an existing CryptoKey, persists plaintext, or sends this to a server. */
export const sealBrowserAccountKey = browserAccount.sealBrowserAccountKey

/** Opens the envelope and checks the key's public half against the one kept beside it. */
export const openBrowserAccountKey = browserAccount.openBrowserAccountKey

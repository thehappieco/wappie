import { t } from '../messages.js'
// A passkey's PRF output wraps the account key, so a passkey unlocks what the
// password unlocks. The wrap is the shared kit's (@thehappieco/kit/passkey),
// bound to Wappie's labels and to the JSON AAD of the RP, the user and the
// credential; the messages are this client's, mapped from the kit's reasons.

import * as kit from '@thehappieco/kit/passkey'
import { passkeyAAD, wappiePasskey, type PasskeyBinding } from '@thehappieco/kit/profiles/wappie'
import type { Bytes } from './bytes.js'

export type { PasskeyBinding }

const passkey = kit.bind(wappiePasskey)

function translated(err: unknown): unknown {
  if (!(err instanceof kit.PasskeyError)) return err
  switch (err.reason) {
    case 'bad_prf':
      return new Error(t('A passkey não forneceu uma chave de desbloqueio válida.'))
    case 'bad_key':
      return new Error(t('Chave da conta inválida.'))
    case 'bad_envelope':
      return new Error(t('O registro desta passkey está inválido. Entre com sua senha.'))
    case 'open_failed':
      return new Error(t('Esta passkey não conseguiu abrir seus dados. Entre com sua senha e cadastre uma passkey compatível.'))
  }
}

/** Only the encrypted envelope may be sent to the server. PRF output stays local. */
export async function wrapPasskey(privateKey: Bytes, prf: Bytes, binding: PasskeyBinding): Promise<Bytes> {
  try {
    return await passkey.wrapPasskey(privateKey, prf, binding.rpID, passkeyAAD(binding))
  } catch (err) {
    throw translated(err)
  }
}

export async function unwrapPasskey(envelope: Bytes, prf: Bytes, binding: PasskeyBinding): Promise<Bytes> {
  try {
    return await passkey.unwrapPasskey(envelope, prf, binding.rpID, passkeyAAD(binding))
  } catch (err) {
    throw translated(err)
  }
}

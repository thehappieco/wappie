import { t } from '../ui/i18n'
import { concat, encodeUTF8, type Bytes } from './bytes'

export interface PasskeyBinding { rpID: string; userID: string; credentialID: string }

function aad(binding: PasskeyBinding): Bytes {
  return encodeUTF8(JSON.stringify(['wappie/passkey-vault', 1, binding.rpID, binding.userID, binding.credentialID]))
}

async function wrappingKey(prf: Bytes, binding: PasskeyBinding): Promise<CryptoKey> {
  if (prf.length !== 32) throw new Error(t('A passkey não forneceu uma chave de desbloqueio válida.'))
  const material = await crypto.subtle.importKey('raw', prf, 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: encodeUTF8(binding.rpID),
    info: encodeUTF8('wappie/passkey-wrap/v1') }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

/** Only the encrypted envelope may be sent to the server. PRF output stays local. */
export async function wrapPasskey(privateKey: Bytes, prf: Bytes, binding: PasskeyBinding): Promise<Bytes> {
  if (privateKey.length !== 32) throw new Error(t('Chave da conta inválida.'))
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const sealed = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad(binding) },
    await wrappingKey(prf, binding), privateKey)
  return concat(new Uint8Array([1]), nonce, new Uint8Array(sealed))
}

export async function unwrapPasskey(envelope: Bytes, prf: Bytes, binding: PasskeyBinding): Promise<Bytes> {
  if (envelope.length !== 61 || envelope[0] !== 1) throw new Error(t('O registro desta passkey está inválido. Entre com sua senha.'))
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: envelope.subarray(1, 13), additionalData: aad(binding) },
      await wrappingKey(prf, binding), envelope.subarray(13)))
  } catch {
    throw new Error(t('Esta passkey não conseguiu abrir seus dados. Entre com sua senha e cadastre uma passkey compatível.'))
  }
}

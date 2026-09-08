import { fromBase64, toBase64, type Bytes } from '../crypto/bytes'

export function base64url(bytes: Bytes): string { return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') }
export function unbase64url(value: string): Bytes {
  const raw = value.replace(/-/g, '+').replace(/_/g, '/')
  return fromBase64(raw + '='.repeat((4 - raw.length % 4) % 4))
}

type Descriptor = Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string }
export type CreationJSON = Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials' | 'extensions'> & {
  challenge: string; user: Omit<PublicKeyCredentialUserEntity, 'id'> & { id: string }; excludeCredentials?: Descriptor[]
}
export type RequestJSON = Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials' | 'extensions'> & {
  challenge: string; allowCredentials?: Descriptor[]
}
type PRFExtensions = AuthenticationExtensionsClientInputs & { prf: { eval: { first: Bytes } } }
type ExtensionResults = AuthenticationExtensionsClientOutputs & { prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } } }

export function supportsPasskeys(): boolean {
  return typeof window !== 'undefined' && window.isSecureContext && typeof PublicKeyCredential !== 'undefined' && Boolean(navigator.credentials)
}

export function creationOptions(wire: CreationJSON, salt: Bytes): PublicKeyCredentialCreationOptions {
  return { ...wire, challenge: unbase64url(wire.challenge), user: { ...wire.user, id: unbase64url(wire.user.id) },
    excludeCredentials: wire.excludeCredentials?.map(d => ({ ...d, id: unbase64url(d.id) })),
    attestation: 'none',
    authenticatorSelection: { ...wire.authenticatorSelection, userVerification: 'required', residentKey: 'required', requireResidentKey: true },
    extensions: { credProps: true, prf: { eval: { first: salt } } } as PRFExtensions }
}

export function requestOptions(wire: RequestJSON, salt: Bytes): PublicKeyCredentialRequestOptions {
  return { ...wire, challenge: unbase64url(wire.challenge),
    allowCredentials: wire.allowCredentials?.map(d => ({ ...d, id: unbase64url(d.id) })),
    userVerification: 'required',
    extensions: { prf: { eval: { first: salt } } } as PRFExtensions }
}

export function publicCredential(credential: Credential | null): PublicKeyCredential {
  if (!credential || credential.type !== 'public-key' || !('rawId' in credential)) throw new Error('Nenhuma passkey foi selecionada.')
  return credential as PublicKeyCredential
}

export function prfOutput(credential: PublicKeyCredential): Bytes | undefined {
  const output = (credential.getClientExtensionResults() as ExtensionResults).prf?.results?.first
  return output?.byteLength === 32 ? new Uint8Array(output) : undefined
}

/** Explicit allowlist: credential.toJSON() would include the secret PRF output. */
export function credentialJSON(credential: PublicKeyCredential): Record<string, unknown> {
  const response = credential.response
  const encode = (value: ArrayBuffer) => base64url(new Uint8Array(value))
  const extension = credential.getClientExtensionResults() as ExtensionResults
  const safeExtensions: Record<string, unknown> = {}
  if (typeof extension.credProps?.rk === 'boolean') safeExtensions.credProps = { rk: extension.credProps.rk }
  if (typeof extension.prf?.enabled === 'boolean') safeExtensions.prf = { enabled: extension.prf.enabled }
  const body = 'attestationObject' in response
    ? { clientDataJSON: encode(response.clientDataJSON), attestationObject: encode((response as AuthenticatorAttestationResponse).attestationObject),
      transports: (response as AuthenticatorAttestationResponse).getTransports?.() ?? [] }
    : { clientDataJSON: encode(response.clientDataJSON), authenticatorData: encode((response as AuthenticatorAssertionResponse).authenticatorData),
      signature: encode((response as AuthenticatorAssertionResponse).signature),
      userHandle: (response as AuthenticatorAssertionResponse).userHandle ? encode((response as AuthenticatorAssertionResponse).userHandle!) : null }
  return { id: encode(credential.rawId), rawId: encode(credential.rawId), type: 'public-key',
    authenticatorAttachment: credential.authenticatorAttachment, response: body, clientExtensionResults: safeExtensions }
}

export function passkeyError(error: unknown): string {
  if (error instanceof Error && 'code' in error && typeof error.code === 'string') {
    const messages: Record<string, string> = {
      bad_credentials: 'Não foi possível confirmar sua identidade. Tente novamente ou entre com a senha.',
      passkeys_disabled: 'Passkeys não estão habilitadas nesta instalação.',
      origin_not_allowed: 'Passkeys não estão disponíveis neste endereço. Acesse o app ou o console do Wappie.',
      passkey_limit: 'Sua conta já tem 12 passkeys. Remova uma antes de cadastrar outra.',
      passkey_not_saved: 'Não foi possível cadastrar a passkey. Ela pode já estar registrada; tente outra.',
      prf_unsupported: 'Esta passkey não oferece o desbloqueio dos seus dados. Use a senha ou escolha outro autenticador.',
      rate_limited: 'Muitas tentativas. Aguarde um momento antes de tentar novamente.',
    }
    if (messages[error.code]) return messages[error.code]
  }
  if (error instanceof DOMException) {
    if (error.name === 'NotAllowedError' || error.name === 'AbortError') return 'A solicitação de passkey foi cancelada ou expirou. Você pode tentar novamente.'
    if (error.name === 'InvalidStateError') return 'Esta passkey já está cadastrada. Escolha outra ou entre com a existente.'
    if (error.name === 'SecurityError') return 'Passkeys não estão disponíveis neste endereço. Acesse o endereço seguro do Wappie.'
    if (error.name === 'NotSupportedError') return 'Este navegador ou autenticador não oferece a passkey necessária. Você pode continuar com a senha.'
  }
  return error instanceof Error ? error.message : 'Não foi possível usar a passkey.'
}

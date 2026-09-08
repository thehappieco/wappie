import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { fromBase64, toBase64, type Bytes } from '../src/crypto/bytes'
import { unwrapPasskey, wrapPasskey, type PasskeyBinding } from '../src/crypto/passkey'
import { base64url, credentialJSON, creationOptions, passkeyError, prfOutput, publicCredential,
  requestOptions, supportsPasskeys, unbase64url, type CreationJSON, type RequestJSON } from '../src/api/webauthn'
import { registerPasskey, signInWithPasskey } from '../src/api/passkeys'

const mocks = vi.hoisted(() => ({
  request: vi.fn(), finish: vi.fn(), signOut: vi.fn(), derive: vi.fn(), unwrapAccount: vi.fn(),
  create: vi.fn(), get: vi.fn(),
}))
vi.mock('../src/api/auth', () => ({ authRequest: mocks.request, finishSession: mocks.finish, signOut: mocks.signOut }))
vi.mock('../src/crypto/account', () => ({ derive: mocks.derive, unwrapPrivateKey: mocks.unwrapAccount }))

const SERVER = 'https://app.wappie.thehappie.co'
const RP = 'thehappie.co'
const USER = '018f3a2b-2222-7000-8000-00000000aaaa'
const TENANT = '018f3a2b-2222-7000-8000-00000000bbbb'
const OTHER_TENANT = '018f3a2b-2222-7000-8000-00000000cccc'
const ID = new Uint8Array([240, 23, 195, 64, 72, 139, 251, 212])
const PRIVATE = new Uint8Array(32).fill(113)
const PRF = new Uint8Array(32).fill(201)
const SALT = new Uint8Array(32).fill(49)
const binding: PasskeyBinding = { rpID: RP, userID: USER, credentialID: base64url(ID) }

function creation(): CreationJSON {
  return { challenge: base64url(new Uint8Array([1, 2, 251, 255])), rp: { id: RP, name: 'Wappie' },
    user: { id: base64url(new Uint8Array([5, 6, 252, 254])), name: 'ana@example.test', displayName: 'Ana' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { userVerification: 'discouraged', residentKey: 'discouraged' },
    attestation: 'direct', excludeCredentials: [{ type: 'public-key', id: base64url(ID), transports: ['internal'] }] }
}

function request(): RequestJSON {
  return { challenge: base64url(new Uint8Array([7, 8, 9, 251])), rpId: RP, userVerification: 'discouraged',
    allowCredentials: [{ type: 'public-key', id: base64url(ID), transports: ['hybrid'] }] }
}

function credential(input: { prf?: Bytes | null; registration?: boolean; id?: Bytes } = {}) {
  const secret = input.prf === undefined ? PRF.slice() : input.prf
  const id = input.id ?? ID
  const buffer = (values: number[]) => new Uint8Array(values).buffer
  const response = input.registration
    ? { clientDataJSON: buffer([1, 2, 3]), attestationObject: buffer([4, 5, 6]), getTransports: () => ['internal', 'hybrid'] }
    : { clientDataJSON: buffer([1, 2, 3]), authenticatorData: buffer([7, 8, 9]), signature: buffer([10, 11, 12]), userHandle: buffer([13, 14]) }
  const toJSON = vi.fn(() => { throw new Error('Generic serialization would leak the PRF') })
  return { secret, toJSON, value: {
    id: 'untrusted-string-id', rawId: id.buffer, type: 'public-key', authenticatorAttachment: 'platform', response, toJSON,
    getClientExtensionResults: () => ({ credProps: { rk: true }, prf: { enabled: true,
      ...(secret ? { results: { first: secret.buffer, second: PRF.buffer } } : {}) },
      unexpectedSecret: base64url(PRF), largeBlob: { blob: PRF.buffer } }),
  } as unknown as PublicKeyCredential }
}

function session(token = 'session-1', tenant = TENANT) {
  return { token, expires_at: '2026-10-01T00:00:00Z', user: {
    id: USER, tenant_id: tenant, email: 'ana@example.test', role: 'owner', wrapped_usk: toBase64(new Uint8Array([1])),
    public_key: toBase64(new Uint8Array(32).fill(15)), has_recovery: true,
  } }
}

function setupRegistration() {
  const accountPrivate = PRIVATE.slice()
  mocks.derive.mockResolvedValue({ authKey: 'password-auth-proof', wrapKey: {} })
  mocks.unwrapAccount.mockResolvedValue({ privateKey: accountPrivate, stale: false })
  mocks.request.mockImplementation(async (_server, path) => {
    if (path === '/v1/auth/challenge') return { salt: toBase64(SALT), params: { alg: 'argon2id', m: 8, t: 1, p: 1 } }
    if (path === '/v1/auth/me') return { user: session().user, grants: [] }
    if (path === '/v1/auth/passkeys/register/options') return {
      flow_id: 'registration-flow', rp_id: RP, user_id: USER, prf_salt: toBase64(SALT), publicKey: creation(),
    }
    if (path === '/v1/auth/passkeys/register/finish') return {}
    throw new Error('Unexpected request ' + path)
  })
  return accountPrivate
}

const registerInput = { serverURL: SERVER, token: 'existing-session', email: 'ana@example.test', password: 'private-password', label: '  Meu telefone  ' }

async function setupLogin(over: { envelope?: Bytes; failFinish?: boolean; failSwitch?: boolean; abortOnLogin?: AbortController; abortOnFinish?: AbortController } = {}) {
  const envelope = over.envelope ?? await wrapPasskey(PRIVATE, PRF, binding)
  const receivedKeys: Bytes[] = []
  mocks.request.mockImplementation(async (_server, path) => {
    if (path === '/v1/auth/passkeys/login/options') return { flow_id: 'login-flow', rp_id: RP, prf_salt: toBase64(SALT), publicKey: request() }
    if (path === '/v1/auth/passkeys/login/finish') {
      over.abortOnLogin?.abort()
      return { ...session(), passkey: { wrapped_usk: toBase64(envelope) } }
    }
    if (path === '/v1/auth/workspaces/session') {
      if (over.failSwitch) throw new Error('Workspace unavailable')
      return session('workspace-session', OTHER_TENANT)
    }
    throw new Error('Unexpected request ' + path)
  })
  mocks.finish.mockImplementation(async (_server, reply, privateKey) => {
    receivedKeys.push(privateKey)
    expect(privateKey).toEqual(PRIVATE)
    if (over.failFinish) throw new Error('Grant loading failed')
    over.abortOnFinish?.abort()
    return { token: reply.token, tenantID: reply.user.tenant_id, userID: USER, readable: [] }
  })
  return receivedKeys
}

beforeEach(() => {
  vi.resetAllMocks()
  vi.stubGlobal('window', { isSecureContext: true })
  vi.stubGlobal('PublicKeyCredential', class {})
  vi.stubGlobal('navigator', { credentials: { create: mocks.create, get: mocks.get } })
  mocks.signOut.mockResolvedValue(undefined)
})
afterEach(() => vi.unstubAllGlobals())

describe('passkey account-key envelope', () => {
  it('round-trips with fresh nonces and never contains the plaintext account key', async () => {
    const one = await wrapPasskey(PRIVATE, PRF, binding)
    const two = await wrapPasskey(PRIVATE, PRF, binding)
    expect(one).toHaveLength(61)
    expect(one[0]).toBe(1)
    expect(one).not.toEqual(two)
    expect(await unwrapPasskey(one, PRF, binding)).toEqual(PRIVATE)
    expect(toBase64(one)).not.toContain(toBase64(PRIVATE))
  })

  it.each(['rpID', 'userID', 'credentialID'] as const)('rejects an envelope moved to another %s', async field => {
    const envelope = await wrapPasskey(PRIVATE, PRF, binding)
    await expect(unwrapPasskey(envelope, PRF, { ...binding, [field]: binding[field] + '-other' })).rejects.toThrow()
  })

  it('rejects modified ciphertext, wrong PRF, malformed versions and lengths', async () => {
    const envelope = await wrapPasskey(PRIVATE, PRF, binding)
    const tampered = envelope.slice(); tampered[30] ^= 1
    const version = envelope.slice(); version[0] = 2
    for (const invalid of [tampered, version, envelope.slice(1), new Uint8Array(62)]) {
      await expect(unwrapPasskey(invalid, PRF, binding)).rejects.toThrow()
    }
    await expect(unwrapPasskey(envelope, new Uint8Array(32).fill(202), binding)).rejects.toThrow()
    await expect(wrapPasskey(PRIVATE.slice(1), PRF, binding)).rejects.toThrow()
    await expect(wrapPasskey(PRIVATE, PRF.slice(1), binding)).rejects.toThrow()
  })
})

describe('WebAuthn conversion and secret allowlists', () => {
  it('round-trips binary base64url without padding', () => {
    const data = new Uint8Array([0, 255, 254, 253, 128])
    expect(base64url(data)).not.toMatch(/[+/=]/)
    expect(unbase64url(base64url(data))).toEqual(data)
  })

  it('forces verified discoverable registration without attestation and converts IDs', () => {
    const wire = creation()
    const options = creationOptions(wire, SALT)
    expect(options.challenge).toEqual(new Uint8Array([1, 2, 251, 255]))
    expect(options.user.id).toEqual(new Uint8Array([5, 6, 252, 254]))
    expect(options.excludeCredentials?.[0]).toEqual({ type: 'public-key', id: ID, transports: ['internal'] })
    expect(options.attestation).toBe('none')
    expect(options.authenticatorSelection).toMatchObject({ userVerification: 'required', residentKey: 'required', requireResidentKey: true })
    expect(options.extensions).toEqual({ credProps: true, prf: { eval: { first: SALT } } })
    expect(typeof wire.user.id).toBe('string')
  })

  it('requires verified login and supplies only the public PRF salt', () => {
    const options = requestOptions(request(), SALT)
    expect(options.userVerification).toBe('required')
    expect(options.allowCredentials?.[0].id).toEqual(ID)
    expect(options.extensions).toEqual({ prf: { eval: { first: SALT } } })
    expect(options.rpId).toBe(RP)
  })

  it.each([true, false])('serializes required %s response bytes without PRF outputs or unknown extensions', registration => {
    const built = credential({ registration })
    const json = credentialJSON(built.value)
    expect(json.id).toBe(base64url(ID))
    expect(json.rawId).toBe(base64url(ID))
    expect(json.clientExtensionResults).toEqual({ credProps: { rk: true }, prf: { enabled: true } })
    expect(json.response).toMatchObject({ clientDataJSON: 'AQID' })
    expect(json.response).toHaveProperty(registration ? 'attestationObject' : 'signature')
    const serialized = JSON.stringify(json)
    expect(serialized).not.toContain('results')
    expect(serialized).not.toContain(base64url(PRF))
    expect(serialized).not.toContain('unexpectedSecret')
    expect(serialized).not.toContain('largeBlob')
    expect(built.toJSON).not.toHaveBeenCalled()
  })

  it('accepts exactly 32 PRF bytes and permits clearing the returned secret buffer', () => {
    const built = credential()
    const output = prfOutput(built.value)!
    expect(output).toEqual(PRF)
    output.fill(0)
    expect(built.secret).toEqual(new Uint8Array(32))
    expect(prfOutput(credential({ prf: null }).value)).toBeUndefined()
    expect(prfOutput(credential({ prf: new Uint8Array(31) }).value)).toBeUndefined()
    expect(prfOutput(credential({ prf: new Uint8Array(64) }).value)).toBeUndefined()
  })

  it('requires a secure browser with credentials support and a selected public credential', () => {
    expect(supportsPasskeys()).toBe(true)
    expect(publicCredential(credential().value).type).toBe('public-key')
    expect(() => publicCredential(null)).toThrow()
    expect(() => publicCredential({ type: 'password' } as Credential)).toThrow()
    vi.stubGlobal('window', { isSecureContext: false })
    expect(supportsPasskeys()).toBe(false)
  })

  it('explains cancellation and unsupported authenticators without exposing credential data', () => {
    expect(passkeyError(new DOMException('', 'AbortError'))).toMatch(/cancelada/)
    expect(passkeyError(new DOMException('', 'NotAllowedError'))).toMatch(/cancelada/)
    expect(passkeyError(new DOMException('', 'NotSupportedError'))).toMatch(/senha/)
  })
})

describe('passkey registration', () => {
  it('registers a bound encrypted key and sends neither password, PRF nor account private key', async () => {
    const accountPrivate = setupRegistration()
    const created = credential({ registration: true })
    mocks.create.mockResolvedValue(created.value)
    await registerPasskey(registerInput)
    expect(mocks.get).not.toHaveBeenCalled()
    const finish = mocks.request.mock.calls.find(call => call[1] === '/v1/auth/passkeys/register/finish')!
    expect(finish[3]).toBe('existing-session')
    expect(finish[2].flow_id).toBe('registration-flow')
    expect(await unwrapPasskey(fromBase64(finish[2].wrapped_usk), PRF, binding)).toEqual(PRIVATE)
    const network = JSON.stringify(mocks.request.mock.calls)
    expect(network).not.toContain(registerInput.password)
    expect(network).not.toContain(toBase64(PRF))
    expect(network).not.toContain(base64url(PRF))
    expect(network).not.toContain(toBase64(PRIVATE))
    expect(accountPrivate).toEqual(new Uint8Array(32))
    expect(created.secret).toEqual(new Uint8Array(32))
  })

  it('uses a verified assertion for the exact new credential when create cannot evaluate PRF', async () => {
    setupRegistration()
    mocks.create.mockResolvedValue(credential({ registration: true, prf: null }).value)
    const asserted = credential()
    mocks.get.mockResolvedValue(asserted.value)
    await registerPasskey(registerInput)
    expect(mocks.get).toHaveBeenCalledOnce()
    const options = mocks.get.mock.calls[0][0].publicKey as PublicKeyCredentialRequestOptions
    expect(options.userVerification).toBe('required')
    expect(options.allowCredentials?.[0].id).toEqual(ID)
    expect(options.rpId).toBe(RP)
    expect(asserted.secret).toEqual(new Uint8Array(32))
  })

  it('does not register if no usable PRF is returned and still clears the account key', async () => {
    const accountPrivate = setupRegistration()
    mocks.create.mockResolvedValue(credential({ registration: true, prf: null }).value)
    mocks.get.mockResolvedValue(credential({ prf: null }).value)
    await expect(registerPasskey(registerInput)).rejects.toThrow(/não oferece/)
    expect(mocks.request.mock.calls.some(call => call[1].endsWith('/register/finish'))).toBe(false)
    expect(accountPrivate).toEqual(new Uint8Array(32))
  })

  it('refuses a fallback assertion for another credential', async () => {
    setupRegistration()
    mocks.create.mockResolvedValue(credential({ registration: true, prf: null }).value)
    mocks.get.mockResolvedValue(credential({ id: new Uint8Array([99, 98]) }).value)
    await expect(registerPasskey(registerInput)).rejects.toThrow(/não oferece/)
    expect(mocks.request.mock.calls.some(call => call[1].endsWith('/register/finish'))).toBe(false)
  })

  it('clears the local account key when the authenticator is cancelled', async () => {
    const accountPrivate = setupRegistration()
    mocks.create.mockRejectedValue(new DOMException('', 'NotAllowedError'))
    await expect(registerPasskey(registerInput)).rejects.toHaveProperty('name', 'NotAllowedError')
    expect(accountPrivate).toEqual(new Uint8Array(32))
    expect(mocks.request.mock.calls.some(call => call[1].endsWith('/register/finish'))).toBe(false)
  })
})

describe('passkey sign-in cleanup', () => {
  it('opens the encrypted key locally, finishes the session, and clears temporary secrets', async () => {
    const keys = await setupLogin()
    const asserted = credential()
    mocks.get.mockResolvedValue(asserted.value)
    const signedIn = await signInWithPasskey({ serverURL: SERVER })
    expect(signedIn.token).toBe('session-1')
    expect(mocks.signOut).not.toHaveBeenCalled()
    expect(keys[0]).toEqual(new Uint8Array(32))
    expect(asserted.secret).toEqual(new Uint8Array(32))
    expect(JSON.stringify(mocks.request.mock.calls)).not.toContain(base64url(PRF))
  })

  it('does not request a server session if PRF is unavailable', async () => {
    await setupLogin()
    mocks.get.mockResolvedValue(credential({ prf: null }).value)
    await expect(signInWithPasskey({ serverURL: SERVER })).rejects.toThrow(/não oferece/)
    expect(mocks.request).toHaveBeenCalledTimes(1)
    expect(mocks.finish).not.toHaveBeenCalled()
    expect(mocks.signOut).not.toHaveBeenCalled()
  })

  it('revokes the minted session if the returned envelope is tampered', async () => {
    const envelope = await wrapPasskey(PRIVATE, PRF, binding); envelope[35] ^= 1
    await setupLogin({ envelope })
    const asserted = credential()
    mocks.get.mockResolvedValue(asserted.value)
    await expect(signInWithPasskey({ serverURL: SERVER })).rejects.toThrow(/abrir seus dados/)
    expect(mocks.signOut).toHaveBeenCalledExactlyOnceWith(SERVER, 'session-1')
    expect(mocks.finish).not.toHaveBeenCalled()
    expect(asserted.secret).toEqual(new Uint8Array(32))
  })

  it('revokes and clears secrets if loading grants fails', async () => {
    const keys = await setupLogin({ failFinish: true })
    mocks.get.mockResolvedValue(credential().value)
    await expect(signInWithPasskey({ serverURL: SERVER })).rejects.toThrow('Grant loading failed')
    expect(mocks.signOut).toHaveBeenCalledExactlyOnceWith(SERVER, 'session-1')
    expect(keys[0]).toEqual(new Uint8Array(32))
  })

  it('revokes the initial session after switching workspace and finishes only the selected one', async () => {
    await setupLogin()
    mocks.get.mockResolvedValue(credential().value)
    const signedIn = await signInWithPasskey({ serverURL: SERVER, tenantID: OTHER_TENANT })
    expect(signedIn.token).toBe('workspace-session')
    expect(signedIn.tenantID).toBe(OTHER_TENANT)
    expect(mocks.signOut).toHaveBeenCalledExactlyOnceWith(SERVER, 'session-1')
  })

  it('revokes both sessions if selected-workspace grant loading fails', async () => {
    await setupLogin({ failFinish: true })
    mocks.get.mockResolvedValue(credential().value)
    await expect(signInWithPasskey({ serverURL: SERVER, tenantID: OTHER_TENANT })).rejects.toThrow('Grant loading failed')
    expect(mocks.signOut.mock.calls).toEqual([[SERVER, 'session-1'], [SERVER, 'workspace-session']])
  })

  it('revokes the initial session if selecting the requested workspace fails', async () => {
    await setupLogin({ failSwitch: true })
    mocks.get.mockResolvedValue(credential().value)
    await expect(signInWithPasskey({ serverURL: SERVER, tenantID: OTHER_TENANT })).rejects.toThrow('Workspace unavailable')
    expect(mocks.signOut).toHaveBeenCalledExactlyOnceWith(SERVER, 'session-1')
  })

  it('revokes a session minted after cancellation instead of returning it to an unmounted view', async () => {
    const controller = new AbortController()
    await setupLogin({ abortOnLogin: controller })
    mocks.get.mockResolvedValue(credential().value)
    await expect(signInWithPasskey({ serverURL: SERVER, signal: controller.signal })).rejects.toHaveProperty('name', 'AbortError')
    expect(mocks.signOut).toHaveBeenCalledExactlyOnceWith(SERVER, 'session-1')
    expect(mocks.finish).not.toHaveBeenCalled()
  })

  it('revokes the session if cancellation happens while grants are being opened', async () => {
    const controller = new AbortController()
    const keys = await setupLogin({ abortOnFinish: controller })
    mocks.get.mockResolvedValue(credential().value)
    await expect(signInWithPasskey({ serverURL: SERVER, signal: controller.signal })).rejects.toHaveProperty('name', 'AbortError')
    expect(mocks.signOut).toHaveBeenCalledExactlyOnceWith(SERVER, 'session-1')
    expect(keys[0]).toEqual(new Uint8Array(32))
  })
})

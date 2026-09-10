import { afterEach, expect, it, vi } from 'vitest'
import { signIn, type SignInStep } from '../src/api/auth'
import { derive, freshSalt, generateAccountKeys, wrapPrivateKey } from '../src/crypto/account'
import { toBase64 } from '../src/crypto/bytes'

afterEach(() => vi.restoreAllMocks())

it('reports password stages before their network/cryptographic work and still opens the real account key', async () => {
  const password = 'synthetic-password'
  const email = 'browser@example.test'
  const salt = freshSalt()
  const params = { alg: 'argon2id', m: 8, t: 1, p: 1 }
  const derived = await derive(password, salt, params)
  const keys = await generateAccountKeys()
  const wrapped = await wrapPrivateKey(keys.privateKey, derived.wrapKey, email)
  keys.privateKey.fill(0)
  const user = { id: crypto.randomUUID(), tenant_id: crypto.randomUUID(), email, role: 'owner',
    wrapped_usk: toBase64(wrapped), public_key: toBase64(keys.publicKey), has_recovery: true }
  const steps: SignInStep[] = []
  let answerChallenge!: () => void
  const challenge = new Promise<void>(resolve => { answerChallenge = resolve })
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    const json = (value: unknown) => new Response(JSON.stringify(value), { status: 200 })
    if (String(url).endsWith('/challenge')) {
      expect(steps).toEqual(['checking'])
      await challenge
      return json({ salt: toBase64(salt), params })
    }
    if (String(url).endsWith('/login')) {
      expect(steps).toEqual(['checking', 'unlocking', 'authenticating'])
      expect(JSON.parse(String(init?.body)).auth_key).toBe(derived.authKey)
      return json({ token: 'synthetic-token', expires_at: new Date(Date.now() + 60_000).toISOString(), user })
    }
    expect(String(url)).toContain('/me')
    expect(steps.at(-1)).toBe('opening')
    return json({ user, grants: [] })
  })
  const signed = signIn({ serverURL: 'https://server.example.test', email, password, onProgress: step => steps.push(step) })
  expect(steps).toEqual(['checking'])
  answerChallenge()
  expect((await signed).accountKey?.publicRaw).toEqual(keys.publicKey)
  expect(steps).toEqual(['checking', 'unlocking', 'authenticating', 'opening'])
})

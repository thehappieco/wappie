import { afterEach, describe, expect, it, vi } from 'vitest'
import { start, state, stop } from '../src/state/archive'
import { admin } from '../src/state/admin'
import type { Session } from '../src/state/session'
import { workspaceRequest } from '../src/api/workspaces'

const empty = '00000000-0000-0000-0000-000000000000'
function identity(): Session { return {
 label: 'person@example.com', serverURL: 'https://test.invalid',
 credential: {kind: 'session', token: 'test-session'}, readable: [], archiveFor: () => undefined,
 account: {email: 'person@example.com', tenantID: empty, hasRecovery: true}, close: async () => {},
} }
afterEach(() => { stop(); vi.restoreAllMocks() })
describe('workspace isolation', () => {
 it('opens identity onboarding without connecting to message APIs', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch')
  await start(identity())
  expect(state.phase).toBe('ready'); expect(state.view).toBe('admin')
  expect(state.connected).toBe(false); expect(state.tenantID).toBe(empty)
  expect(state.hasRecovery).toBe(true); expect(fetch).not.toHaveBeenCalled()
 })
 it('clears console identities and tokens when leaving a workspace', () => {
  state.tenantID = '018f3a2b-0000-7000-8000-000000000001'
  admin.accounts = [{id: 'old-user', email: 'old@example.com', role: 'member', public_key: ''}]
  admin.keysError = 'old error'
  stop()
  expect(admin.accounts).toEqual([]); expect(admin.keysError).toBe('')
  expect(state.tenantID).toBe(''); expect(state.deviceID).toBe('')
 })
 it('uses the current session for workspace HTTP requests', async () => {
  await start(identity())
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({workspaces: []}), {status: 200}))
  expect(await workspaceRequest('')).toEqual({workspaces: []})
  expect(fetch).toHaveBeenCalledWith('https://test.invalid/v1/auth/workspaces', expect.objectContaining({headers: expect.objectContaining({Authorization: 'Bearer test-session'})}))
  stop()
  await expect(workspaceRequest('')).rejects.toThrow('Entre com sua conta')
 })
})

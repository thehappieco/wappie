import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { readLastDevice, rememberLastDevice } from '../src/ui/lastDevice'
const userID = '018f3a2b-2222-7000-8000-000000001111'
const workspaceID = '018f3a2b-2222-7000-8000-000000002222'
const deviceID = '018f3a2b-2222-7000-8000-000000003333'
const scope = { serverOrigin: 'https://api.example.test', userID, workspaceID }
let saved: Map<string, string>
beforeEach(() => {
  saved = new Map()
  vi.stubGlobal('localStorage', { getItem: (key: string) => saved.get(key) ?? null, setItem: (key: string, value: string) => saved.set(key, value) })
})
afterEach(() => vi.unstubAllGlobals())
describe('last device browser preference', () => {
  it('stores only a validated device ID and normalizes the origin and identifiers', () => {
    rememberLastDevice({ ...scope, serverOrigin: scope.serverOrigin + '/ignored/path', userID: userID.toUpperCase() }, deviceID.toUpperCase())
    expect(readLastDevice(scope)).toBe(deviceID)
    expect([...saved.values()]).toEqual([deviceID])
    expect(readLastDevice({ ...scope, serverOrigin: 'https://other.example.test' })).toBeNull()
  })
  it('ignores corrupted values and missing or invalid identities', () => {
    for (const value of ['invalid', '00000000-0000-0000-0000-000000000000', 'person@example.test']) rememberLastDevice(scope, value)
    expect(saved.size).toBe(0)
    rememberLastDevice(null, deviceID)
    rememberLastDevice({ ...scope, userID: 'person@example.test' }, deviceID)
    rememberLastDevice({ ...scope, workspaceID: '' }, deviceID)
    expect(saved.size).toBe(0)
    rememberLastDevice(scope, deviceID)
    saved.set([...saved.keys()][0], '{malformed}')
    expect(readLastDevice(scope)).toBeNull()
  })
  it('does not fail login when browser storage is denied', () => {
    vi.stubGlobal('localStorage', { getItem() { throw new Error('denied') }, setItem() { throw new Error('quota') } })
    expect(() => rememberLastDevice(scope, deviceID)).not.toThrow()
    expect(readLastDevice(scope)).toBeNull()
    vi.stubGlobal('localStorage', undefined)
    expect(readLastDevice(scope)).toBeNull()
    expect(() => rememberLastDevice(scope, deviceID)).not.toThrow()
  })
})

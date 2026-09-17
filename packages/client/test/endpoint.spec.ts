import { afterEach, expect, it, vi } from 'vitest'
import { endpoint, websocketURL } from '../src/api/endpoint'
afterEach(() => vi.unstubAllGlobals())
it('uses the explicit installation even from the hosted application origin', () => {
  vi.stubGlobal('location', new URL('https://app.wappie.thehappie.co/'))
  expect(endpoint('https://archive.example.test/path?ignored=yes', '/v1/auth/me')).toBe('https://archive.example.test/v1/auth/me')
  expect(websocketURL('https://archive.example.test')).toBe('wss://archive.example.test/v1/ws')
})
it('uses the page origin only when no installation address was supplied', () => {
  vi.stubGlobal('location', new URL('https://archive.example.test/app?view=all#fragment'))
  expect(endpoint('', '/v1/auth/me')).toBe('https://archive.example.test/v1/auth/me')
})

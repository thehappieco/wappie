import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { expect, it } from 'vitest'
import { authRequest } from '../src/api/auth'
it('refuses an authenticated redirect before following it to another endpoint', async () => {
  let followed = false
  const server = createServer((req, res) => {
    if (req.url === '/first') { res.writeHead(307, {Location:'/unexpected'}); res.end(); return }
    followed = true; res.end('{}')
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  try {
    const port = (server.address() as AddressInfo).port
    await expect(authRequest(`http://127.0.0.1:${port}`, '/first', undefined, 'synthetic-secret')).rejects.toThrow()
    expect(followed).toBe(false)
  } finally { await new Promise<void>(resolve => server.close(() => resolve())) }
})

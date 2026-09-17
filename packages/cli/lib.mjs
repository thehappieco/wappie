import { createHash, randomUUID } from 'node:crypto'
import { mkdir, readFile, writeFile, rename, stat, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import { homedir } from 'node:os'
import { auth, Connection, bytes, seal } from '@whatserver2/client'

export function serverOrigin(value) {
  const u = new URL(value)
  if (u.username || u.password || u.search || u.hash || u.pathname !== '/') throw new Error('Use a server origin without credentials, path, query or fragment')
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname))) throw new Error('Use HTTPS (HTTP is allowed only on loopback)')
  return u.origin
}
export function sessionPath(dir, origin) {
  return join(dir, createHash('sha256').update(origin).digest('hex') + '.json')
}
export const defaultStateDir = () => join(homedir(), '.config', 'whatserver2')
export async function saveSession(dir, origin, signed) {
  await mkdir(dir, { recursive: true, mode: 0o700 })
  const target = sessionPath(dir, origin)
  const temporary = target + '.' + randomUUID()
  const data = { origin, token: signed.token, expiresAt: new Date(signed.expiresAt).toISOString(), email: signed.email, tenantID: signed.tenantID, userID: signed.userID }
  try {
    await writeFile(temporary, JSON.stringify(data) + '\n', { mode: 0o600, flag: 'wx' })
    await rename(temporary, target)
  } finally { await unlink(temporary).catch(() => {}) }
}
export async function loadSession(dir, origin) {
  const path = sessionPath(dir, origin)
  const meta = await stat(path)
  if ((meta.mode & 0o077) !== 0) throw new Error('Session file must be private (chmod 600)')
  const data = JSON.parse(await readFile(path, 'utf8'))
  if (data.origin !== origin || !data.token || !Number.isFinite(Date.parse(data.expiresAt)) || Date.parse(data.expiresAt) <= Date.now()) throw new Error('Session expired or belongs to another server; log in again')
  return data
}
export async function request(origin, token, method, path, body, fetcher = fetch) {
  const url = new URL(path, origin)
  if (!path.startsWith('/v1/') || !url.pathname.startsWith('/v1/') || url.origin !== origin || url.username || url.password) throw new Error('Requests must stay on this server under /v1/')
  const response = await fetcher(url, { method, redirect: 'error', headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30_000) })
  const text = await response.text()
  let result
  try { result = text ? JSON.parse(text) : null } catch { throw new Error(`Server returned non-JSON (${response.status})`) }
  if (!response.ok) throw new Error(result?.message || `Request failed (${response.status})`)
  return result
}
export function parseArgs(argv) {
  const options = {}; const positional = []
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) { positional.push(argv[i]); continue }
    const key = argv[i].slice(2)
    if (key === 'help') { options.help = true; continue }
    if (!argv[i + 1] || argv[i + 1].startsWith('--')) throw new Error(`Missing value for --${key}`)
    options[key] = argv[++i]
  }
  return { options, positional }
}
export async function execute(argv, io, sdk = { auth, Connection, bytes, seal }) {
  const { options: o, positional: p } = parseArgs(argv)
  const command = p.shift()
  if (!command || o.help) { io.print(help); return }
  if (!o.server) throw new Error('--server is required')
  const origin = serverOrigin(o.server); const dir = o['state-dir'] || defaultStateDir()
  const secret = async (name, prompt) => o[name + '-file'] ? (await readFile(o[name + '-file'], 'utf8')).replace(/\r?\n$/, '') : io.secret(prompt)
  const password = () => secret('password', 'Password: ')
  const save = signed => saveSession(dir, origin, signed)
  const recovery = async action => {
    if (!o['recovery-out']) throw new Error('--recovery-out FILE is required; the new recovery code is written there')
    // Reserve a private output before changing the account. Never overwrite an
    // existing recovery code or discover an unwritable path after rotation.
    await writeFile(o['recovery-out'], '', { flag: 'wx', mode: 0o600 })
    const result = await action()
    await writeFile(o['recovery-out'], result.recoveryCode + '\n', { mode: 0o600 })
    await save(result.session)
    io.print({ signed_in: true, tenant_id: result.session.tenantID, recovery_file: o['recovery-out'] })
  }
  if (command === 'login') {
    if (!o.email) throw new Error('--email is required')
    const signed = await sdk.auth.signIn({ serverURL: origin, email: o.email, password: await password(), tenantID: o.workspace })
    await save(signed); io.print({ signed_in: true, tenant_id: signed.tenantID, expires_at: signed.expiresAt }); return
  }
  if (command === 'signup') {
    if (!o.email) throw new Error('--email is required')
    await recovery(async () => sdk.auth.signUp({ serverURL: origin, email: o.email, password: await password(), invite: o.invite || '', displayName: o.name, emailVerificationToken: o.verification })); return
  }
  if (command === 'recover') {
    if (!o.email) throw new Error('--email is required')
    await recovery(async () => sdk.auth.recover({ serverURL: origin, email: o.email, code: await secret('code', 'Recovery code: '), password: await password() })); return
  }
  if (command === 'signup-config') { io.print(await sdk.auth.signupConfig(origin)); return }
  if (command === 'verify-email') { if (!o.email) throw new Error('--email is required'); io.print(await sdk.auth.sendSignupVerification(origin, o.email)); return }
  const session = await loadSession(dir, origin)
  if (command === 'logout') { await sdk.auth.signOut(origin, session.token); await unlink(sessionPath(dir, origin)); io.print({ signed_out: true }); return }
  if (command === 'password') {
    const updated = await sdk.auth.changePassword({ serverURL: origin, token: session.token, email: session.email, current: await password(), next: await secret('new-password', 'New password: ') })
    await save({ ...session, ...updated }); io.print({ password_changed: true }); return
  }
  if (command === 'http' || command === 'me' || command === 'members' || command === 'workspaces' || command === 'storage') {
    const method = command === 'http' ? (p.shift() || 'GET').toUpperCase() : 'GET'
    const path = command === 'http' ? p.shift() : ({ me: '/v1/auth/me', members: '/v1/auth/workspaces/members', workspaces: '/v1/auth/workspaces', storage: '/v1/auth/workspaces/storage' })[command]
    if (!path) throw new Error('http requires METHOD /v1/PATH')
    const body = o.json ? JSON.parse(await io.readJSON(o.json)) : undefined
    io.print(await request(origin, session.token, method, path, body)); return
  }
  if (command === 'workspace') {
    if (!p[0]) throw new Error('workspace requires a workspace UUID')
    const selected = await request(origin, session.token, 'POST', '/v1/auth/workspaces/session', { tenant_id: p[0] })
    await save({ token: selected.token, expiresAt: selected.expires_at, tenantID: selected.user.tenant_id, userID: selected.user.id, email: selected.user.email })
    io.print({ tenant_id: selected.user.tenant_id }); return
  }
  if (command === 'ws') {
    if (!p[0] || !o.reply) throw new Error('ws requires REQUEST_TYPE --reply RESPONSE_TYPE [--json FILE]')
    const connection = await sdk.Connection.connect({ serverURL: origin, credential: { kind: 'session', token: session.token }, clientID: 'wsctl' })
    try { io.print(await connection.request(p[0], o.json ? JSON.parse(await io.readJSON(o.json)) : {}, o.reply)) } finally { connection.close() }
    return
  }
  if (command === 'grant') {
    if (!o.device || !o.user) throw new Error('grant requires --device UUID --user UUID')
    const connection = await sdk.Connection.connect({ serverURL: origin, credential: { kind: 'session', token: session.token }, clientID: 'wsctl' })
    try {
      const users = await connection.request('users.list', {}, 'users')
      const recipient = users.users.find(user => user.id === o.user)
      if (!recipient) throw new Error('Recipient is not a member of this workspace')
      if (o['public-key'] && o['public-key'] !== recipient.public_key) throw new Error('Recipient public key does not match')
      const reply = await sdk.auth.withDeviceKey({ serverURL: origin, token: session.token, email: session.email, password: await password(), deviceID: o.device }, async (deviceKey, epoch, archiveTenantID) => {
        const tenant = sdk.bytes.parseUUID(archiveTenantID || session.tenantID)
        const row = await sdk.seal.grantRow(tenant, sdk.bytes.parseUUID(o.device), sdk.bytes.parseUUID(o.user), epoch)
        const encrypted = await sdk.seal.sealDirect(sdk.bytes.fromBase64(recipient.public_key), sdk.seal.Kind.DeviceGrant, tenant, row, epoch, deviceKey)
        return connection.request('grant.add', { device_id: o.device, user_id: o.user, epoch, sealed_dsk: sdk.bytes.toBase64(encrypted) }, 'device.readers')
      }); io.print(reply)
    } finally { connection.close() }
    return
  }
  throw new Error(`Unknown command: ${command}`)
}
export const help = `wsctl COMMAND --server https://server.example [options]

login --email EMAIL [--workspace UUID]
signup --email EMAIL --recovery-out FILE [--invite CODE] [--name NAME] [--verification TOKEN]
recover --email EMAIL --recovery-out FILE [--code-file FILE]
signup-config | verify-email --email EMAIL
logout | password | me | members | workspaces | storage
workspace UUID
http METHOD /v1/PATH [--json FILE|-]
ws REQUEST_TYPE --reply RESPONSE_TYPE [--json FILE|-]
grant --device UUID --user UUID [--public-key EXPECTED_BASE64]

Passwords are prompted without echo; scripts may use --password-file FILE
and --new-password-file FILE. --state-dir DIR overrides private local sessions.
Each server has an isolated session. Passwords/private keys are never saved.`

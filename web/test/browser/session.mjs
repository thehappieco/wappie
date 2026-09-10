// Optional real-browser regression. Install Playwright separately; never reuse
// a personal browser profile. All API/WebSocket traffic is synthetic, while
// production HTML/assets/headers are used unless QA_DIST selects a local build.
import { build } from 'esbuild'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import assert from 'node:assert/strict'

const playwright = await import(process.env.QA_PLAYWRIGHT_MODULE || 'playwright')
const engine = process.env.QA_BROWSER || 'chromium'
const browser = await playwright[engine].launch({ headless: true,
  ...(process.env.QA_BROWSER_EXECUTABLE ? { executablePath: process.env.QA_BROWSER_EXECUTABLE } : {}) })
const appOrigin = 'https://app.wappie.thehappie.co'
const consoleOrigin = 'https://console.wappie.thehappie.co'
const apiOrigin = 'https://api.wappie.thehappie.co'
const localBuild = process.env.QA_DIST && resolve(process.env.QA_DIST)
const deviceID = '018f3a2b-2222-7000-8000-00000000dddd'
const compiled = await build({ entryPoints: [fileURLToPath(new URL('./sessionFixture.ts', import.meta.url))],
  write: false, bundle: true, format: 'esm', plugins: [{ name: 'qa-locales', setup(builder) {
    builder.onLoad({ filter: /ui\/i18n.ts$/ }, async args => ({ loader: 'ts',
      contents: (await readFile(args.path, 'utf8')).replace(/^const catalogs =.*$/m, 'const catalogs = {}') }))
  } }] })
try {
  const context = await browser.newContext({ serviceWorkers: 'block', locale: 'pt-BR' })
  if (process.env.QA_DEBUG) await context.addInitScript(() => {
    window.qaStorageErrors = []
    const put = IDBObjectStore.prototype.put
    IDBObjectStore.prototype.put = function (...args) {
      window.qaStorageErrors.push({ operation: 'put-attempt', store: this.name, key: args[1] === 'current' ? 'current' : 'other' })
      try {
        const request = put.apply(this, args)
        request.addEventListener('success', () => window.qaStorageErrors.push({ operation: 'put-success' }))
        request.addEventListener('error', () => window.qaStorageErrors.push({ operation: 'put-error', name: request.error?.name }))
        return request
      }
      catch (error) { window.qaStorageErrors.push({ operation: 'put', name: error.name }); throw error }
    }
    const transact = IDBDatabase.prototype.transaction
    IDBDatabase.prototype.transaction = function (...args) {
      const tx = transact.apply(this, args)
      tx.addEventListener('abort', () => window.qaStorageErrors.push({ operation: 'transaction', name: tx.error?.name }))
      if (args[1] === 'readwrite') tx.addEventListener('complete', () => window.qaStorageErrors.push({operation:'transaction-complete'}))
      return tx
    }
  })
  let fixture, signed = false, loginRequests = 0
  const errors = []
  if (localBuild) await context.route('**/*', async route => {
    const url = new URL(route.request().url())
    if (url.origin === consoleOrigin && !url.pathname.startsWith('/v1/')) {
      // WebKit interception cannot fulfill 3xx. A browser redirect simulates
      // navigation here; the actual HTTP redirect has independent Go coverage.
      const target = (appOrigin + '/console' + url.search).replace(/&/g, '&amp;').replace(/"/g, '&quot;')
      return route.fulfill({ status: 200, contentType: 'text/html', body: `<!doctype html><meta http-equiv="refresh" content="0;url=${target}">` })
    }
    const isShell = url.origin === appOrigin && ['/', '/console'].includes(url.pathname)
    if (isShell) {
      const live = await route.fetch({ url: appOrigin + '/' })
      return route.fulfill({ response: live, body: await readFile(resolve(localBuild, 'index.html')) })
    }
    if ([appOrigin, apiOrigin].includes(url.origin) && url.pathname.startsWith('/assets/')) {
      try { return await route.fulfill({ status: 200, contentType: url.pathname.endsWith('.css') ? 'text/css' : 'application/javascript',
        body: await readFile(resolve(localBuild, '.' + url.pathname)) }) }
      catch { /* An unchanged live bridge can still use its earlier assets. */ }
    }
    return route.fallback()
  })
  await context.route('**/qa-fixture.js', route => route.fulfill({ contentType: 'application/javascript', body: compiled.outputFiles[0].text }))
  await context.route('https://checkout.stripe.test/**', route => route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>Synthetic payment return</title>' }))
  // This broad interception also prevents accidental production writes if
  // an application component adds another API request in the future.
  await context.route('**/v1/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (path === '/v1/auth/passkeys/config') return route.fulfill({ json: { enabled: false } })
    if (path === '/v1/auth/challenge') return route.fulfill({ json: fixture.challenge })
    if (path === '/v1/auth/login') {
      loginRequests++
      signed = route.request().postDataJSON().auth_key === fixture.authKey
      return route.fulfill({ status: signed ? 200 : 401, json: signed ? fixture.reply : { code: 'bad_credentials' } })
    }
    if (path === '/v1/auth/me') return route.fulfill({ status: signed ? 200 : 401,
      json: signed ? { ...fixture.reply, grants: fixture.grants } : { code: 'unauthorized' } })
    if (path === '/v1/auth/workspaces') return route.fulfill({ json: { workspaces: [{ id: fixture.reply.user.tenant_id, name: 'Synthetic workspace', role: 'owner' }] } })
    if (path === '/v1/auth/logout') { signed = false; return route.fulfill({ status: 204 }) }
    return route.fulfill({ status: 404, json: { code: 'not_found' } })
  })
  await context.routeWebSocket('**/v1/ws', socket => socket.onMessage(raw => {
    const frame = JSON.parse(String(raw))
    const send = (t, p) => socket.send(JSON.stringify({ t, r: frame.r, p }))
    const device = { device_id: deviceID }
    switch (frame.t) {
      case 'hello': return send('welcome', { version: 1, tenant_id: fixture.reply.user.tenant_id, account: fixture.email, role: 'owner', features: [], server_ts: Date.now() })
      case 'devices.list': return send('devices', { devices: [{ id: deviceID, label: 'Test number', status: 'online', running: true, receipt_mode: 'passive', created_at: new Date().toISOString() }] })
      case 'contacts.list': case 'contacts.resolve': return send('contacts', { ...device, contacts: [] })
      case 'chats.list': return send('chats', { ...device, chats: [] })
      case 'keys.get': return send('keys', { ...device, keys: [] })
      case 'reproject.list': return send('reproject.rows', { ...device, rows: [] })
      case 'users.list': return send('users', { users: [] })
      case 'devices.stats': return send('devices.stats.result', { stats: [] })
      case 'apikeys.list': return send('apikeys', { keys: [] })
      default: return send('error', { code: 'not_found', message: 'Synthetic fixture has no such resource' })
    }
  }))
  const page = await context.newPage()
  page.on('pageerror', error => errors.push(error.message))
  page.on('console', message => { if (message.type() === 'error' && /Content Security Policy|Refused to|TypeError/.test(message.text())) errors.push(message.text()) })
  const inApp = async () => {
    try { await page.locator('.sidebar').waitFor({ timeout: 20_000 }) }
    catch (error) {
      console.error(JSON.stringify({ browser: engine, url: page.url(), alerts: await page.locator('.alert').allTextContents(),
        loginForm: await page.locator('form[name=wappie-login]').count(), errors, storage: await storageState() }))
      throw error
    }
  }
  const storageState = () => page.evaluate(() => new Promise(resolve => {
    const request = indexedDB.open('wappie-browser-session', 1)
    request.onsuccess = () => {
      const db = request.result
      const read = db.transaction('session').objectStore('session').get('current')
      read.onsuccess = () => {
        const value = read.result
        const key = value?.version === 2 ? value.accountEnvelope?.key : value?.accountKey?.key
        resolve({ errors: window.qaStorageErrors, present: Boolean(value), version: value?.version, hasX25519: Boolean(value?.accountKey), keyAlgorithm: key?.algorithm?.name,
          nonExtractable: key?.extractable === false,
          epochMatches: Boolean(value?.epoch && document.cookie.includes('wappie_session_epoch=' + value.epoch)) })
        db.close()
      }
    }
  }))
  const inConsole = () => page.locator('.console-main').waitFor({ timeout: 20_000 })
  await page.goto(appOrigin)
  await page.locator('input[name=username]').waitFor({ timeout: 20_000 })
  await page.addScriptTag({ type: 'module', url: appOrigin + '/qa-fixture.js' })
  await page.waitForFunction(() => typeof window.prepareLoginFixture === 'function')
  fixture = await page.evaluate(() => window.prepareLoginFixture())
  async function login() {
    await page.locator('input[name=username]').fill(fixture.email)
    await page.locator('input[name=password]').fill(fixture.password)
    await page.locator('form[name=wappie-login] button[type=submit]').click()
  }
  await login()
  await inApp()
  const persisted = await storageState()
  assert.equal(persisted.present, true, 'an acknowledged write must also be readable')
  assert.equal(persisted.version, 2)
  assert.equal(persisted.hasX25519, false, 'persist ciphertext and an AES handle, never the incompatible X25519 handle')
  assert.equal(persisted.keyAlgorithm, 'AES-GCM')
  assert.equal(persisted.nonExtractable, true)
  if (process.env.QA_DEBUG) console.log(JSON.stringify({stage:'after-first-login', storage:await storageState(), alerts:await page.locator('.alert').allTextContents(),
    assets:await page.evaluate(() => performance.getEntriesByType('resource').map(entry=>new URL(entry.name).pathname).filter(path=>path.startsWith('/assets/')))}))
  assert.equal(loginRequests, 1)
  await page.reload(); await inApp()
  await page.locator('.console-link').click(); await inConsole()
  assert.equal(page.url().startsWith(appOrigin + '/console'), true)
  await page.reload(); await inConsole()
  await page.locator('.console-app-link').click(); await inApp()
  await page.goto(consoleOrigin + '/?workspace=' + fixture.reply.user.tenant_id); await inConsole()
  const returnURL = page.url()
  await page.goto('https://checkout.stripe.test/')
  await page.goto(returnURL); await inConsole()
  assert.equal(loginRequests, 1, 'refresh, console navigation and payment return must not ask for another login')
  await page.locator('button[aria-label="Sair da conta"]').first().click()
  await page.locator('input[name=username]').waitFor()
  await login(); await inConsole()
  assert.equal(loginRequests, 2)
  await page.locator('.console-app-link').click(); await inApp()
  assert.deepEqual(errors, [])
  console.log(JSON.stringify({ browser: engine, actualApp: true, realCryptography: true, readableDevice: true,
    persistedAES: true, persistedX25519: false, nonExtractable: true,
    firstLogin: true, refresh: true, consoleEntry: true, navigation: true, paymentReturn: true, relogin: true, pageErrors: 0 }))
  await context.close()
} finally { await browser.close() }

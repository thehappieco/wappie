// The reading limits (docs/mcp-enclave.md §19.19, enclave/budgets.mjs): a
// rolling day in one-minute buckets, the first hour from the record's
// creation, a call checked before it runs and counted after, the time a limit
// resets, Go told once per connection, code and window, and calls running at
// once (or a JSON-RPC batch's elements) unable to pass a check together.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { BUDGET_CODES, createReadingLimits, tierOf } from '../budgets.mjs'
import { CLIENT_LIMITS } from '../constants.mjs'
import { hostOf, profileOf } from '../media/gate.mjs'

const MINUTE = 60_000, HOUR = 60 * MINUTE, DAY = 24 * HOUR
const start = Date.parse('2026-10-01T12:00:00.000Z')
function limitsAt(limits = CLIENT_LIMITS) {
  const clock = { at: start }, hits = [], events = []
  const budgets = createReadingLimits({ limits, now: () => clock.at, onHit: (id, code) => { hits.push([id, code]) }, log: { event: (name, fields) => events.push({ name, ...fields }) } })
  return { clock, hits, events, budgets }
}
const refusal = async promise => { try { await promise; return null } catch (error) { return error } }
/** One served call: its reservation (the most it may return), then what it returned. */
async function serve(limits, kind, n, most = Math.max(1, n)) { const ticket = await limits.reserve(kind, most); ticket.settle(n) }

test('tiers: a tested client and a record 0.5.0 wrote have no reading limits; an unknown client and a token do', () => {
  const { budgets } = limitsAt()
  assert.equal(tierOf({}), 'web_tested')
  assert.equal(budgets.forConnection({ connection_id: 'a', created_at: start }), null)
  assert.equal(budgets.forConnection({ connection_id: 'a', limits_tier: 'web_tested', created_at: start }), null)
  assert.equal(budgets.forConnection({ connection_id: 'a', limits_tier: 'local_tested', created_at: start }), null)
  assert.ok(budgets.forConnection({ connection_id: 'a', limits_tier: 'unknown', created_at: start }))
  assert.ok(budgets.forConnection({ connection_id: 'a', limits_tier: 'token', created_at: start }))
  assert.deepEqual(BUDGET_CODES, ['daily_messages', 'daily_attachments', 'first_hour_messages', 'first_hour_attachments', 'network'])
})

test('the first hour: 300 messages and 10 attachments from creation, a call that starts under the limit served whole, the reset at the hour, Go told once', async () => {
  const { clock, hits, events, budgets } = limitsAt()
  const limits = budgets.forConnection({ connection_id: 'c1', limits_tier: 'unknown', created_at: start })
  await serve(limits, 'messages', 299)
  await serve(limits, 'messages', 50)
  const error = await refusal(limits.reserve('messages', 50))
  assert.deepEqual([error?.code, error?.reset_at], ['limit_reached', '2026-10-01T13:00:00Z'])
  assert.equal((await refusal(limits.reserve('messages', 1))).code, 'limit_reached')
  assert.deepEqual(hits, [['c1', 'first_hour_messages']], 'once in the window')
  assert.deepEqual(events.map(entry => [entry.name, entry.code, entry.conn.length]), [['budget_hit', 'first_hour_messages', 12]])
  // Attachments count apart.
  for (let n = 0; n < 10; n++) await serve(limits, 'attachments', 1)
  assert.equal((await refusal(limits.reserve('attachments', 1))).code, 'limit_reached')
  // Past the hour the first-hour budget is gone; the day's 2,000 still hold the 349 read.
  clock.at = start + HOUR
  assert.equal(await refusal(limits.reserve('messages', 50)), null)
  assert.equal(await refusal(limits.reserve('attachments', 1)), null)
})

test('the rolling day: 2,000 messages and 50 attachments over 24 hours in minute buckets, the reset when the oldest buckets leave, Go told once a window', async () => {
  const { clock, hits, budgets } = limitsAt()
  const created = start - 2 * HOUR
  const limits = budgets.forConnection({ connection_id: 't1', limits_tier: 'token', created_at: created })
  await serve(limits, 'messages', 1500)
  clock.at = start + 30 * MINUTE
  await serve(limits, 'messages', 600)
  const error = await refusal(limits.reserve('messages', 50))
  assert.equal(error?.code, 'limit_reached')
  assert.equal(error.reset_at, new Date(start + DAY + MINUTE).toISOString().replace('.000Z', 'Z'), 'when the first bucket leaves, 2,000 is no longer reached')
  assert.deepEqual(hits, [['t1', 'daily_messages']])
  clock.at = start + DAY - MINUTE
  assert.equal((await refusal(limits.reserve('messages', 50))).code, 'limit_reached')
  assert.equal(hits.length, 1)
  clock.at = start + DAY + MINUTE
  assert.equal(await refusal(serve(limits, 'messages', 0, 50)), null, 'the 1,500 have left the day')
  await serve(limits, 'messages', 1500)
  assert.equal((await refusal(limits.reserve('messages', 50))).code, 'limit_reached')
  assert.deepEqual(hits, [['t1', 'daily_messages'], ['t1', 'daily_messages']], 'a new window, a new notice')
  // Nothing counts but what a call returned; a kind with no limit has a ticket that counts nothing.
  clock.at += DAY
  await serve(limits, 'messages', 0); await serve(limits, 'messages', -5); await serve(limits, 'chats', 10); await serve(limits, 'messages', 1.5)
  for (let n = 0; n < 49; n++) await serve(limits, 'attachments', 1)
  assert.equal(await refusal(serve(limits, 'attachments', 1)), null)
  assert.equal((await refusal(limits.reserve('attachments', 1))).code, 'limit_reached')
  assert.equal(await refusal(serve(limits, 'messages', 1999, 50)), null, 'the messages counted nothing')
})

test('calls running at once: each reserves the most it may return, one that could pass the limit with them waits, a failed one frees its reservation, and the counter passes the limit by one call at most', async () => {
  const small = { unknown: { daily: { messages: 1000, attachments: 5 }, first_hour: { messages: 100, attachments: 2 } } }
  const { budgets, hits } = limitsAt(small)
  const limits = budgets.forConnection({ connection_id: 'r1', limits_tier: 'unknown', created_at: start })
  const first = await limits.reserve('messages', 50)
  const second = await limits.reserve('messages', 50)
  let third = null, settled = false
  const waiting = limits.reserve('messages', 50).then(ticket => { third = ticket }, error => { third = error }).finally(() => { settled = true })
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(settled, false, 'with 100 reserved of 100, the third call waits')
  first.settle(50)
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(settled, false, '50 counted and 50 still running: it waits again')
  second.release()
  await waiting
  assert.equal(typeof third.settle, 'function', 'the second failed and freed its 50: the third starts under the limit')
  third.settle(50)
  third.settle(50)
  const after = await refusal(limits.reserve('messages', 1))
  assert.equal(after?.code, 'limit_reached', '100 served: at the limit')
  assert.deepEqual(hits, [['r1', 'first_hour_messages']])

  // Ten calls at once, the elements of one batch: served while they start under the limit, the rest refused, none past it by more than one call.
  const fresh = budgets.forConnection({ connection_id: 'r2', limits_tier: 'unknown', created_at: start })
  let served = 0
  const results = await Promise.allSettled(Array.from({ length: 10 }, async () => {
    const ticket = await fresh.reserve('messages', 50)
    await new Promise(resolve => setTimeout(resolve, 5))
    served += 50
    ticket.settle(50)
  }))
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 2)
  assert.ok(results.filter(result => result.status === 'rejected').every(result => result.reason.code === 'limit_reached'))
  assert.equal(served, 100, 'never more than the limit plus one call')
  // Attachments: one in flight at the edge holds the next one back too.
  const one = await fresh.reserve('attachments', 1)
  const two = await fresh.reserve('attachments', 1)
  const three = fresh.reserve('attachments', 1)
  one.settle(1); two.settle(1)
  assert.equal((await refusal(three)).code, 'limit_reached')
})

test('a token used from another network is told to Go once a day; counters of connections gone are forgotten', async () => {
  const { clock, hits, budgets } = limitsAt()
  budgets.network({ connection_id: 'n1' })
  budgets.network({ connection_id: 'n1' })
  assert.deepEqual(hits, [['n1', 'network']])
  clock.at += DAY
  budgets.network({ connection_id: 'n1' })
  assert.equal(hits.length, 2)
  assert.equal(budgets.takeHits(), 2)
  assert.equal(budgets.takeHits(), 0, 'since the last line')
  const limits = budgets.forConnection({ connection_id: 'gone', limits_tier: 'unknown', created_at: clock.at })
  await serve(limits, 'messages', 300)
  const running = await limits.reserve('attachments', 1)
  budgets.sweep(new Set())
  assert.equal((await refusal(limits.reserve('messages', 1))).code, 'limit_reached', 'a connection with a call running keeps its counters')
  running.release()
  budgets.sweep(new Set())
  assert.equal(await refusal(budgets.forConnection({ connection_id: 'gone', limits_tier: 'unknown', created_at: clock.at }).reserve('messages', 1)), null)
})

test('the host profile (§19.23): a record\'s own profile from 0.6.0, its redirect host for a record 0.5.0 wrote', () => {
  assert.equal(profileOf({ profile: 'chatgpt.com', redirect_host: 'claude.ai' }), 'chatgpt.com', 'Codex: chatgpt.com\'s profile, whatever the redirect')
  assert.equal(profileOf({ profile: 'default', redirect_host: 'claude.ai' }), 'default', 'an unknown client on claude.ai\'s host gets the default wait')
  assert.equal(profileOf({ profile: 'claude.ai' }), 'claude.ai')
  assert.equal(profileOf({ profile: 'evil.example' }), 'default')
  assert.equal(profileOf({ redirect_host: 'claude.ai' }), 'claude.ai', 'legacy')
  assert.equal(profileOf({ redirect_host: 'chatgpt.com' }), 'chatgpt.com', 'legacy')
  assert.equal(profileOf({}), hostOf(undefined))
})

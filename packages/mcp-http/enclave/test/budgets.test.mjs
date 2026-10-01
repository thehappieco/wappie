// The reading limits (docs/mcp-enclave.md §19.19, enclave/budgets.mjs): a
// rolling day in one-minute buckets, the first hour from the record's
// creation, a call checked before it runs and counted after, the time a limit
// resets, and Go told once per connection, code and window.
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
const refusal = fn => { try { fn(); return null } catch (error) { return error } }

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

test('the first hour: 300 messages and 10 attachments from creation, a call that starts under the limit served whole, the reset at the hour, Go told once', () => {
  const { clock, hits, events, budgets } = limitsAt()
  const limits = budgets.forConnection({ connection_id: 'c1', limits_tier: 'unknown', created_at: start })
  limits.before('messages')
  limits.count('messages', 299)
  limits.before('messages')
  limits.count('messages', 50)
  const error = refusal(() => limits.before('messages'))
  assert.deepEqual([error?.code, error?.reset_at], ['limit_reached', '2026-10-01T13:00:00Z'])
  assert.equal(refusal(() => limits.before('messages')).code, 'limit_reached')
  assert.deepEqual(hits, [['c1', 'first_hour_messages']], 'once in the window')
  assert.deepEqual(events.map(entry => [entry.name, entry.code, entry.conn.length]), [['budget_hit', 'first_hour_messages', 12]])
  // Attachments count apart.
  for (let n = 0; n < 10; n++) { limits.before('attachments'); limits.count('attachments', 1) }
  assert.equal(refusal(() => limits.before('attachments')).code, 'limit_reached')
  // Past the hour the first-hour budget is gone; the day's 2,000 still hold the 349 read.
  clock.at = start + HOUR
  assert.equal(refusal(() => limits.before('messages')), null)
  assert.equal(refusal(() => limits.before('attachments')), null)
})

test('the rolling day: 2,000 messages and 50 attachments over 24 hours in minute buckets, the reset when the oldest buckets leave, Go told once a window', () => {
  const { clock, hits, budgets } = limitsAt()
  const created = start - 2 * HOUR
  const limits = budgets.forConnection({ connection_id: 't1', limits_tier: 'token', created_at: created })
  limits.count('messages', 1500)
  clock.at = start + 30 * MINUTE
  limits.count('messages', 600)
  const error = refusal(() => limits.before('messages'))
  assert.equal(error?.code, 'limit_reached')
  assert.equal(error.reset_at, new Date(start + DAY + MINUTE).toISOString().replace('.000Z', 'Z'), 'when the first bucket leaves, 2,000 is no longer reached')
  assert.deepEqual(hits, [['t1', 'daily_messages']])
  clock.at = start + DAY - MINUTE
  assert.equal(refusal(() => limits.before('messages')).code, 'limit_reached')
  assert.equal(hits.length, 1)
  clock.at = start + DAY + MINUTE
  assert.equal(refusal(() => limits.before('messages')), null, 'the 1,500 have left the day')
  limits.count('messages', 1500)
  assert.equal(refusal(() => limits.before('messages')).code, 'limit_reached')
  assert.deepEqual(hits, [['t1', 'daily_messages'], ['t1', 'daily_messages']], 'a new window, a new notice')
  // Nothing counts but what a call returned.
  limits.count('messages', 0); limits.count('messages', -5); limits.count('chats', 10); limits.count('messages', 1.5)
  for (let n = 0; n < 49; n++) limits.count('attachments', 1)
  assert.equal(refusal(() => limits.before('attachments')), null)
  limits.count('attachments', 1)
  assert.equal(refusal(() => limits.before('attachments')).code, 'limit_reached')
})

test('a token used from another network is told to Go once a day; counters of connections gone are forgotten', () => {
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
  limits.count('messages', 300)
  budgets.sweep(new Set())
  assert.equal(refusal(() => budgets.forConnection({ connection_id: 'gone', limits_tier: 'unknown', created_at: clock.at }).before('messages')), null)
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

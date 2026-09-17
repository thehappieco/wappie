import { test } from 'node:test'
import assert from 'node:assert/strict'
import { contactCandidates, matchesText, excerpt, phoneFromIdentity } from '../contacts.mjs'
test('contacts join only explicit phone aliases and preserve ambiguity', () => {
  const archived = [{ uid: 'a', contact_key: '777@lid', contact_pn: '5511999990000@s.whatsapp.net', names: [{ name: 'Archived name', source: 'archive' }] }, { uid: 'b', contact_key: '888@lid', names: [{ name: 'Roberto', source: 'archive' }] }]
  const personal = [{ name: 'Robérto', phones: ['+5511999990000'] }, { name: 'Roberto work', phones: ['+5511999990001'] }]
  const found = contactCandidates(archived, personal, 'roberto', 20)
  assert.equal(found.candidates.length, 3)
  assert.equal(found.ambiguous, true)
  assert.deepEqual(found.candidates[0].identifiers, ['777@lid', '5511999990000@s.whatsapp.net'])
  assert.equal(found.candidates[1].phones.length, 0)
  assert.deepEqual(found.candidates[2].identifiers, ['5511999990001@s.whatsapp.net'])
  assert.equal(phoneFromIdentity('5511999990000@lid'), null)
  assert.equal(contactCandidates(archived, personal, 'roberto', 1).omitted_candidates, 2)
})
test('lexical matching and excerpts find terms after the output truncation boundary', () => {
  const text = 'x '.repeat(1000) + 'A reunião é amanhã às 15h.'
  assert.equal(matchesText(text, 'reuniao amanha'), true)
  const result = excerpt(text, 'reuniao', 128)
  assert.equal(result.truncated, true)
  assert.match(result.value, /reunião/)
  assert.equal(matchesText('The exam is ready', 'appointment'), false)
})
test('different personal names sharing a phone remain ambiguous even when archive aliases merge', () => {
  const archived = [{ uid: 'a', contact_key: '777@lid', contact_pn: '15551234567@s.whatsapp.net', names: [] }]
  const personal = [{ name: 'Alex', phones: ['+15551234567'] }, { name: 'Alex Jones', phones: ['+15551234567'] }]
  const result = contactCandidates(archived, personal, 'Alex', 20)
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0].name_conflict, true)
  assert.equal(result.ambiguous, true)
  assert.match(result.instruction, /Ask/)
})
test('a conflicting personal name outside the query still marks a snapshot-only match ambiguous', () => {
  const personal = [{ name: 'Alex', phones: ['+15551234567'] }, { name: 'Blair', phones: ['+15551234567'] }]
  const result = contactCandidates([], personal, 'Alex', 20)
  assert.equal(result.candidates.length, 1)
  assert.equal(result.candidates[0].name_conflict, true)
  assert.equal(result.ambiguous, true)
})

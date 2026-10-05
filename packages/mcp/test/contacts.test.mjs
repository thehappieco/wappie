import { test } from 'node:test'
import assert from 'node:assert/strict'
import { contactCandidates, isPhoneQuery, matchesText, excerpt, phoneFromIdentity } from '../contacts.mjs'
test('contacts join only explicit phone aliases and preserve ambiguity', () => {
  const archived = [{ uid: 'a', contact_key: '777@lid', contact_pn: '5511999990000@s.whatsapp.net', names: [{ name: 'Archived name', source: 'archive' }] }, { uid: 'b', contact_key: '888@lid', names: [{ name: 'Roberto', source: 'archive' }] }]
  const personal = [{ name: 'Robérto', phones: ['+5511999990000'] }, { name: 'Roberto work', phones: ['+5511999990001'] }]
  const found = contactCandidates(archived, personal, 'roberto', 20, { phones: true })
  assert.equal(found.candidates.length, 3)
  assert.equal(found.ambiguous, true)
  assert.deepEqual(found.candidates[0].identifiers, ['777@lid', '5511999990000@s.whatsapp.net'])
  assert.equal(found.candidates[1].phones.length, 0)
  assert.deepEqual(found.candidates[2].identifiers, ['5511999990001@s.whatsapp.net'])
  assert.equal(phoneFromIdentity('5511999990000@lid'), null)
  assert.equal(contactCandidates(archived, personal, 'roberto', 1).omitted_candidates, 2)
})
test('a candidate carries phones only when asked, never the contact\'s row uid, and matching still reads every phone (§19.32)', () => {
  const archived = [{ uid: 'a', contact_key: '777@lid', contact_pn: '5511999990000@s.whatsapp.net', names: [{ name: 'Roberto', source: 'archive' }] }]
  const personal = [{ name: 'Roberto work', phones: ['+5511999990001'] }]
  for (const query of ['roberto', '5511999990000', '5511999990001']) {
    const hidden = contactCandidates(archived, personal, query, 20)
    assert.ok(hidden.candidates.length >= 1, query)
    for (const candidate of hidden.candidates) {
      assert.equal(Object.hasOwn(candidate, 'phones'), false, query)
      assert.equal(Object.hasOwn(candidate, 'contact_uid'), false, query)
      assert.equal(JSON.stringify(candidate).includes('"a"'), false, query)
    }
  }
  const shown = contactCandidates(archived, personal, 'roberto', 20, { phones: true })
  assert.deepEqual(shown.candidates.map(candidate => candidate.phones), [['+5511999990000'], ['+5511999990001']])
  assert.equal(Object.hasOwn(shown.candidates[0], 'contact_uid'), false)
  // A phone number the user gave: 7 to 15 digits, with + and the usual separators only.
  for (const query of ['+55 11 99999-0000', '11999990000', '(11) 9999-0000', '+1 555.123.4567', '1234567']) assert.equal(isPhoneQuery(query), true, query)
  for (const query of ['0000', '123456', 'Roberto 11999990000', '777@lid', '5511999990000@s.whatsapp.net', '1234567890123456', '+', '55+11 99999 0000']) assert.equal(isPhoneQuery(query), false, query)
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

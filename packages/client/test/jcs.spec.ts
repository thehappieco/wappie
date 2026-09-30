import { describe, expect, it } from 'vitest'

import { canonicalJSON, CanonicalJSONError } from '../src/crypto/jcs'

// RFC 8785 is what the console and the attested reader hash a consent's scope
// with (docs/mcp-enclave.md §17.2, the device check): if they serialize one
// byte differently, every consent with sending fails. So the function is held
// to the RFC's own examples, then to the shape the device check hashes.

describe('RFC 8785\'s own examples', () => {
  it('writes §3.2.2\'s sample exactly', () => {
    // The RFC's input, parsed as a JSON text: numbers in several spellings and
    // a string with escapes that must come out minimal.
    const input = JSON.parse('{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],' +
      '"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}')
    expect(canonicalJSON(input)).toBe('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],' +
      '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}')
  })

  it('sorts keys by UTF-16 code units, as §3.2.3 does', () => {
    const input = JSON.parse('{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One",' +
      '"\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}')
    expect(canonicalJSON(input)).toBe('{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis",' +
      '"€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}')
  })

  it('writes Appendix B\'s numbers as ECMAScript does', () => {
    const cases: [number, string][] = [
      [0, '0'], [-0, '0'], [5e-324, '5e-324'], [-5e-324, '-5e-324'], [1.7976931348623157e308, '1.7976931348623157e+308'],
      [9007199254740992, '9007199254740992'], [295147905179352830000, '295147905179352830000'], [1e21, '1e+21'],
      [9.999999999999997e22, '9.999999999999997e+22'], [0.000001, '0.000001'], [1e-7, '1e-7'], [-1.9999999999999998, '-1.9999999999999998'],
    ]
    for (const [value, text] of cases) expect(canonicalJSON(value)).toBe(text)
  })

  it('refuses what I-JSON has no word for, rather than writing something else', () => {
    for (const bad of [Number.NaN, Infinity, -Infinity, undefined, () => 1, 1n, Symbol('x'), new Date(0), new Map(), { a: undefined }, ['\ud800'], { '\udc00': 1 }, 'a\ud83d']) {
      expect(() => canonicalJSON(bad)).toThrow(CanonicalJSONError)
    }
    // A surrogate pair is one character, not two lone halves.
    expect(canonicalJSON('😀')).toBe('"😀"')
  })
})

describe('the scope a device check hashes', () => {
  it('is written with sorted keys, sorted lists as given, null and booleans as JSON', () => {
    // docs/mcp-enclave.md §17.2 rule 3; the vectors the enclave and the console
    // share (packages/mcp-http/enclave/test/device-check-vectors.json) hash this text.
    const scope = {
      workspace_id: '01a08e0e-c546-7db3-9c44-e6352636d330', device_id: '0199b3c4-3333-7444-8555-666677778888', epoch: 3,
      service_user_id: '0199b3c4-0000-7000-8000-00000000c0de', request: 'AAAAAAAAAAAAAAAAAAAAAA', kid: 'fedcba9876543210',
      device_ids: ['0199b3c4-3333-7444-8555-666677778888', '0199b3c4-9999-7444-8555-666677778888'], expires_at: '2026-10-28T12:00:00.000Z',
      consent_version: 3, media: false, send: 'draft', send_self: true, send_groups: false, send_chats: [], send_signature: null,
    }
    expect(canonicalJSON(scope)).toBe('{"consent_version":3,"device_id":"0199b3c4-3333-7444-8555-666677778888",' +
      '"device_ids":["0199b3c4-3333-7444-8555-666677778888","0199b3c4-9999-7444-8555-666677778888"],"epoch":3,' +
      '"expires_at":"2026-10-28T12:00:00.000Z","kid":"fedcba9876543210","media":false,"request":"AAAAAAAAAAAAAAAAAAAAAA",' +
      '"send":"draft","send_chats":[],"send_groups":false,"send_self":true,"send_signature":null,' +
      '"service_user_id":"0199b3c4-0000-7000-8000-00000000c0de","workspace_id":"01a08e0e-c546-7db3-9c44-e6352636d330"}')
  })

  it('is the same text whatever order the keys were written in', () => {
    const a = { b: [3, { y: 1, x: 2 }], a: 'á', c: null }
    const b = { c: null, a: 'á', b: [3, { x: 2, y: 1 }] }
    expect(canonicalJSON(a)).toBe(canonicalJSON(b))
    expect(canonicalJSON(a)).toBe('{"a":"á","b":[3,{"x":2,"y":1}],"c":null}')
    // A prototype-free object is plain JSON too.
    expect(canonicalJSON(Object.assign(Object.create(null), { z: 1, a: 2 }))).toBe('{"a":2,"z":1}')
  })
})

import { readFileSync } from 'node:fs'
import { expect, it } from 'vitest'
import repertoire from '../src/emoji'
it('uses the exact Unicode repertoire accepted by the public Go API', () => {
  expect(repertoire).toEqual(JSON.parse(readFileSync(new URL('../../../internal/emoji/emoji.json',import.meta.url),'utf8')))
})

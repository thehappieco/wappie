import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
const root = fileURLToPath(new URL('../', import.meta.url))
describe('standalone public client', () => {
  it('ships a public build entry without application or Vue dependencies', () => {
    expect(existsSync(root + 'package.json')).toBe(true)
    const manifest = JSON.parse(readFileSync(root + 'package.json', 'utf8'))
    expect(manifest.private).not.toBe(true)
    expect(manifest.exports['.']).toBeDefined()
    expect(manifest.dependencies.vue).toBeUndefined()
    const source = readdirSync(root + 'src', { recursive: true }).filter(path => String(path).endsWith('.ts'))
    expect(source.length).toBeGreaterThan(10)
    for (const file of source) expect(readFileSync(root + 'src/' + file, 'utf8')).not.toMatch(/from ['"](?:vue|.*(?:state|ui|commercial)\/)/)
  })
})

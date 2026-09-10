import { describe, expect, it } from 'vitest'
import { emojiGroups, normalizeReactionEmoji } from '../src/ui/emoji'

describe('one complete emoji shared with the API', () => {
  it('keeps families, skin tones, flags, keycaps and ZWJ sequences complete', () => {
    for (const emoji of ['', '👩🏽‍💻', '👨‍👩‍👧‍👦', '🇪🇪', '1️⃣', '🏳️‍🌈', '🐦‍🔥', '🫩', '👍🏾']) expect(normalizeReactionEmoji(emoji)).toBe(emoji)
    expect(normalizeReactionEmoji('❤')).toBe('❤️')
    expect(normalizeReactionEmoji('1⃣')).toBe('1️⃣')
  })
  it('rejects letters, multiple emoji, incomplete components and fabricated ZWJ strings', () => {
    for (const value of ['a', 'hello', '1', '#', ' ', '👍👍', '🇪🇪🇧🇷', '👍hello', 'a\uFE0F', '\u200D', '👍\u200D👍', '\uFE0F', '🏻', '🦰', '🇪', '👍\n', '😀\uFE0F\uFE0F']) expect(normalizeReactionEmoji(value), value).toBeNull()
  })
  it('accepts every palette entry and its official presentation aliases', () => {
    let count = 0
    for (const group of emojiGroups) for (const variants of group.emojis) {
      count++
      for (const value of variants) expect(normalizeReactionEmoji(value)).toBe(variants[0])
    }
    expect(count).toBe(3944)
  })
})

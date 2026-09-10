import { describe, expect, it } from 'vitest'
import { groupReactions, reactionSummary, type ReactionLike } from '../src/ui/reactionGroups'

const reaction = (emoji: string, who = 'Ana', fromMe = false): ReactionLike => ({ emoji, who, fromMe })

describe('reaction grouping', () => {
  it('ignores empty and whitespace withdrawals without inventing a reaction', () => {
    expect(reactionSummary([])).toEqual({ groups: [], visible: [], hiddenGroups: 0, total: 0 })
    expect(groupReactions([reaction(''), reaction(' \t\n'), reaction('❤️')])).toEqual([
      { key: '❤', emoji: '❤️', count: 1, mine: false, reactions: [reaction('❤️')] },
    ])
  })

  it('orders groups by count, preserving first appearance when counts tie', () => {
    const rows = ['🎉', '👍', '❤️', '👍', '❤️', '🎉', '👍', '😂', '😂'].map(emoji => reaction(emoji))
    expect(groupReactions(rows).map(group => [group.emoji, group.count])).toEqual([
      ['👍', 3], ['🎉', 2], ['❤️', 2], ['😂', 2],
    ])
  })

  it('merges only VS16 and displays the first original variant that contains it', () => {
    const rows = [reaction('❤', 'Ana'), reaction('❤️', 'Bruno'), reaction('❤', 'Carla')]
    const [heart] = groupReactions(rows)
    expect(heart).toMatchObject({ key: '❤', emoji: '❤️', count: 3 })
    expect(heart!.reactions).toEqual(rows)
    expect(groupReactions([reaction('❤')])[0]!.emoji).toBe('❤')
    expect(groupReactions([reaction('❤️'), reaction('❤')])[0]!.emoji).toBe('❤️')
  })

  it('preserves VS15, skin tones and different ZWJ sequences as distinct groups', () => {
    const emojis = ['❤', '❤\uFE0E', '👍', '👍🏻', '👍🏽', '👩‍💻', '👩💻', '👨‍👩‍👧', '👨‍👩‍👦']
    expect(groupReactions(emojis.map(emoji => reaction(emoji))).map(group => group.key)).toEqual(emojis)
  })

  it('keeps other text unchanged rather than adding more normalization or validation', () => {
    const emojis = [' ❤️ ', '❤️', 'é', 'e\u0301', 'A', 'a']
    expect(groupReactions(emojis.map(emoji => reaction(emoji))).map(group => group.key)).toEqual([' ❤ ', '❤', 'é', 'e\u0301', 'A', 'a'])
  })

  it('counts different people with the same displayed name and retains their original data', () => {
    const rows = [
      { ...reaction('👍', 'Alex'), id: 'one' },
      { ...reaction('👍', 'Alex', true), id: 'two' },
      { ...reaction('👍', '', false), id: 'three' },
    ]
    const [group] = groupReactions(rows)
    expect(group!.count).toBe(3)
    expect(group!.mine).toBe(true)
    expect(group!.reactions.map(row => row.id)).toEqual(['one', 'two', 'three'])
    rows.forEach((row, index) => expect(group!.reactions[index]).toBe(row))
  })

  it('marks only groups containing a current-user reaction', () => {
    const groups = groupReactions([reaction('👍'), reaction('❤️', 'Eu', true), reaction('❤️')])
    expect(groups.map(group => [group.emoji, group.mine])).toEqual([['❤️', true], ['👍', false]])
  })

  it('returns at most four visible groups by default and counts hidden groups separately from reactions', () => {
    const rows = ['👍', '👍', '❤️', '❤️', '😂', '😂', '🎉', '😮', '😮', '🙏'].map(emoji => reaction(emoji))
    const summary = reactionSummary(rows)
    expect(summary.visible.map(group => group.emoji)).toEqual(['👍', '❤️', '😂', '😮'])
    expect(summary.groups).toHaveLength(6)
    expect(summary.hiddenGroups).toBe(2)
    expect(summary.total).toBe(10)
    expect(summary.visible[0]).toBe(summary.groups[0])
  })

  it('supports a smaller visible limit without changing the full group list or total', () => {
    const rows = ['👍', '❤️', '😂'].map(emoji => reaction(emoji))
    expect(reactionSummary(rows, 1)).toMatchObject({ visible: [expect.objectContaining({ emoji: '👍' })], hiddenGroups: 2, total: 3 })
    expect(reactionSummary(rows, 0)).toMatchObject({ visible: [], hiddenGroups: 3, total: 3 })
    expect(reactionSummary(rows, -1).visible).toEqual([])
    expect(reactionSummary(rows, 1.9).visible).toHaveLength(1)
  })

  it('does not mutate frozen input or share derived mutable arrays between calls', () => {
    const first = Object.freeze(reaction('❤'))
    const second = Object.freeze(reaction('❤️', 'Bruno', true))
    const rows = Object.freeze([first, second])
    const summary = reactionSummary(rows)
    expect(rows).toEqual([reaction('❤'), reaction('❤️', 'Bruno', true)])
    summary.visible.pop()
    expect(summary.groups).toHaveLength(1)
    summary.groups[0]!.reactions.pop()
    expect(rows).toHaveLength(2)
    expect(groupReactions(rows)[0]!.reactions).toHaveLength(2)
  })
})

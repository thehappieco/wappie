export interface ReactionLike {
  emoji: string
  who: string
  fromMe: boolean
}

export interface ReactionGroup<T extends ReactionLike = ReactionLike> {
  key: string
  emoji: string
  count: number
  mine: boolean
  reactions: T[]
}

export interface ReactionSummary<T extends ReactionLike = ReactionLike> {
  groups: ReactionGroup<T>[]
  visible: ReactionGroup<T>[]
  hiddenGroups: number
  total: number
}

const EMOJI_PRESENTATION = '\uFE0F'

/** Group current reactions without changing their identities or original text. */
export function groupReactions<T extends ReactionLike>(rows: readonly T[]): ReactionGroup<T>[] {
  const groups = new Map<string, ReactionGroup<T>>()
  for (const reaction of rows) {
    // VS16 only changes emoji presentation. Skin tones, ZWJ sequences and VS15
    // remain distinct; the caller owns validation of the actual reaction.
    const key = reaction.emoji.replace(/\uFE0F/g, '')
    if (!key.trim()) continue

    let group = groups.get(key)
    if (!group) {
      group = { key, emoji: reaction.emoji, count: 0, mine: false, reactions: [] }
      groups.set(key, group)
    }
    if (!group.emoji.includes(EMOJI_PRESENTATION) && reaction.emoji.includes(EMOJI_PRESENTATION)) {
      group.emoji = reaction.emoji
    }
    group.count++
    group.mine ||= reaction.fromMe
    group.reactions.push(reaction)
  }
  // Map insertion order plus a stable sort preserves first appearance on ties.
  return [...groups.values()].sort((left, right) => right.count - left.count)
}

export function reactionSummary<T extends ReactionLike>(rows: readonly T[], maxVisible = 4): ReactionSummary<T> {
  const groups = groupReactions(rows)
  const limit = Number.isFinite(maxVisible) ? Math.max(0, Math.floor(maxVisible)) : 4
  const visible = groups.slice(0, limit)
  return {
    groups,
    visible,
    hiddenGroups: groups.length - visible.length,
    total: groups.reduce((sum, group) => sum + group.count, 0),
  }
}

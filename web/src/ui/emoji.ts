import data from '../../../internal/emoji/emoji.json'

/** Complete Unicode emoji sequences, shared with the API; no runtime Unicode-version mismatch. */
export const emojiGroups = data.groups
const accepted = new Map<string, string>([['', '']])
for (const group of emojiGroups) for (const variants of group.emojis) {
  for (const value of variants) accepted.set(value, variants[0]!)
}

/** Empty means withdrawal; null is invalid. Never count UTF-16 code units as visible emoji. */
export function normalizeReactionEmoji(value: string): string | null {
  return value.length <= 128 ? accepted.get(value) ?? null : null
}

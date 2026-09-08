// Counting a poll nobody but this client can read.
//
// The archive stores a vote as a list of SHA-256 hashes of the option text.
// That is what WhatsApp puts on the wire, and it is also the only thing this
// server could store: a poll's question and options are sealed content, so the
// server holds the vote and the poll and can match neither to the other.
//
// So the tally happens here. The client opens the poll, hashes each option, and
// looks for the result among the selections. It is not a workaround — it is the
// only arrangement in which a sealed archive can show poll results at all, and
// it keeps the property the whole product rests on: a database dump reveals
// neither the question nor anybody's answer.
//
// What that costs is worth naming. A vote for an option this client cannot see
// — an option edited after the fact, a hash from a poll variant nobody here
// parses — matches nothing and is counted as unmatched rather than dropped. A
// tally that quietly ignored it would report fewer voters than there were.

/**
 * limitOf says how many options one voter may pick.
 *
 * The trap is that zero does not mean zero, and it does not mean one either.
 * WhatsApp's `selectableOptionsCount` carries 1 for a poll that allows a single
 * answer — that is what the field is for — and whatsmeow normalises anything
 * out of range to 0, so 0 is the value a poll carries when it stated no limit
 * at all. That is what "allow multiple answers" produces.
 *
 * Reading 0 as 1 is therefore not a conservative default, it is the wrong
 * answer: it takes every multiple-choice poll in the archive and refuses the
 * second tick, silently, while the same poll on a phone accepts it. That was
 * the bug this function exists to remove.
 *
 * An absent field reads the same as 0, and the archive cannot tell them apart
 * anyway — the count is sealed with `omitempty`, so a zero never survives the
 * round trip as a zero. They mean the same thing, which is what makes that
 * acceptable rather than a loss.
 *
 * The count is capped at the number of options, because a poll claiming a limit
 * larger than itself is stating a bound it cannot reach and a caller should not
 * have to think about it.
 */
export function limitOf(poll: { selectable_count?: number; options?: string[] }): number {
  const options = poll.options?.length ?? 0
  const stated = poll.selectable_count ?? 0
  if (stated <= 0) return Math.max(1, options)
  return Math.min(stated, Math.max(1, options))
}

/** Selection is what a vote becomes, and whether the press was refused. */
export interface Selection {
  options: string[]
  /** Set when the poll's limit is already reached and this option was not in it. */
  refused: boolean
}

/**
 * nextSelection decides what pressing an option does.
 *
 * Pressing one already chosen takes it back. WhatsApp treats a vote as
 * replacing the voter's previous answer, so removing one from the list and
 * sending the rest is how a single choice is withdrawn.
 *
 * At the limit, the press is refused rather than absorbed. The alternative —
 * dropping the oldest choice to make room — was considered and rejected: it
 * unticks something the person chose deliberately, without saying so, and the
 * only evidence would be a count that failed to go up. WhatsApp's own client
 * disables the remaining options instead, which is the same answer said in
 * advance.
 */
export function nextSelection(current: string[], option: string, limit: number): Selection {
  if (current.includes(option)) {
    return { options: current.filter((o) => o !== option), refused: false }
  }
  if (current.length >= limit) {
    return { options: current, refused: true }
  }
  return { options: [...current, option], refused: false }
}

/** Vote is one answer, already opened. */
export interface Vote {
  /** Who cast it, as a display name. */
  who: string
  /** The key they cast it under, for avatars and for identity. */
  key: string
  fromMe: boolean
  at?: Date
  /**
   * The selections, hex-encoded. Empty is a withdrawal: WhatsApp treats a vote
   * as replacing the voter's previous one, so an empty selection is how a
   * person takes theirs back.
   */
  selected: string[]
  /**
   * Whether the selection could be opened at all. A vote that arrived while
   * this account could not derive the poll's secret is still a vote, and still
   * counts as somebody having answered — it just cannot say what they chose.
   */
  opened: boolean
}

/** OptionTally is one option and who chose it. */
export interface OptionTally {
  text: string
  voters: Vote[]
  mine: boolean
}

export interface Tally {
  options: OptionTally[]
  /** How many people answered, counting each person once. */
  voters: number
  /** Votes whose selection matched no option this client can see. */
  unmatched: number
  /** Votes nobody here could open. */
  sealed: number
}

/**
 * count matches votes to options.
 *
 * Pure, and takes the option hashes rather than computing them, because hashing
 * is asynchronous in the browser and this is the part worth testing without a
 * clock or a crypto engine in the way.
 *
 * Only the newest vote per person counts. WhatsApp replaces a voter's previous
 * answer rather than adding to it, so a person who changed their mind must
 * appear once, under what they chose last — summing every row would report a
 * poll of four people as having had nine answers.
 */
export function count(options: string[], hashes: string[], votes: Vote[]): Tally {
  const byOption = new Map<string, OptionTally>()
  const tallies = options.map((text, i) => {
    const t: OptionTally = { text, voters: [], mine: false }
    // A poll with two identically worded options hashes them the same way, so
    // the first wins and the second stays empty. WhatsApp's own clients have
    // the same problem, and there is nothing here that could tell them apart.
    if (!byOption.has(hashes[i])) byOption.set(hashes[i], t)
    return t
  })

  let unmatched = 0
  let sealed = 0
  let voters = 0
  for (const vote of newest(votes)) {
    if (!vote.opened) {
      sealed++
      voters++
      continue
    }
    // A withdrawal. It is not an answer and must not be counted as one.
    if (vote.selected.length === 0) continue
    // Counted once, whatever they ticked. A poll that allows three choices is
    // still answered by one person, and "6 votos" on a poll three people
    // answered is the kind of wrong nobody can see is wrong.
    voters++
    let matched = false
    for (const hash of vote.selected) {
      const option = byOption.get(hash)
      if (!option) continue
      option.voters.push(vote)
      if (vote.fromMe) option.mine = true
      matched = true
    }
    if (!matched) unmatched++
  }

  return { options: tallies, voters, unmatched, sealed }
}

/**
 * newest keeps one vote per person, the last they cast.
 *
 * Ordered by time, and by sequence when two rows share a second — a person
 * changing their mind twice in the same second is unlikely and a poll that
 * showed the wrong answer because of it would be impossible to explain.
 */
function newest(votes: Vote[]): Vote[] {
  const latest = new Map<string, Vote>()
  for (const vote of votes) {
    const seen = latest.get(vote.key)
    if (!seen || at(vote) >= at(seen)) latest.set(vote.key, vote)
  }
  return [...latest.values()]
}

function at(v: Vote): number {
  return v.at ? v.at.getTime() : 0
}

/**
 * digest hashes one option the way WhatsApp does: plain SHA-256 of the text,
 * no salt and no truncation, hex-encoded so it can be a Map key.
 *
 * Pinned on the server side by TestPollOptionsAreHashedWithSHA256. If upstream
 * ever changed it, every vote would keep storing and none would ever match an
 * option again — and the poll would simply look unanswered.
 */
const digests = new Map<string, string>()

export async function digest(option: string): Promise<string> {
  const cached = digests.get(option)
  if (cached !== undefined) return cached
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(option))
  const hex = hexOf(new Uint8Array(bytes))
  digests.set(option, hex)
  return hex
}

/** hashesOf digests every option of a poll, in order. */
export function hashesOf(options: string[]): Promise<string[]> {
  return Promise.all(options.map(digest))
}

/**
 * fromBase64 turns one selection into the same hex the digests use.
 *
 * Go writes a byte slice as base64 in JSON, so this is the shape a selection
 * arrives in. Returns an empty string for anything that is not base64, which
 * then matches no option — a malformed selection must not be able to be counted
 * as a vote for whatever happens to hash to nothing.
 */
export function fromBase64(b64: string): string {
  try {
    const raw = atob(b64)
    const bytes = new Uint8Array(raw.length)
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i)
    return hexOf(bytes)
  } catch {
    return ''
  }
}

function hexOf(bytes: Uint8Array): string {
  let out = ''
  for (const b of bytes) out += b.toString(16).padStart(2, '0')
  return out
}

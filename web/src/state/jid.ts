// WhatsApp identifiers.
//
// An identity here is a pair, (lid, pn), with LID primary. A phone number is not
// always knowable — withholding it is what LID is for — so nothing may assume
// one is present, and the two forms of the same person must resolve to the same
// contact or names and pictures attach to the wrong half.

export const SERVER_USER = 's.whatsapp.net'
export const SERVER_LID = 'lid'
export const SERVER_GROUP = 'g.us'
export const SERVER_BROADCAST = 'broadcast'
export const SERVER_NEWSLETTER = 'newsletter'

export interface JID {
  user: string
  server: string
  /** The device suffix, as in 5511999999999:12@s.whatsapp.net. Rare on stored rows. */
  device: string
}

export function parseJID(raw: string): JID {
  const at = raw.lastIndexOf('@')
  if (at < 0) return { user: raw, server: '', device: '' }
  const server = raw.slice(at + 1)
  let user = raw.slice(0, at)
  let device = ''
  const colon = user.indexOf(':')
  if (colon >= 0) {
    device = user.slice(colon + 1)
    user = user.slice(0, colon)
  }
  return { user, server, device }
}

/**
 * STATUS_BROADCAST is the pseudo-chat every status update is filed under.
 *
 * It is not a conversation. WhatsApp addresses status posts to one fixed JID
 * and puts the author in the participant field, so the archive holds them as a
 * single chat containing dozens of unrelated people talking past each other.
 * Storing them that way is right — chat_key is the storage identity, and
 * re-keying per author would re-import every status as a duplicate — but
 * showing them that way is not.
 */
export const STATUS_BROADCAST = 'status@broadcast'

export function isStatus(raw: string): boolean {
  return raw === STATUS_BROADCAST
}

export function isGroup(raw: string): boolean {
  return parseJID(raw).server === SERVER_GROUP
}

/**
 * displayFallback is what to show when no name is known.
 *
 * A phone number is formatted; a LID is not, because it is not a number anyone
 * can dial and printing it as one invites people to try.
 */
export function displayFallback(raw: string): string {
  const jid = parseJID(raw)
  switch (jid.server) {
    case SERVER_GROUP:
      return 'grupo sem nome'
    case SERVER_BROADCAST:
      return jid.user === 'status' ? 'status' : 'lista de transmissão'
    case SERVER_NEWSLETTER:
      return 'canal'
    case SERVER_LID:
      // The digits, not a constant. Every unnamed person used to render as the
      // same string, so ten strangers in one group were one indistinguishable
      // stranger repeated — which is worse than an ugly label, because it reads
      // as one person saying all of it.
      //
      // All of them, not a suffix: this account has 883 distinct group senders,
      // and a four-digit tail collides among that many with near certainty,
      // which would put the bug straight back. Prefixed so it is never mistaken
      // for a phone number, which it is not — hiding the number is what a LID
      // is for.
      return jid.user ? `LID ${jid.user}` : 'sem identificação'
    default:
      return formatPhone(jid.user)
  }
}

/**
 * formatPhone renders a number the way it is dialled locally where possible.
 *
 * Brazilian numbers get the shape a Brazilian expects, since that is where this
 * is used. Everything else keeps the international form rather than being
 * mangled into a layout it does not have.
 */
export function formatPhone(user: string): string {
  if (!/^\d+$/.test(user)) return user
  if (user.startsWith('55') && (user.length === 12 || user.length === 13)) {
    const ddd = user.slice(2, 4)
    const rest = user.slice(4)
    const half = rest.length === 9 ? 5 : 4
    return `+55 (${ddd}) ${rest.slice(0, half)}-${rest.slice(half)}`
  }
  return `+${user}`
}

/** initials are what a placeholder avatar shows. */
export function initials(name: string): string {
  const words = name
    .replace(/[^\p{L}\p{N}\s]/gu, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
  if (words.length === 0) return '#'
  if (words.length === 1) return [...words[0]].slice(0, 2).join('').toUpperCase()
  return (
    [...words[0]][0] + [...words[words.length - 1]][0]
  ).toUpperCase()
}

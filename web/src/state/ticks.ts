/**
 * What the ticks on a message mean.
 *
 * The rule the owner asked for, stated once, as a function of things a test can
 * hand it:
 *
 *   clock      still leaving this tab
 *   ✓ grey     sent, and the server has it
 *   ✓✓ grey    EVERYONE received it
 *   ✓✓ blue    EVERYONE read it
 *   ✓✓✓ blue   EVERYONE played it
 *
 * "Everyone" is why this needs a denominator and why the denominator being
 * unknown is a first-class answer rather than a zero. Two acknowledgements mean
 * everything between two people and almost nothing in a group of forty, so a
 * conversation whose size nobody knows shows one grey tick and says why — never
 * a promotion on a number that was guessed.
 *
 * A pure function, deliberately. No component in this repository is rendered by
 * any test, so anything that lives inside one is untested by construction, and
 * this is the part where being wrong means telling somebody their message was
 * read when it was not.
 */

/** Where a message got to. */
export type Tick = '' | 'pending' | 'sent' | 'delivered' | 'read' | 'played'

/** The acknowledgements a message has collected, as counts of people. */
export interface Acks {
  delivered: number
  read: number
  played: number
  deliveredAt?: Date
  readAt?: Date
  playedAt?: Date
  /** One of our own devices reported reading it: read, but not here. */
  readByUs?: boolean
  retrying?: boolean
  failed?: boolean
}

export function noAcks(): Acks {
  return { delivered: 0, read: 0, played: 0 }
}

/** The parts of a message the rule reads. */
export interface Ticked {
  fromMe: boolean
  type: string
  viewOnce: boolean
  pending?: 'sending' | 'failed' | 'unarchived'
}

export interface TickReport {
  tick: Tick
  /** Why it is not further along, when that needs saying. */
  caveat: string
}

/**
 * playable says whether a third step exists for this message at all.
 *
 * Voice notes and view-once media, and nothing else. Reading this as "has an
 * attachment" would leave every photograph sitting at two blue ticks forever,
 * waiting for a "played" that WhatsApp never sends for a photograph — a message
 * permanently one step short of a state it can never reach.
 */
export function playable(m: Ticked): boolean {
  return m.type === 'ptt' || m.viewOnce
}

/**
 * denominatorFor is how many people have to acknowledge before "everyone" is
 * true.
 *
 * One in a direct conversation. In a group, everybody but us. Undefined when it
 * is not known, and undefined for a broadcast list or a newsletter — neither is
 * a group and neither is a conversation with one other person, so falling
 * through to 1 would paint a message sent to forty people blue the moment one
 * of them read it.
 */
export function denominatorFor(
  chat: { isGroup: boolean; isStatus: boolean; audience?: number } | undefined,
  chatKey: string,
): number | undefined {
  if (!chat) return undefined
  if (chat.isStatus) return undefined
  const server = chatKey.split('@')[1] ?? ''
  if (server === 'broadcast' || server === 'newsletter') return undefined
  if (!chat.isGroup) return 1
  if (!chat.audience || chat.audience < 2) return undefined
  // Everyone but us.
  return chat.audience - 1
}

/**
 * tickReport decides what to draw.
 *
 * The order is highest first, and the comparison is >= rather than ===: a
 * person can leave a group after reading, and a count that has passed the
 * denominator has certainly met it. What it must never do is promote when the
 * count EXCEEDS a denominator it does not trust — see below.
 */
export function tickReport(
  m: Ticked,
  acks: Acks,
  denominator: number | undefined,
): TickReport {
  // Nothing is drawn on somebody else's message. The ticks are a statement
  // about what happened to something we sent.
  if (!m.fromMe) return { tick: '', caveat: '' }
  if (m.pending === 'sending') return { tick: 'pending', caveat: 'ainda enviando' }
  if (m.pending === 'failed') return { tick: '', caveat: 'não foi enviada' }

  if (acks.failed) {
    return { tick: 'sent', caveat: 'o servidor do WhatsApp recusou esta mensagem' }
  }
  if (acks.retrying) {
    // Named, and deliberately not promoted. A message being retried looks
    // delivered from every angle except the one that matters.
    return { tick: 'sent', caveat: 'entrega sendo tentada de novo' }
  }

  if (denominator === undefined || denominator <= 0) {
    return {
      tick: 'sent',
      caveat: 'não dá para dizer "todos" sem saber quantos são nesta conversa',
    }
  }

  // More acknowledgements than there are people. Either somebody has left the
  // group since, or two identifiers of one person were counted apart. Both mean
  // the denominator is not describing this message, so the honest answer is not
  // to promote on it.
  const tooMany = Math.max(acks.delivered, acks.read, acks.played) > denominator
  if (tooMany) {
    return {
      tick: 'sent',
      caveat: `${acks.delivered} confirmações para ${denominator} destinatários — ` +
        'a composição do grupo mudou desde então',
    }
  }

  if (playable(m) && acks.played >= denominator) return { tick: 'played', caveat: '' }
  if (acks.read >= denominator) return { tick: 'read', caveat: '' }
  if (acks.delivered >= denominator) return { tick: 'delivered', caveat: '' }

  if (denominator > 1) {
    return {
      tick: 'sent',
      caveat: `${acks.delivered} de ${denominator} receberam, ${acks.read} leram`,
    }
  }
  return { tick: 'sent', caveat: 'entregue ao servidor do WhatsApp' }
}

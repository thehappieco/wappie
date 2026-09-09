import { t } from '../ui/i18n'
/**
 * Disappearing messages, as a reader sees them.
 *
 * The archive keeps them — that is a deliberate decision, with a legal
 * dimension in some jurisdictions — so the only honest thing to do is say
 * plainly that a message was meant to vanish, and when.
 *
 * The predicate here is wider than the stored flag, for a reason worth stating.
 * `ephemeral` records that the message travelled inside the disappearing
 * envelope, which is what makes it actually vanish on the recipient's phone.
 * `expiration` records the timer it declared. The two normally agree — send.wrap
 * makes sure of it on the way out — but rows that came from a history sync, or
 * from a client that wrote the timer without the wrapper, carry one and not the
 * other. Reading only the flag is why the marker appeared on some messages and
 * not on others that all had an expiry date.
 */

/** The parts of a message this module needs. */
export interface Ephemeral {
  ephemeral: boolean
  expiration: number
  expiresAt?: Date
}

/** Whether the message was meant to disappear. */
export function isEphemeral(m: Ephemeral): boolean {
  return m.ephemeral || m.expiration > 0 || m.expiresAt !== undefined
}

/**
 * Whether the moment it was meant to vanish has passed.
 *
 * `now` is passed in rather than read, so a caller can drive it from a ticking
 * value and have the label change on screen without a reload.
 */
export function hasExpired(m: Ephemeral, now: number): boolean {
  return m.expiresAt !== undefined && m.expiresAt.getTime() <= now
}

/**
 * The chip to draw on the message, or none.
 *
 * "expirada" is deliberately not "apagada": nothing was deleted, and the
 * message is still here. It says the sender's timer has run out — that on every
 * other client in the conversation this text is gone.
 */
export function expiryLabel(m: Ephemeral, now: number): string {
  if (!isEphemeral(m)) return ''
  return hasExpired(m, now) ? t('expirada') : t('temporária')
}

/** WhatsApp's own presets, in seconds. */
export const TIMER_PRESETS = [0, 86_400, 604_800, 7_776_000] as const

/**
 * timerLabel names a disappearing timer.
 *
 * The presets get the words WhatsApp uses, so a setting made here reads the
 * same as one made on the phone. Anything else is spelled out rather than
 * rounded to the nearest preset, because the protocol accepts arbitrary values
 * and a reader has to be able to see one that did not come from a preset.
 */
export function timerLabel(seconds: number): string {
  switch (seconds) {
    case 0:
      return t('desativadas')
    case 86_400:
      return t('24 horas')
    case 604_800:
      return t('7 dias')
    case 7_776_000:
      return t('90 dias')
  }
  if (seconds % 86_400 === 0) return t('{count} dias', { count: seconds / 86_400 })
  if (seconds % 3_600 === 0) return t('{count} horas', { count: seconds / 3_600 })
  if (seconds % 60 === 0) return `${seconds / 60} min`
  return `${seconds} s`
}

// Ticks that survive a reload, and the one acknowledgement that must never
// count.
//
// state.timeline is reassigned wholesale on every live frame — an arriving row
// can be an edit, a deletion or a reaction against a line already on screen, so
// the conversation is reprojected rather than patched. Anything hung on a
// message therefore lives until the next frame and no longer, which is exactly
// why a conversation opened cold showed one grey tick on everything, including
// messages read months ago.

import { beforeEach, describe, expect, it } from 'vitest'

import type { MessageAcks, ReceiptEvent } from '../src/api/protocol'
import { absorbReceipts, acksFor, applyReceipt, forgetReceipts } from '../src/state/receipts'

const holding = () => true

function receipt(over: Partial<ReceiptEvent>): ReceiptEvent {
  return {
    seq: 1,
    device_id: 'd',
    chat_key: '120363000000000000@g.us',
    wa_ids: ['M1'],
    reader_key: '111@lid',
    reader_person: '111@lid',
    kind: 'delivered',
    ts: new Date().toISOString(),
    ...over,
  } as ReceiptEvent
}

beforeEach(() => forgetReceipts())

describe('acknowledgements a page carried', () => {
  it('are there before any live frame arrives', () => {
    absorbReceipts([{ wa_id: 'M1', delivered: 3, read: 2 } satisfies MessageAcks])
    expect(acksFor('M1').delivered).toBe(3)
    expect(acksFor('M1').read).toBe(2)
  })

  // A page can land after a live receipt — the request was in flight while the
  // frame arrived. Receipts only accumulate, so the merge is a maximum and
  // needs no generation counter to be safe against either order.
  it('never lower a count a live frame had already raised', () => {
    applyReceipt(receipt({ reader_person: 'a@lid' }), holding)
    applyReceipt(receipt({ reader_person: 'b@lid' }), holding)
    absorbReceipts([{ wa_id: 'M1', delivered: 1 }])
    expect(acksFor('M1').delivered).toBe(2)
  })

  it('are forgotten when the conversation closes', () => {
    absorbReceipts([{ wa_id: 'M1', delivered: 3 }])
    forgetReceipts()
    expect(acksFor('M1').delivered).toBe(0)
  })
})

describe('counting people rather than events', () => {
  // The same person's phone and laptop both acknowledge. Counting the frames
  // would make a group of eight report eleven readers, and a tick waiting for
  // everyone would wait on a number that does not exist.
  it('counts one person once, however many devices they carry', () => {
    applyReceipt(receipt({ reader_key: '111:12@lid', reader_person: '111@lid' }), holding)
    applyReceipt(receipt({ reader_key: '111:31@lid', reader_person: '111@lid' }), holding)
    expect(acksFor('M1').delivered).toBe(1)
  })

  it('counts two people twice', () => {
    applyReceipt(receipt({ reader_person: '111@lid' }), holding)
    applyReceipt(receipt({ reader_person: '222@lid' }), holding)
    expect(acksFor('M1').delivered).toBe(2)
  })
})

describe('our own acknowledgements', () => {
  // The bug this replaced, and it was on screen. WhatsApp's "sender" receipt is
  // our OWN handset confirming it received a message we sent, stored as a
  // delivery with is_from_me. Counting it drew two grey ticks the instant our
  // own phone acknowledged — in a direct conversation, where the denominator is
  // one, that is every message, with the recipient's phone possibly switched
  // off.
  it('never count as somebody else receiving it', () => {
    applyReceipt(receipt({ is_from_me: true }), holding)
    expect(acksFor('M1').delivered).toBe(0)
  })

  // A read from another of our own devices is worth keeping, apart: the message
  // genuinely was read, just not here.
  it('are reported when one of our own devices read it', () => {
    applyReceipt(receipt({ is_from_me: true, kind: 'read' }), holding)
    expect(acksFor('M1').read).toBe(0)
    expect(acksFor('M1').readByUs).toBe(true)
  })
})

describe('what is not an acknowledgement', () => {
  // A message stuck in retry looks delivered from every angle except the one
  // that matters.
  it('does not let a retry count as a delivery', () => {
    applyReceipt(receipt({ kind: 'retry' }), holding)
    expect(acksFor('M1').delivered).toBe(0)
  })

  it('does not let a server error count as a delivery', () => {
    applyReceipt(receipt({ kind: 'error' }), holding)
    expect(acksFor('M1').delivered).toBe(0)
  })
})

describe('what this tab is not holding', () => {
  // A receipt frame names a device, not a conversation, so every chat of the
  // account arrives here. Without the filter the map grows for the life of the
  // tab and none of it is ever drawn.
  it('is ignored', () => {
    applyReceipt(receipt({ wa_ids: ['ELSEWHERE'] }), (id) => id === 'M1')
    expect(acksFor('ELSEWHERE').delivered).toBe(0)
  })
})

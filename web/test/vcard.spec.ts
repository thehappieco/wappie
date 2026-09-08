import { describe, expect, it } from 'vitest'

import { parse } from '../src/ui/vcard'

// A contact card is text a stranger's phone wrote, stored sealed and opened
// here. Every failure in this file is silent: a name shows up as mojibake, or
// half a name, or the "abrir conversa" button never appears — and the card
// still looks like a card.

describe('reading a card', () => {
  it('prefers the name the sender chose to display', () => {
    const card = parse('BEGIN:VCARD\nN:Laham;Lana;;;\nFN:Lana Laham\nEND:VCARD')
    expect(card.name).toBe('Lana Laham')
  })

  it('assembles a name from its parts when there is no display name', () => {
    // N is the name taken apart by a machine: family first. Rendering it in
    // stored order gives "Laham;Lana", which is not anybody's name.
    const card = parse('BEGIN:VCARD\nN:Laham;Lana;;;\nEND:VCARD')
    expect(card.name).toBe('Lana Laham')
  })

  it('joins a name folded across two lines', () => {
    // A vCard wraps a long value by starting the next line with a space.
    // Reading line by line without this shows half a name and drops the rest.
    const card = parse('BEGIN:VCARD\nFN:Maria Fernanda\n  de Almeida Souza\nEND:VCARD')
    expect(card.name).toBe('Maria Fernanda de Almeida Souza')
  })

  it('decodes quoted-printable, which is how accents arrive', () => {
    // Most names in this archive have an accent in them, and phones send them
    // like this. Reading the bytes as text produces "JoÃ£o" and nothing later
    // can repair it.
    const card = parse(
      'BEGIN:VCARD\nFN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:Jo=C3=A3o Gon=C3=A7alves\nEND:VCARD',
    )
    expect(card.name).toBe('João Gonçalves')
  })

  it('joins a quoted-printable value folded with a trailing equals', () => {
    const card = parse(
      'BEGIN:VCARD\nFN;ENCODING=QUOTED-PRINTABLE:Jo=C3=\n=A3o\nEND:VCARD',
    )
    expect(card.name).toBe('João')
  })

  it('keeps the waid, which is the only thing that opens a conversation', () => {
    // The printed number is written however the sender's phone felt like
    // writing it. waid is WhatsApp's own parameter and is the account.
    const card = parse(
      'BEGIN:VCARD\nFN:Lana\nTEL;type=CELL;type=VOICE;waid=5511988887777:+55 11 98888-7777\nEND:VCARD',
    )
    expect(card.numbers).toHaveLength(1)
    expect(card.numbers[0].waid).toBe('5511988887777')
    expect(card.numbers[0].number).toBe('+55 11 98888-7777')
    expect(card.numbers[0].label).toBe('celular')
  })

  it('refuses a waid that is not a bare number', () => {
    // The card is text somebody else wrote and this becomes a JID.
    const card = parse('BEGIN:VCARD\nTEL;waid=55@evil.example:+55 11 1:END:VCARD')
    expect(card.numbers[0]?.waid).toBe('')
  })

  it('unescapes commas and semicolons in a value', () => {
    const card = parse('BEGIN:VCARD\nNOTE:vizinha\\, prédio B\; portão azul\nEND:VCARD')
    expect(card.notes).toEqual(['vizinha, prédio B; portão azul'])
  })

  it('reads a grouped property, which iOS emits', () => {
    // "item1.TEL" is the same TEL. A parser keying on the whole head loses
    // every number on a card from an iPhone.
    const card = parse('BEGIN:VCARD\nitem1.TEL;waid=5511999998888:+55 11 99999-8888\nEND:VCARD')
    expect(card.numbers[0]?.waid).toBe('5511999998888')
  })

  it('survives a card it cannot make sense of', () => {
    const card = parse('isso não é um vcard')
    expect(card.name).toBe('')
    expect(card.numbers).toHaveLength(0)
  })
})

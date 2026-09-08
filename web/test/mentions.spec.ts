// Mentions, inline.
//
// They used to be a footnote: "menciona Fulano" under the message, because the
// body is rendered as plain text runs — no v-html, deliberately, since the
// archive's whole premise is that nothing untrusted becomes markup. So the
// tokenizer is what makes a mention appear in the sentence, and every failure
// mode here is silent in the same way: the message still renders, correctly,
// just without the thing that told somebody they were tagged.

import { describe, expect, it } from 'vitest'

import { runs, unmatchedMentions } from '../src/ui/format'

const ZE = '5511999999999@s.whatsapp.net'
const ANA = '224437861388494@lid'

describe('mentions in a message body', () => {
  it('highlights the numbers the message actually mentioned', () => {
    const out = runs('bom dia @5511999999999, tudo certo?', [ZE])
    expect(out).toEqual([
      { text: 'bom dia ' },
      { text: '@5511999999999', mention: ZE },
      { text: ', tudo certo?' },
    ])
  })

  // An "@" followed by digits is not a mention by itself. People write "@11"
  // meaning eleven o'clock, and drawing a person there would be an invention —
  // one that also offers a popover claiming an identity nobody sent.
  it('leaves an @number alone when no mention names it', () => {
    expect(runs('chego @11 na padaria', [ZE])).toEqual([{ text: 'chego @11 na padaria' }])
  })

  it('resolves a LID mention by its user part', () => {
    const out = runs('@224437861388494 viu isso?', [ANA])
    expect(out[0]).toEqual({ text: '@224437861388494', mention: ANA })
  })

  // A mention can carry a device suffix on the JID while the text has only the
  // number. Matching the whole JID would miss it, and the reader would see a
  // bare number in a sentence that WhatsApp itself draws as a name.
  it('matches a mention whose JID carries a device suffix', () => {
    const out = runs('oi @5511999999999', ['5511999999999:12@s.whatsapp.net'])
    expect(out[1]?.mention).toBe('5511999999999:12@s.whatsapp.net')
  })

  it('handles several mentions and keeps the text between them', () => {
    const out = runs('@5511999999999 e @224437861388494 vejam', [ZE, ANA])
    expect(out.map((r) => r.mention ?? r.text)).toEqual([ZE, ' e ', ANA, ' vejam'])
  })

  it('still splits links, and does not mistake a number in one for a mention', () => {
    const out = runs('veja https://example.invalid/@5511999999999 agora', [ZE])
    expect(out.filter((r) => r.mention)).toHaveLength(0)
    expect(out.some((r) => r.href === 'https://example.invalid/@5511999999999')).toBe(true)
  })

  it('costs nothing when a message mentions nobody', () => {
    expect(runs('só um texto @11h', [])).toEqual([{ text: 'só um texto @11h' }])
  })
})

describe('mentions the text has no room for', () => {
  // Real, and the reason the footnote survives: an edit can replace the text of
  // a message and leave its mention list behind, and a caption's mentions do
  // not have to appear in the caption at all. Somebody was tagged and told
  // about it; dropping that from the screen would be losing a fact.
  it('reports a mention whose number is not in the body', () => {
    expect(unmatchedMentions('texto corrigido', [ZE, ANA])).toEqual([ZE, ANA])
  })

  it('reports nothing when every mention is inline', () => {
    expect(unmatchedMentions('@5511999999999 oi', [ZE])).toEqual([])
  })

  it('reports only the ones left over', () => {
    expect(unmatchedMentions('@5511999999999 e a outra?', [ZE, ANA])).toEqual([ANA])
  })
})

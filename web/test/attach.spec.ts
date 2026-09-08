import { describe, expect, it } from 'vitest'

import {
  MAX_BYTES,
  animatedWebP,
  extension,
  family,
  fitWithin,
  floorScore,
  losesAnimation,
  mimeFor,
  refuse,
  nameFor,
  offer,
  opusAudio,
  planFor,
  sourceMime,
  unusualVoiceNote,
} from '../src/media/plan'
import { WAVEFORM_BARS, bucket } from '../src/media/probe'

// The decisions taken before a single byte is uploaded.
//
// Every one of them is a refusal or a choice the server cannot make for us, and
// most of them are silent when wrong: an attachment sent under the wrong kind
// arrives and never opens, a caption on a voice note fails the send as an
// internal error, a file over the ceiling uploads completely before being
// refused. Answering here costs nothing and says something useful.

function file(name: string, type = '', size = 1024) {
  return { name, type, size }
}

describe('what sort of file this is', () => {
  it('reads the mime type when there is one', () => {
    expect(family(file('x', 'image/png'))).toBe('image')
    expect(family(file('x', 'video/mp4'))).toBe('video')
    expect(family(file('x', 'audio/ogg'))).toBe('audio')
    expect(family(file('x', 'application/pdf'))).toBe('other')
  })

  it('falls back to the name, because a dragged file often has no type', () => {
    expect(family(file('férias.HEIC'))).toBe('image')
    expect(family(file('clipe.MOV'))).toBe('video')
    expect(family(file('recado.opus'))).toBe('audio')
  })

  it('does not treat an svg as a picture', () => {
    // It is markup, and markup that can carry script. Sending it as a document
    // is both truthful and the only thing a canvas could not mangle.
    expect(family(file('logo.svg', 'image/svg+xml'))).toBe('other')
  })

  it('reads an extension only when there is one to read', () => {
    expect(extension('relatório.PPTX')).toBe('pptx')
    expect(extension('semponto')).toBe('')
    expect(extension('.perfil')).toBe('')
    expect(extension('acaba.com.ponto.')).toBe('')
  })
})

describe('what to offer for a file', () => {
  it('leads with the compressed photo, which is what a phone does', () => {
    expect(offer(file('foto.jpg', 'image/jpeg'))[0]).toBe('photo')
  })

  it('offers HD and "as a file" for every picture', () => {
    const choices = offer(file('foto.jpg', 'image/jpeg'))
    expect(choices).toContain('photo_hd')
    expect(choices).toContain('file')
  })

  it('leads with the file for something that moves', () => {
    // Every other choice for a picture re-encodes through a canvas, which sees
    // one frame. A GIF sent as a photograph arrives frozen and nothing reports
    // that anything was lost.
    expect(offer(file('meme.gif', 'image/gif'))[0]).toBe('file')
  })

  it('leads with the voice note for something recorded as one', () => {
    expect(offer(file('audio.ogg', 'audio/ogg'))[0]).toBe('voice')
    expect(offer(file('recado.opus'))[0]).toBe('voice')
  })

  it('leads with the audio file for anything else', () => {
    // A voice note is Opus in an Ogg container. An mp3 sent as one goes, and
    // most clients play it, and some do not — so it is offered second rather
    // than first, with the doubt written next to it.
    expect(offer(file('musica.mp3', 'audio/mpeg'))[0]).toBe('audio')
    expect(offer(file('nota.m4a', 'audio/mp4'))[0]).toBe('audio')
    expect(offer(file('musica.mp3', 'audio/mpeg'))).toContain('voice')
  })

  it('says which voice notes are made of something unexpected', () => {
    expect(unusualVoiceNote(planFor('voice'), file('m.mp3', 'audio/mpeg'))).toBe(true)
    expect(unusualVoiceNote(planFor('voice'), file('a.ogg', 'audio/ogg; codecs=opus'))).toBe(false)
    expect(unusualVoiceNote(planFor('audio'), file('m.mp3', 'audio/mpeg'))).toBe(false)
  })

  it('recognises Opus however it was labelled', () => {
    expect(opusAudio(file('a.ogg', 'audio/ogg'))).toBe(true)
    expect(opusAudio(file('a.webm', 'audio/webm;codecs=opus'))).toBe(true)
    expect(opusAudio(file('a.wav', 'audio/wav'))).toBe(false)
  })

  it('offers only the file for a spreadsheet', () => {
    expect(offer(file('planilha.xlsx'))).toEqual(['file'])
  })
})

describe('the mime type the recipient renders from', () => {
  it('follows the re-encoding when there is one', () => {
    expect(mimeFor(planFor('photo'), file('foto.png', 'image/png'))).toBe('image/jpeg')
    expect(mimeFor(planFor('sticker'), file('foto.png', 'image/png'))).toBe('image/webp')
  })

  it("keeps the file's own type when nothing is re-encoded", () => {
    expect(mimeFor(planFor('file'), file('foto.png', 'image/png'))).toBe('image/png')
  })

  it('reads the extension when the file claims nothing', () => {
    expect(mimeFor(planFor('file'), file('slides.pptx'))).toContain('presentationml')
    expect(mimeFor(planFor('file'), file('doc.pdf'))).toBe('application/pdf')
  })

  it('falls back to something that renders as a download, not as nothing', () => {
    expect(mimeFor(planFor('file'), file('coisa.qqq'))).toBe('application/octet-stream')
  })

  it('can say what a file already is, ignoring what a plan would make it', () => {
    // Needed because a re-encoding plan does not always re-encode: a picture
    // inside the bound is passed through, and describing those bytes by the
    // format they were going to become is exactly the mistake to avoid.
    expect(sourceMime(file('captura.png', 'image/png'))).toBe('image/png')
    expect(sourceMime(file('captura.png'))).toBe('image/png')
    expect(sourceMime(file('coisa.qqq'))).toBe('application/octet-stream')
  })
})

describe('the name the download is given', () => {
  it('is left alone when the bytes are', () => {
    expect(nameFor(planFor('file'), 'contrato.pdf')).toBe('contrato.pdf')
  })

  it('follows the bytes when they change', () => {
    // A PNG re-encoded as JPEG and still called .png is a file some readers
    // refuse to open.
    expect(nameFor(planFor('photo'), 'captura.png')).toBe('captura.jpg')
    expect(nameFor(planFor('sticker'), 'carinha.png')).toBe('carinha.webp')
  })
})

describe('refusing before spending an upload', () => {
  it('refuses an empty file', () => {
    expect(refusalFor('file', file('vazio.txt', '', 0))).toMatch(/vazio/)
  })

  it('refuses one over the ceiling', () => {
    // The server checks this after streaming the whole thing to WhatsApp, so
    // without the check here the bar fills to the end and then fails.
    expect(refusalFor('video', file('longo.mp4', 'video/mp4', MAX_BYTES + 1))).toMatch(/limite/)
  })

  it('refuses a caption on a voice note', () => {
    expect(refusalFor('voice', file('a.ogg', 'audio/ogg'), 'escuta isso')).toMatch(/legenda/)
  })

  it('refuses a caption on a round video note', () => {
    expect(refusalFor('ptv', file('a.mp4', 'video/mp4'), 'olha')).toMatch(/legenda/)
  })

  it('refuses a caption on a sticker, which the wire would simply drop', () => {
    // Unlike audio, this one is not an error on the server: the sticker branch
    // reads no caption field at all, so the text just evaporates between here
    // and the recipient. That is the worse failure of the two.
    expect(refusalFor('sticker', file('s.webp', 'image/webp'), 'kkk')).toMatch(/legenda/)
  })

  it('allows a caption on a photo, a video and a document', () => {
    expect(refusalFor('photo', file('f.jpg', 'image/jpeg'), 'olha')).toBe('')
    expect(refusalFor('video', file('v.mp4', 'video/mp4'), 'olha')).toBe('')
    expect(refusalFor('file', file('d.pdf', 'application/pdf'), 'segue')).toBe('')
  })

  it('does not mind whitespace that is not a caption', () => {
    expect(refusalFor('voice', file('a.ogg', 'audio/ogg'), '   \n ')).toBe('')
  })
})

describe('what HD means here', () => {
  // There is no HD field in the protobuf this build compiles against. HD is
  // nothing but the resolution of the bytes uploaded, so the bound is the whole
  // of the feature and is worth checking.
  it('never scales a picture up', () => {
    expect(fitWithin(800, 600, 3000)).toEqual({ width: 800, height: 600 })
  })

  it('fits the longest side, whichever it is', () => {
    expect(fitWithin(4000, 3000, 1600)).toEqual({ width: 1600, height: 1200 })
    expect(fitWithin(3000, 4000, 1600)).toEqual({ width: 1200, height: 1600 })
  })

  it('keeps HD above the ordinary bound', () => {
    expect(planFor('photo_hd').maxLongSide).toBeGreaterThan(planFor('photo').maxLongSide)
    expect(planFor('photo_hd').quality).toBeGreaterThan(planFor('photo').quality)
  })

  it('leaves a file alone entirely', () => {
    expect(planFor('file').encodeTo).toBe('')
    expect(planFor('file').maxLongSide).toBe(0)
  })

  it('lets a small photograph through, and never a small sticker', () => {
    // A photograph is happy as a PNG, so one already inside the bound is passed
    // through rather than recompressed. WhatsApp's sticker message is WebP, and
    // a PNG inside one does not render — so that conversion is not optional,
    // however small the picture already is.
    expect(planFor('photo').strictFormat).toBe(false)
    expect(planFor('photo_hd').strictFormat).toBe(false)
    expect(planFor('sticker').strictFormat).toBe(true)
    expect(planFor('sticker').encodeTo).toBe('image/webp')
  })

  it('never rounds a side down to nothing', () => {
    expect(fitWithin(4000, 3, 100).height).toBeGreaterThanOrEqual(1)
  })
})

describe('the forwarded flag', () => {
  it('turns a bare score into a real forward', () => {
    // The server reads the score only inside `if forwarded`, so a score on its
    // own evaporates and the message arrives with no badge at all.
    expect(floorScore(false, 7)).toEqual({ forwarded: true, score: 7 })
  })

  it('floors a flag with no score at one', () => {
    // Forwarded with a score of zero draws no badge either. The flag has to
    // imply at least one hop for the recipient to see anything.
    expect(floorScore(true, 0)).toEqual({ forwarded: true, score: 1 })
  })

  it('leaves an ordinary message alone', () => {
    expect(floorScore(false, 0)).toEqual({ forwarded: false, score: 0 })
  })

  it('keeps five, which is where the label changes', () => {
    expect(floorScore(true, 5)).toEqual({ forwarded: true, score: 5 })
  })
})

describe('a sticker that moves', () => {
  // The shapes below were checked against real files: libwebp's own img2webp
  // writes RIFF/WEBP/VP8X with flag bit 0x02 set, and cwebp writes a still as
  // RIFF/WEBP/VP8 with no extended chunk at all.

  it('reads the animation bit out of the container', () => {
    expect(animatedWebP(webp({ extended: true, animated: true }))).toBe(true)
  })

  it('does not call a still extended WebP animated', () => {
    expect(animatedWebP(webp({ extended: true, animated: false }))).toBe(false)
  })

  it('knows a plain VP8 cannot be animated', () => {
    expect(animatedWebP(webp({ extended: false, animated: false }))).toBe(false)
  })

  it('refuses to guess from truncated bytes', () => {
    expect(animatedWebP(new Uint8Array([0x52, 0x49, 0x46, 0x46]))).toBe(false)
    expect(animatedWebP(new Uint8Array(0))).toBe(false)
  })

  it('is not fooled by something that is not a RIFF at all', () => {
    expect(animatedWebP(new Uint8Array(40).fill(0x41))).toBe(false)
  })
})

describe('warning that a moving image is about to stop moving', () => {
  it('warns for a GIF sent as a photo', () => {
    expect(losesAnimation(planFor('photo'), file('m.gif', 'image/gif'))).toBe(true)
  })

  it('does not warn for a GIF sent as a file', () => {
    expect(losesAnimation(planFor('file'), file('m.gif', 'image/gif'))).toBe(false)
  })

  it('does not warn for a WebP sent as a sticker, which is passed through', () => {
    expect(losesAnimation(planFor('sticker'), file('s.webp', 'image/webp'))).toBe(false)
  })

  it('says nothing about a photograph, which was never moving', () => {
    expect(losesAnimation(planFor('photo'), file('f.jpg', 'image/jpeg'))).toBe(false)
  })
})

describe('the waveform behind a voice note', () => {
  it('is exactly sixty-four bars whatever the recording is', () => {
    expect(bucket(new Float32Array(3)).length).toBe(WAVEFORM_BARS)
    expect(bucket(new Float32Array(48_000 * 600)).length).toBe(WAVEFORM_BARS)
  })

  it('draws silence flat rather than full', () => {
    expect(bucket(new Float32Array(1000))).toEqual(new Array(WAVEFORM_BARS).fill(0))
  })

  it('scales against the recording, so a quiet one is not a flat line', () => {
    const quiet = new Float32Array(WAVEFORM_BARS * 10)
    quiet[0] = 0.01
    expect(bucket(quiet)[0]).toBe(100)
  })

  it('takes the peak, not the mean', () => {
    // Averaging thousands of samples per bar flattens speech into a ribbon.
    // The peak is what makes a voice note look like somebody talking.
    const samples = new Float32Array(WAVEFORM_BARS * 100)
    samples[50] = 1
    const bars = bucket(samples)
    expect(bars[0]).toBe(100)
    expect(bars[1]).toBe(0)
  })

  it('reads a negative swing as loudness, not as silence', () => {
    const samples = new Float32Array(WAVEFORM_BARS)
    samples[0] = -1
    expect(bucket(samples)[0]).toBe(100)
  })

  it('answers with the right shape for nothing at all', () => {
    expect(bucket(new Float32Array(0))).toEqual(new Array(WAVEFORM_BARS).fill(0))
  })
})

// --- helpers ---------------------------------------------------------------

function refusalFor(
  choice: Parameters<typeof planFor>[0],
  f: { name: string; type: string; size: number },
  caption = '',
): string {
  return refuse(planFor(choice), f, caption)
}

/** A RIFF/WEBP header, long enough for the reader to reach the flag byte. */
function webp({ extended, animated }: { extended: boolean; animated: boolean }): Uint8Array {
  const out = new Uint8Array(40)
  const write = (at: number, text: string) => {
    for (let i = 0; i < text.length; i++) out[at + i] = text.charCodeAt(i)
  }
  write(0, 'RIFF')
  write(8, 'WEBP')
  write(12, extended ? 'VP8X' : 'VP8 ')
  if (extended) out[20] = animated ? 0x02 : 0x00
  return out
}

import { afterEach, describe, expect, it, vi } from 'vitest'
import { discard, prepare } from '../src/media/prepare'

const prepared: { previewURL: string }[] = []
afterEach(() => { for (const item of prepared.splice(0)) discard(item); vi.restoreAllMocks() })
describe('previewing unchanged media sent as a document', () => {
  it.each([
    ['song.mp3', 'audio/mpeg', 'audio'], ['recording.m4a', '', 'audio'],
    ['video.mp4', 'video/mp4', 'video'], ['video.mov', '', 'video'], ['notes.pdf', 'application/pdf', 'none'],
  ])('offers the local player for %s without changing bytes or its document delivery', async (name, type, kind) => {
    const file = new File(['original untouched bytes'], name!, { type })
    const result = await prepare(file, 'file'); prepared.push(result)
    expect(result.kind).toBe('document'); expect(result.previewKind).toBe(kind)
    expect(result.blob).toBe(file); expect(await result.blob.text()).toBe('original untouched bytes')
    expect(result.previewURL.startsWith('blob:')).toBe(true)
    const revoke = vi.spyOn(URL, 'revokeObjectURL'); discard(result); prepared.pop()
    expect(revoke).toHaveBeenCalledExactlyOnceWith(result.previewURL)
  })
})

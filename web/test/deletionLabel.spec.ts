import { describe, expect, it } from 'vitest'
import { deletionLabel } from '../src/ui/deletionLabel'

describe('message deletion attribution', () => {
  it('never calls a direct chat deletion a group administrator action', () => {
    expect(deletionLabel(false, { byAuthor: false })).toBe('Apagada por quem enviou')
    expect(deletionLabel(false, { byAuthor: false, byAdmin: true })).toBe('Apagada por quem enviou')
  })
  it('requires explicit evidence before naming an administrator', () => {
    expect(deletionLabel(true, { byAuthor: false })).toBe('Mensagem apagada')
    expect(deletionLabel(true, { byAuthor: false, byAdmin: true })).toBe('Apagada por um administrador do grupo')
    expect(deletionLabel(true, { byAuthor: true })).toBe('Apagada por quem enviou')
  })
})

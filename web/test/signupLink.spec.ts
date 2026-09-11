import { expect, it } from 'vitest'
import { signupLink } from '../src/ui/signupLink'

it('reads invitation and verification links without keeping secrets in the browser URL', () => {
  const parsed = signupLink('https://app.example.test/console?signup=1#invite=abc123&email=reader%2Btest%40example.test&verification=proof')
  expect(parsed).toEqual({ signup: true, invite: 'abc123', email: 'reader+test@example.test', verification: 'proof', cleanURL: 'https://app.example.test/console?signup=1' })
  expect(signupLink('https://app.example.test/console#tab=members').cleanURL).toBe('https://app.example.test/console#tab=members')
  expect(signupLink('https://app.example.test/console?invite=not-a-trusted-fragment').invite).toBe('')
})

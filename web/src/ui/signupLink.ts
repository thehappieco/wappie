/** Secrets arrive in the fragment so they are absent from HTTP and referrer logs. */
export function signupLink(current: string): { signup: boolean; invite: string; email: string; verification: string; cleanURL: string } {
  const url = new URL(current)
  const fragment = new URLSearchParams(url.hash.slice(1))
  const invite = fragment.get('invite') ?? ''
  const email = fragment.get('email') ?? ''
  const verification = fragment.get('verification') ?? ''
  const signup = url.searchParams.get('signup') === '1' || !!invite || !!verification
  for (const key of ['invite', 'email', 'verification']) fragment.delete(key)
  url.hash = fragment.toString()
  return { signup, invite, email, verification, cleanURL: url.toString() }
}

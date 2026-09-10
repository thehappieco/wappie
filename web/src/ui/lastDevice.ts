/** Non-secret browser preference; it never authenticates or grants device access. */
export interface DevicePreferenceScope {
  serverOrigin: string
  userID: string
  workspaceID: string
}
const nilUUID = '00000000-0000-0000-0000-000000000000'
function validID(value: string): boolean {
  return /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(value) && value !== nilUUID
}
function storageKey(scope: DevicePreferenceScope): string | null {
  if (!validID(scope.userID) || !validID(scope.workspaceID)) return null
  try {
    const server = new URL(scope.serverOrigin)
    if (!['https:', 'http:'].includes(server.protocol)) return null
    return `wappie:last-device:v1:${JSON.stringify([server.origin, scope.userID.toLowerCase(), scope.workspaceID.toLowerCase()])}`
  } catch { return null }
}

export function readLastDevice(scope: DevicePreferenceScope | null): string | null {
  if (!scope) return null
  const key = storageKey(scope)
  if (!key) return null
  try {
    const value = localStorage.getItem(key)
    return value && validID(value) ? value.toLowerCase() : null
  } catch { return null }
}

/** Keep across logout; another account/workspace has a separate key. */
export function rememberLastDevice(scope: DevicePreferenceScope | null, deviceID: string): void {
  if (!scope || !validID(deviceID)) return
  const key = storageKey(scope)
  if (!key) return
  try { localStorage.setItem(key, deviceID.toLowerCase()) } catch { /* Storage is optional for opening a number. */ }
}

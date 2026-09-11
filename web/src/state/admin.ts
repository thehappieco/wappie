// The tenant console.
//
// Everything here runs on the connection the reader already has, because the
// two screens are one session: switching does not reconnect, re-derive a key or
// re-read a conversation.
//
// The interesting part is pairing. A device's archive key is generated in this
// file, sealed once per account that should be able to read that WhatsApp
// number, and then dropped — the server receives the public half and a set of
// blobs it cannot open. That is why linking a device belongs in a browser at
// all: anywhere else, the private half would have to travel.

import { reactive, watch } from 'vue'
import { t } from '../ui/i18n'

import { ProtocolError } from '../api/client'
import * as P from '../api/protocol'
import { fromBase64, newUUIDv7, parseUUID, toBase64 } from '../crypto/bytes'
import { generateKeyPair } from '../crypto/hpke'
import { grantRow, Kind, sealDirect } from '../crypto/seal'
import { withDeviceKey } from '../api/auth'
import { connection, credential, refreshCurrentAccess, refreshDevices, state } from './archive'

/** Pairing is a conversation with a phone, so it has states rather than a result. */
export interface PairingState {
  phase: 'idle' | 'starting' | 'waiting' | 'done' | 'failed'
  deviceID: string
  /** The eight characters to type on the phone, as WhatsApp formats them. */
  code: string
  /**
   * The payload behind a QR, replaced roughly every twenty seconds until the
   * window closes. Held as text; the drawing happens in the component.
   */
  qr: string
  expires?: Date
  error: string
  /** Which accounts the new device's key was sealed to. */
  grantedTo: string[]
}

interface AdminState {
  loading: boolean
  error: string

  /** Counters per device id. Filled in after the list draws; they cost a scan. */
  stats: Record<string, P.DeviceStat>
  statsLoaded: boolean

  detail: P.DeviceDetail | null
  detailError: string
  detailLoading: boolean
  deviceBusy: boolean
  pairingTarget: P.DeviceInfo | null

  accounts: P.UserSummary[]

  keys: P.APIKeyInfo[]
  keysError: string
  /** A key in the clear, held only until the person says they have copied it. */
  minted: P.APIKeyCreated | null

  pairing: PairingState
  /** Set after a delete, so the count it removed can be shown. */
  removed: P.DeviceDeleted | null

  grantBusy: boolean
  grantError: string
}

const freshAdmin = (): AdminState => ({
  loading: false,
  error: '',
  stats: {},
  statsLoaded: false,
  detail: null,
  detailError: '',
  detailLoading: false,
  deviceBusy: false,
  pairingTarget: null,
  accounts: [],
  keys: [],
  keysError: '',
  minted: null,
  pairing: { phase: 'idle', deviceID: '', code: '', qr: '', error: '', grantedTo: [] },
  removed: null,
  grantBusy: false,
  grantError: '',
})

let adminGeneration = 0
let detailGeneration = 0
export const admin = reactive<AdminState>(freshAdmin())
watch([() => state.tenantID, () => state.account, () => state.phase === 'locked'], () => {
  adminGeneration++; detailGeneration++; pairingGeneration++; release(); Object.assign(admin, freshAdmin())
}, { flush: 'sync' })
function currentAdmin(): () => boolean {
  const generation = adminGeneration
  const workspace = state.tenantID
  const account = state.account
  return () => generation === adminGeneration && state.tenantID === workspace && state.account === account
}

/** canAdminister mirrors the server's rule, so the UI offers what will work. */
export function canAdminister(): boolean {
  return state.role === 'owner' || state.role === 'admin'
}

function socket() {
  const conn = connection()
  if (!conn) throw new Error('sem conexão com o servidor')
  return conn
}

function say(err: unknown): string {
  if (err instanceof ProtocolError && err.code === 'last_device_reader') return t('Este é o último membro ativo com a chave deste número. Conceda acesso a outra pessoa antes de removê-lo.')
  if (err instanceof ProtocolError) return err.message
  return err instanceof Error ? err.message : String(err)
}

/**
 * load fetches what the console draws.
 *
 * Counters are a separate request because they count rows, which is the one
 * query that grows with the archive. The list draws first and the numbers
 * arrive after, rather than the whole screen waiting on them.
 */
export async function load(): Promise<void> {
  const current = currentAdmin()
  admin.loading = true; admin.error = ''
  try {
    await refreshDevices()
    if (!current()) return
    if (canAdminister()) {
      const users = await socket().request<P.Users>(P.TypeUsersList, {}, P.TypeUsers)
      if (!current()) return
      admin.accounts = users.users ?? []
    } else { admin.accounts = [] }
  } catch (err) { if (current()) admin.error = say(err) }
  finally { if (current()) admin.loading = false }
  if (!current()) return
  void loadStats()
  if (canAdminister()) void loadKeys()
}

export async function loadStats(): Promise<void> {
  const current = currentAdmin()
  try {
    const reply = await socket().request<P.DeviceStats>(P.TypeDevicesStats, {}, P.TypeDeviceStats)
    if (!current()) return
    const byID: Record<string, P.DeviceStat> = {}
    for (const s of reply.stats ?? []) byID[s.device_id] = s
    admin.stats = byID; admin.statsLoaded = true
  } catch { /* Counters are optional; do not hide the usable device list. */ }
}

export async function openDetail(deviceID: string): Promise<void> {
  const active = currentAdmin()
  const generation = ++detailGeneration
  const current = () => active() && generation === detailGeneration
  admin.detail = null; admin.detailError = ''; admin.removed = null; admin.detailLoading = true
  try {
    const detail = await socket().request<P.DeviceDetail>(P.TypeDeviceInfo,
      { device_id: deviceID } satisfies P.DeviceRef, P.TypeDeviceDetail)
    if (current() && detail.device.id === deviceID) admin.detail = detail
  } catch (err) { if (current()) admin.detailError = say(err) }
  finally { if (current()) admin.detailLoading = false }
}

export function closeDetail(): void {
  detailGeneration++
  admin.detail = null; admin.detailError = ''; admin.detailLoading = false
}

/** Permanently deletes a device after the caller has confirmed the full id. */
export async function removeDevice(deviceID: string, unlink = true): Promise<boolean> {
  if (admin.deviceBusy) return false
  const current = currentAdmin()
  admin.deviceBusy = true; admin.detailError = ''
  try {
    const gone = await socket().request<P.DeviceDeleted>(P.TypeDeviceDelete,
      { device_id: deviceID, confirm: deviceID, unlink } satisfies P.DeleteRequest, P.TypeDeviceGone)
    if (!current()) return true
    admin.removed = gone
    if (admin.detail?.device.id === deviceID) closeDetail()
    delete admin.stats[deviceID]
    // Deletion is already committed. A refresh failure must not invite a
    // second destructive operation by pretending the delete itself failed.
    try { await refreshDevices() } catch (err) { if (current()) admin.error = say(err) }
    return true
  } catch (err) {
    if (current()) {
      if (admin.detail?.device.id === deviceID) admin.detailError = say(err)
      else admin.error = say(err)
    }
    return false
  } finally { if (current()) admin.deviceBusy = false }
}

export async function renameDevice(deviceID: string, label: string): Promise<boolean> {
  if (admin.deviceBusy) return false
  const current = currentAdmin()
  admin.deviceBusy = true; admin.detailError = ''
  try {
    const detail = await socket().request<P.DeviceDetail>(P.TypeDeviceRename, { device_id: deviceID, label }, P.TypeDeviceDetail)
    if (!current()) return true
    if (admin.detail?.device.id === deviceID) admin.detail = detail
    try { await refreshDevices() } catch (err) { if (current()) admin.error = say(err) }
    return true
  } catch (err) {
    if (current()) {
      if (admin.detail?.device.id === deviceID) admin.detailError = say(err)
      else admin.error = say(err)
    }
    return false
  } finally { if (current()) admin.deviceBusy = false }
}

export async function stopDevice(deviceID: string): Promise<void> { await setDeviceRunning(deviceID, false) }
export async function startDevice(deviceID: string): Promise<void> { await setDeviceRunning(deviceID, true) }

async function setDeviceRunning(deviceID: string, running: boolean): Promise<void> {
  if (admin.deviceBusy) return
  const current = currentAdmin()
  admin.deviceBusy = true; admin.error = ''; admin.detailError = ''
  try {
    await socket().request(running ? P.TypeDeviceStart : P.TypeDeviceStop,
      { device_id: deviceID } satisfies P.DeviceRef, P.TypeDeviceStatus)
    if (!current()) return
    await refreshDevices()
    if (!current()) return
    if (admin.detail?.device.id === deviceID) {
      const updated = state.devices.find(d => d.id === deviceID)
      if (updated) admin.detail.device = updated
    }
  } catch (err) {
    if (current()) {
      if (admin.detail?.device.id === deviceID) admin.detailError = say(err)
      else admin.error = say(err)
    }
  } finally { if (current()) admin.deviceBusy = false }
}

/** Opens pairing for a pending row, keeping its original key and readers. */
export function preparePairing(device: P.DeviceInfo): void {
  cancelPairing()
  closeDetail()
  admin.pairingTarget = device
}

// ---------------------------------------------------------------------------
// Who can open a device
// ---------------------------------------------------------------------------

/**
 * grantAccess hands one or more accounts the key to a device.
 *
 * It runs here rather than on the server because the server cannot do it: it
 * has never held the device's private key. Whoever grants must already be able
 * to read the device, which is why the password is asked for again — the key
 * is recovered for the length of this call and overwritten after.
 *
 * A grant that fails to seal stops the whole operation. Recording some and not
 * others would leave a list that says people have access when they do not.
 */
export async function grantAccess(
  deviceID: string,
  userIDs: string[],
  password: string,
): Promise<boolean> {
  if (admin.grantBusy) return false
  const current = currentAdmin()
  admin.grantError = ''; admin.grantBusy = true
  try {
    const who = credential()
    if (!who || who.kind !== 'session') throw new Error('conceder acesso exige uma conta, não uma chave de API')
    const targets = admin.accounts.filter((a) => userIDs.includes(a.id))
    if (!targets.length) throw new Error('escolha ao menos uma conta')
    const tenant = parseUUID(state.tenantID), device = parseUUID(deviceID)
    const myID = admin.accounts.find(account => account.email === state.account)?.id
    const readers = await withDeviceKey(
      { serverURL: who.serverURL, email: state.account, password, token: who.token, deviceID },
      async (deviceKey, epoch) => {
        let last: P.Readers | null = null
        for (const target of targets) {
          if (!current()) return null
          const row = await grantRow(tenant, device, parseUUID(target.id), epoch)
          const sealed = await sealDirect(fromBase64(target.public_key), Kind.DeviceGrant, tenant, row, epoch, deviceKey)
          if (!current()) return null
          last = await socket().request<P.Readers>(P.TypeGrantAdd,
            { device_id: deviceID, user_id: target.id, epoch, sealed_dsk: toBase64(sealed) } satisfies P.GrantRequest, P.TypeReaders)
        }
        return last
      },
    )
    if (!current()) return false
    if (readers && admin.detail?.device.id === deviceID) admin.detail.readers = readers.readers
    if (myID && userIDs.includes(myID)) await refreshCurrentAccess()
    return !!readers
  } catch (err) { if (current()) admin.grantError = say(err); return false }
  finally { if (current()) admin.grantBusy = false }
}

/** A revoked key cannot remove the last active reader, as enforced by the server. */
export async function revokeAccess(deviceID: string, userID: string): Promise<boolean> {
  if (admin.grantBusy) return false
  const current = currentAdmin()
  const myID = admin.accounts.find(account => account.email === state.account)?.id
  admin.grantError = ''; admin.grantBusy = true
  try {
    const readers = await socket().request<P.Readers>(P.TypeGrantRevoke,
      { device_id: deviceID, user_id: userID } satisfies P.GrantRevoke, P.TypeReaders)
    if (!current()) return false
    if (admin.detail?.device.id === deviceID) admin.detail.readers = readers.readers
    if (userID === myID) await refreshCurrentAccess()
    return true
  } catch (err) { if (current()) admin.grantError = say(err); return false }
  finally { if (current()) admin.grantBusy = false }
}

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

export async function loadKeys(): Promise<void> {
  const current = currentAdmin()
  admin.keysError = ''
  try {
    const reply = await socket().request<P.APIKeys>(P.TypeKeysList, {}, P.TypeAPIKeys)
    if (current()) admin.keys = reply.keys ?? []
  } catch (err) {
    if (current()) admin.keysError = say(err)
  }
}

export async function createKey(name: string, scope: P.KeyScope, actsAs = ''): Promise<void> {
  admin.keysError = ''
  try {
    admin.minted = await socket().request<P.APIKeyCreated>(
      P.TypeKeyCreate,
      { name, scope, ...(actsAs ? { acts_as: actsAs } : {}) } satisfies P.APIKeyRequest,
      P.TypeAPIKeyNew,
    )
    await loadKeys()
  } catch (err) {
    admin.keysError = say(err)
  }
}

export function dismissMintedKey(): void {
  admin.minted = null
}

export async function revokeKey(prefix: string): Promise<void> {
  admin.keysError = ''
  try {
    await socket().request(
      P.TypeKeyRevoke,
      { prefix } satisfies P.APIKeyRef,
      P.TypeAPIKeyGone,
    )
    await loadKeys()
  } catch (err) {
    admin.keysError = say(err)
  }
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

let stopPairing: (() => void) | null = null
let pairingGeneration = 0

export interface PairInput {
  /** "code" types eight characters on the phone; "qr" is scanned from it. */
  method: 'code' | 'qr'
  /** Required for code pairing, ignored for a QR. */
  phone: string
  label: string
  /** Account ids that should be able to read this device. At least one. */
  grantTo: string[]
  receiptMode: 'passive' | 'active'
  existingDeviceID?: string
}

/**
 * pair links a WhatsApp account and hands out the key that opens it.
 *
 * In order, because the order is the guarantee:
 *
 *  1. A device id is chosen here. A grant binds to the device, so the grants
 *     have to exist before the row does.
 *  2. An archive keypair is generated here.
 *  3. The private half is sealed once per account chosen, to that account's
 *     public key.
 *  4. The public half and the sealed blobs go to the server, which stores
 *     ciphertext it has no key for.
 *  5. The private half is overwritten and dropped.
 *
 * At least one grant is required. The command line allows none because it can
 * print the key for somebody to save; doing that here would put an archive key
 * in a browser's clipboard and in whatever it gets pasted into, which is
 * exactly how the first archive of this project was lost.
 */
export async function pair(input: PairInput): Promise<void> {
  const generation = ++pairingGeneration
  const workspace = state.tenantID
  const current = () => generation === pairingGeneration && workspace === state.tenantID
  admin.pairing = {
    phase: 'starting',
    deviceID: '',
    code: '',
    qr: '',
    error: '',
    grantedTo: [],
  }

  if (input.existingDeviceID) {
    admin.pairing.deviceID = input.existingDeviceID
    admin.pairing.phase = 'waiting'
    try {
      stopPairing = socket().stream(P.TypePair, {
        device_id: input.existingDeviceID, resume: true, method: input.method,
        phone: input.method === 'code' ? input.phone : '', display_name: 'Chrome (Linux)',
      } satisfies P.PairResumeRequest, frame => { void handlePairFrame(frame, generation) })
    } catch (err) { admin.pairing.phase = 'failed'; admin.pairing.error = say(err) }
    return
  }
  const chosen = admin.accounts.filter((a) => input.grantTo.includes(a.id))
  if (chosen.length === 0) {
    admin.pairing.phase = 'failed'
    admin.pairing.error =
      t('Escolha ao menos um membro para acessar as conversas deste número.')
    return
  }

  const deviceID = newUUIDv7()
  const tenant = parseUUID(state.tenantID)
  const device = parseUUID(deviceID)
  let keys: Awaited<ReturnType<typeof generateKeyPair>> | undefined

  try {
    keys = await generateKeyPair()
    if (!current()) return
    const grants: P.KeyGrant[] = []
    for (const account of chosen) {
      const row = await grantRow(tenant, device, parseUUID(account.id), 1)
      const sealed = await sealDirect(
        fromBase64(account.public_key),
        Kind.DeviceGrant,
        tenant,
        row,
        1,
        keys.privateKey,
      )
      if (!current()) return
      grants.push({ user_id: account.id, sealed_dsk: toBase64(sealed) })
    }

    const request: P.PairRequest = {
      label: input.label || input.phone || t('Número do WhatsApp'),
      method: input.method,
      phone: input.method === 'code' ? input.phone : '',
      display_name: 'Chrome (Linux)',
      receipt_mode: input.receiptMode,
      device_id: deviceID,
      archive_public_key: toBase64(keys.publicKey),
      grants,
    }

    admin.pairing.deviceID = deviceID
    admin.pairing.grantedTo = chosen.map((a) => a.email)
    admin.pairing.phase = 'waiting'

    stopPairing = socket().stream(P.TypePair, request, (frame) => {
      void handlePairFrame(frame, generation)
    })
  } catch (err) {
    if (current()) { admin.pairing.phase = 'failed'; admin.pairing.error = say(err) }
  } finally {
    // Whatever happened above, the private half does not outlive this call.
    // It exists in the sealed blobs and nowhere else.
    keys?.privateKey.fill(0)
  }
}

async function handlePairFrame(frame: P.Frame, generation: number): Promise<void> {
  if (generation !== pairingGeneration) return
  switch (frame.t) {
    case P.TypePairCode: {
      const code = frame.p as P.PairCode
      admin.pairing.code = code.code
      admin.pairing.expires = new Date(code.expires)
      break
    }
    case P.TypePairQR: {
      // Replaced rather than accumulated: only the newest one is live, and
      // showing a stale QR is showing something that cannot work.
      const qr = frame.p as P.PairCode
      admin.pairing.qr = qr.code
      admin.pairing.expires = new Date(qr.expires)
      break
    }
    case P.TypePairSuccess:
      admin.pairing.phase = 'done'
      admin.pairing.code = ''
      admin.pairing.qr = ''
      release()
      await refreshPairingDevices(generation, true)
      break
    case P.TypePairTimeout:
      admin.pairingTarget = null
      admin.pairing.phase = 'failed'
      admin.pairing.error =
        t('O código expirou. Você pode conectar o número novamente.')
      release()
      await refreshPairingDevices(generation)
      break
    case P.TypeError: {
      const err = frame.p as P.WireError
      admin.pairing.phase = 'failed'
      admin.pairing.error = err.message
      release()
      await refreshPairingDevices(generation)
      break
    }
  }
}

/**
 * cancelPairing stops an attempt in progress.
 *
 * Both halves matter: the listener stops, and the server is told, because a
 * pairing left running holds a WhatsApp login socket open and a device row that
 * nobody can account for.
 */
export function cancelPairing(): void {
  pairingGeneration++
  const id = admin.pairing.phase === 'waiting' ? admin.pairing.deviceID : ''
  if (id) {
    try {
      socket().send(P.TypePairCancel, '', { device_id: id } satisfies P.DeviceRef)
    } catch {
      // No connection means the server already lost the pairing with it.
    }
  }
  release()
  admin.pairing = { phase: 'idle', deviceID: '', code: '', qr: '', error: '', grantedTo: [] }
  void refreshPairingDevices(pairingGeneration)
}

/** Pairing may finish just as logout/reconnect closes its shared socket. */
async function refreshPairingDevices(generation: number, stats = false): Promise<void> {
  const captured = connection()
  const active = currentAdmin()
  const current = () => generation === pairingGeneration && active() && connection() === captured
  if (!captured || !current()) return
  try {
    await refreshDevices()
    if (stats && current()) await loadStats()
  } catch (error) {
    // Keep the actual pairing outcome. Refresh failures belong to the console
    // and must not be published into another account or pairing attempt.
    if (current()) admin.error = say(error)
  }
}

function release(): void {
  stopPairing?.()
  stopPairing = null
}

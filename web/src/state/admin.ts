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

import { ProtocolError } from '../api/client'
import * as P from '../api/protocol'
import { fromBase64, newUUIDv7, parseUUID, toBase64 } from '../crypto/bytes'
import { generateKeyPair } from '../crypto/hpke'
import { grantRow, Kind, sealDirect } from '../crypto/seal'
import { withDeviceKey } from '../api/auth'
import { connection, credential, refreshDevices, state } from './archive'

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
  accounts: [],
  keys: [],
  keysError: '',
  minted: null,
  pairing: { phase: 'idle', deviceID: '', code: '', qr: '', error: '', grantedTo: [] },
  removed: null,
  grantBusy: false,
  grantError: '',
})

export const admin = reactive<AdminState>(freshAdmin())
watch(() => state.tenantID, () => Object.assign(admin, freshAdmin()), { flush: 'sync' })

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
  admin.loading = true
  admin.error = ''
  try {
    await refreshDevices()
    const users = await socket().request<P.Users>(P.TypeUsersList, {}, P.TypeUsers)
    admin.accounts = users.users ?? []
  } catch (err) {
    admin.error = say(err)
  } finally {
    admin.loading = false
  }
  void loadStats()
  if (canAdminister()) void loadKeys()
}

export async function loadStats(): Promise<void> {
  try {
    const reply = await socket().request<P.DeviceStats>(
      P.TypeDevicesStats,
      {},
      P.TypeDeviceStats,
    )
    const byID: Record<string, P.DeviceStat> = {}
    for (const s of reply.stats ?? []) byID[s.device_id] = s
    admin.stats = byID
    admin.statsLoaded = true
  } catch {
    // Counters are decoration. A device list without them is still the list,
    // and an error banner over "how many messages" would bury the real state.
  }
}

export async function openDetail(deviceID: string): Promise<void> {
  admin.detail = null
  admin.detailError = ''
  admin.removed = null
  // Set before the request, so the sheet opens saying "loading" rather than the
  // click appearing to do nothing while a count runs.
  admin.detailLoading = true
  try {
    admin.detail = await socket().request<P.DeviceDetail>(
      P.TypeDeviceInfo,
      { device_id: deviceID } satisfies P.DeviceRef,
      P.TypeDeviceDetail,
    )
  } catch (err) {
    admin.detailError = say(err)
  } finally {
    admin.detailLoading = false
  }
}

export function closeDetail(): void {
  admin.detail = null
  admin.detailError = ''
  admin.detailLoading = false
}

/**
 * removeDevice deletes a device and everything it archived.
 *
 * The confirm repeats the id because the server insists on it, and the server
 * insists because this is the one call with no way back.
 */
export async function removeDevice(deviceID: string, unlink: boolean): Promise<void> {
  admin.detailError = ''
  try {
    const gone = await socket().request<P.DeviceDeleted>(
      P.TypeDeviceDelete,
      { device_id: deviceID, confirm: deviceID, unlink } satisfies P.DeleteRequest,
      P.TypeDeviceGone,
    )
    admin.removed = gone
    admin.detail = null
    delete admin.stats[deviceID]
    await refreshDevices()
  } catch (err) {
    admin.detailError = say(err)
  }
}

export async function stopDevice(deviceID: string): Promise<void> {
  try {
    await socket().request(
      P.TypeDeviceStop,
      { device_id: deviceID } satisfies P.DeviceRef,
      P.TypeDeviceStatus,
    )
    await refreshDevices()
  } catch (err) {
    admin.error = say(err)
  }
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
): Promise<void> {
  admin.grantError = ''
  admin.grantBusy = true
  try {
    const who = credential()
    if (!who || who.kind !== 'session') {
      throw new Error('conceder acesso exige uma conta, não uma chave de API')
    }
    const targets = admin.accounts.filter((a) => userIDs.includes(a.id))
    if (!targets.length) throw new Error('escolha ao menos uma conta')

    const tenant = parseUUID(state.tenantID)
    const device = parseUUID(deviceID)

    const readers = await withDeviceKey(
      { serverURL: who.serverURL, email: state.account, password, token: who.token, deviceID },
      async (deviceKey, epoch) => {
        let last: P.Readers | null = null
        for (const target of targets) {
          const row = await grantRow(tenant, device, parseUUID(target.id), epoch)
          const sealed = await sealDirect(
            fromBase64(target.public_key),
            Kind.DeviceGrant,
            tenant,
            row,
            epoch,
            deviceKey,
          )
          last = await socket().request<P.Readers>(
            P.TypeGrantAdd,
            {
              device_id: deviceID,
              user_id: target.id,
              epoch,
              sealed_dsk: toBase64(sealed),
            } satisfies P.GrantRequest,
            P.TypeReaders,
          )
        }
        return last
      },
    )
    if (readers && admin.detail) admin.detail.readers = readers.readers
  } catch (err) {
    admin.grantError = say(err)
  } finally {
    admin.grantBusy = false
  }
}

/**
 * revokeAccess removes one account from a device's list.
 *
 * No key is needed: this deletes a row. Which is also the limit of what it
 * does — see the note the sheet shows beside it.
 */
export async function revokeAccess(deviceID: string, userID: string): Promise<void> {
  admin.grantError = ''
  admin.grantBusy = true
  try {
    const readers = await socket().request<P.Readers>(
      P.TypeGrantRevoke,
      { device_id: deviceID, user_id: userID } satisfies P.GrantRevoke,
      P.TypeReaders,
    )
    if (admin.detail) admin.detail.readers = readers.readers
  } catch (err) {
    admin.grantError = say(err)
  } finally {
    admin.grantBusy = false
  }
}

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

export async function loadKeys(): Promise<void> {
  admin.keysError = ''
  try {
    const reply = await socket().request<P.APIKeys>(P.TypeKeysList, {}, P.TypeAPIKeys)
    admin.keys = reply.keys ?? []
  } catch (err) {
    admin.keysError = say(err)
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

export interface PairInput {
  /** "code" types eight characters on the phone; "qr" is scanned from it. */
  method: 'code' | 'qr'
  /** Required for code pairing, ignored for a QR. */
  phone: string
  label: string
  /** Account ids that should be able to read this device. At least one. */
  grantTo: string[]
  receiptMode: 'passive' | 'active'
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
  admin.pairing = {
    phase: 'starting',
    deviceID: '',
    code: '',
    qr: '',
    error: '',
    grantedTo: [],
  }

  const chosen = admin.accounts.filter((a) => input.grantTo.includes(a.id))
  if (chosen.length === 0) {
    admin.pairing.phase = 'failed'
    admin.pairing.error =
      'Escolha ao menos uma conta. Sem isso o aparelho arquiva mensagens que ninguém consegue abrir.'
    return
  }

  const deviceID = newUUIDv7()
  const tenant = parseUUID(state.tenantID)
  const device = parseUUID(deviceID)
  const keys = await generateKeyPair()

  try {
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
      grants.push({ user_id: account.id, sealed_dsk: toBase64(sealed) })
    }

    const request: P.PairRequest = {
      label: input.label || input.phone || 'aparelho',
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
      void handlePairFrame(frame)
    })
  } finally {
    // Whatever happened above, the private half does not outlive this call.
    // It exists in the sealed blobs and nowhere else.
    keys.privateKey.fill(0)
  }
}

async function handlePairFrame(frame: P.Frame): Promise<void> {
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
      await refreshDevices()
      void loadStats()
      break
    case P.TypePairTimeout:
      admin.pairing.phase = 'failed'
      admin.pairing.error =
        'O tempo acabou sem o código ser digitado. Nada foi criado; pode tentar de novo.'
      release()
      await refreshDevices()
      break
    case P.TypeError: {
      const err = frame.p as P.WireError
      admin.pairing.phase = 'failed'
      admin.pairing.error = err.message
      release()
      await refreshDevices()
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
  const id = admin.pairing.deviceID
  if (id) {
    try {
      socket().send(P.TypePairCancel, '', { device_id: id } satisfies P.DeviceRef)
    } catch {
      // No connection means the server already lost the pairing with it.
    }
  }
  release()
  admin.pairing = { phase: 'idle', deviceID: '', code: '', qr: '', error: '', grantedTo: [] }
  void refreshDevices()
}

function release(): void {
  stopPairing?.()
  stopPairing = null
}

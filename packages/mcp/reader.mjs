import { ArchiveClient, ArchiveError, auth, bytes, hpke, seal } from '@whatserver2/client'
import { Opener } from '@whatserver2/client/api/opener'
import { loadCredential, LocalConfigError, readPrivateFile } from './config.mjs'

const locked = () => ({ state: 'locked', reason: 'Encrypted content. Local reading has not been enabled for this MCP server.' })
const omitted = () => ({ state: 'absent' })
const textFields = ['uid', 'device_id', 'wa_id', 'chat_key', 'sender_key', 'sender_lid', 'sender_pn', 'ts', 'kind', 'type', 'source', 'target_uid']
function metadata(message) {
  const result = {}
  for (const key of textFields) if (typeof message[key] === 'string') result[key] = message[key]
  for (const key of ['seq', 'is_from_me', 'is_group', 'view_once', 'ephemeral']) if (typeof message[key] === 'number' || typeof message[key] === 'boolean') result[key] = message[key]
  if (message.media) result.attachment = {
    media_type: message.media.media_type, mimetype: message.media.mimetype,
    file_length: message.media.file_length, download_status: message.media.download_status,
  }
  return result
}
function openedText(value, max) {
  if (value.state === 'ok') return { state: 'ok', value: value.value.slice(0, max), truncated: value.value.length > max }
  if (value.state === 'tampered') return { state: 'tampered' }
  if (value.state === 'absent') return omitted()
  return { state: 'locked', reason: 'The authorized key could not open this content.' }
}
export async function createReader(config) {
  const credential = await loadCredential(config)
  const api = new ArchiveClient({ serverURL: config.server, workspaceID: config.workspace, token: credential.token })
  const allowed = device => !config.device_ids || config.device_ids.includes(device)
  function permit(device) { if (!allowed(device)) throw new ArchiveError('not_authorized', 403) }
  async function withOpener(device, operation) {
    permit(device)
    if (!config.allow_plaintext) return operation(null)
    if (credential.kind === 'session') {
      const password = await readPrivateFile(config.password_file)
      try {
        return await auth.withDeviceKey({ serverURL: config.server, token: credential.token,
          email: credential.email, password: password.toString('utf8').replace(/\r?\n$/, ''), deviceID: device,
          expectedTenantID: config.workspace, expectedUserID: credential.userID,
          signal: AbortSignal.timeout(30_000),
          maxKDF: { m: 128 * 1024, t: 5, p: 4 }, maxAuthResponseBytes: 4 * 1024 * 1024,
        }, async (raw, _epoch, namespace) => operation(new Opener(api.keySource(device), bytes.parseUUID(namespace), bytes.parseUUID(device), device, await hpke.importArchiveKey(raw))))
      } finally { password.fill(0) }
    }
    // Fetch grants on every operation. A locally held key never bypasses a
    // revoked grant, a restricted API key, or current workspace permissions.
    const grants = await api.grants()
    if (grants.user_id !== config.service_user_id) throw new ArchiveError('account_mismatch')
    const grant = grants.grants.find(item => item.device_id === device)
    if (!grant) throw new ArchiveError('not_authorized', 403)
    if (!Number.isSafeInteger(grant.epoch) || grant.epoch < 1 || grant.epoch > 65535) throw new ArchiveError('invalid_grant')
    const data = await readPrivateFile(config.service_key_file)
    let raw, archive
    try {
      const encoded = data.toString('utf8').trim()
      if (!/^[A-Za-z0-9_-]{43}$/.test(encoded)) throw new LocalConfigError('invalid_service_key')
      raw = Buffer.from(encoded, 'base64url')
      if (raw.length !== 32 || raw.toString('base64url') !== encoded) throw new LocalConfigError('invalid_service_key')
      const namespace = bytes.parseUUID(grant.archive_tenant_id || config.workspace)
      const deviceBytes = bytes.parseUUID(device)
      const row = await seal.grantRow(namespace, deviceBytes, bytes.parseUUID(grants.user_id), grant.epoch)
      archive = await seal.openDirect(await hpke.importArchiveKey(raw), seal.Kind.DeviceGrant, namespace, row, bytes.fromBase64(grant.sealed_dsk))
      return await operation(new Opener(api.keySource(device), namespace, deviceBytes, device, await hpke.importArchiveKey(archive)))
    } finally { data.fill(0); raw?.fill(0); archive?.fill(0) }
  }
  async function messages(rows, device, opener) {
    if (rows.some(row => row.device_id !== device)) throw new ArchiveError('device_mismatch')
    await opener?.prefetch(rows.map(row => row.content_key_id))
    return Promise.all(rows.map(async row => ({ ...metadata(row),
      body: row.body_sealed ? opener ? openedText(await opener.body(row), config.max_text_chars) : locked() : omitted(),
      structured_content: row.payload_sealed ? { state: 'unsupported', reason: 'This MCP version does not open structured content.' } : omitted(),
    })))
  }
  return {
    async listNumbers() {
      const reply = await api.listDevices()
      return { workspace_id: config.workspace, plaintext_enabled: config.allow_plaintext,
        numbers: reply.devices.filter(device => allowed(device.id)).map(device => ({
          id: device.id, name: device.label || device.push_name || device.pn || 'Unnamed number',
          phone: device.pn, status: device.status, paused: device.paused === true,
        })),
      }
    },
    async listChats({ device_id, limit }) {
      permit(device_id)
      const reply = await api.listChats(device_id, { limit })
      return withOpener(device_id, async opener => {
        await opener?.prefetch(reply.chats.flatMap(chat => [chat.name_key_id, chat.last_body_key_id]))
        return { workspace_id: config.workspace, device_id, truncated: reply.truncated,
          chats: await Promise.all(reply.chats.map(async chat => ({
            uid: chat.uid, chat_key: chat.chat_key, is_group: chat.is_group === true, last_ts: chat.last_ts,
            name: chat.name_sealed ? opener ? openedText(await opener.chatName(chat), config.max_text_chars) : locked() : omitted(),
            preview: chat.last_body_sealed ? opener ? openedText(await opener.chatPreview(chat), config.max_text_chars) : locked() : omitted(),
          }))),
        }
      })
    },
    async listMessages({ device_id, chat_key, limit, before }) {
      permit(device_id)
      const reply = await api.listMessages(device_id, { chatKey: chat_key, limit, before })
      return withOpener(device_id, async opener => ({ workspace_id: config.workspace, device_id, chat_key: reply.chat_key,
        messages: await messages(reply.messages, device_id, opener), has_more: reply.has_more,
        ...(reply.has_more && reply.next_ts && reply.next_seq !== undefined ? { next: { ts: reply.next_ts, seq: reply.next_seq } } : {}),
      }))
    },
    async getMessage({ device_id, uid }) {
      permit(device_id)
      const reply = await api.getMessage(uid)
      if (reply.device_id !== device_id) throw new ArchiveError('not_authorized', 403)
      return withOpener(device_id, async opener => ({ workspace_id: config.workspace, message: (await messages([reply], device_id, opener))[0] }))
    },
    async listRevisions({ device_id, uid, limit = 50 }) {
      permit(device_id)
      const reply = await api.history(uid)
      if (reply.device_id !== device_id) throw new ArchiveError('not_authorized', 403)
      return withOpener(device_id, async opener => {
        const versions = reply.versions.slice(0, limit)
        const opened = await messages(versions.map(version => version.message), device_id, opener)
        return { workspace_id: config.workspace, device_id, chat_key: reply.chat_key,
          revisions: versions.map((version, index) => ({ revision: version.revision, from: version.from, until: version.until, message: opened[index] })),
          truncated: reply.versions.length > limit, deleted: Boolean(reply.deletion),
        }
      })
    },
  }
}

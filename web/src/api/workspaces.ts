import { endpoint } from './endpoint'
import { credential } from '../state/archive'
import { t } from '../ui/i18n'

export interface Workspace { id: string; name: string; avatar?: string; kind: 'personal' | 'team'; role: string; status: string }
export interface MemberDeviceAccess { device_id: string; label: string; pn?: string; has_key: boolean; read: boolean; send: boolean; manage: boolean }
export interface Member { id: string; email: string; name?: string; avatar?: string; role: string; status: string; last_owner?: boolean; device_access?: MemberDeviceAccess[] }
export interface Permission { device_id: string; user_id: string; read: boolean; send: boolean; manage: boolean; has_key: boolean }
export interface Invitation { id: string; email: string; role: string; status: 'pending' | 'expired' | 'accepted' | 'revoked'; created_at: string; expires_at: string; completed_at: string | null; revoked_at: string | null; can_reveal: boolean }
export class WorkspaceError extends Error { constructor(readonly code: string, message: string) { super(message); this.name = 'WorkspaceError' } }
export async function workspaceRequest<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const auth = credential()
  if (!auth || auth.kind !== 'session') throw new Error(t('Entre com sua conta para gerenciar o espaço.'))
  const response = await fetch(endpoint(auth.serverURL, `/v1/auth/workspaces${path}`), {
    method, cache: 'no-store', headers: { Authorization: `Bearer ${auth.token}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const data = response.status === 204 ? undefined : await response.json()
  if (!response.ok) {
    const messages: Record<string, string> = {
      last_owner: 'O espaço de trabalho precisa manter um proprietário ativo. Promova outra pessoa antes de alterar este acesso.',
      last_device_reader: 'Este é o último membro ativo com a chave deste número. Conceda acesso a outra pessoa antes de removê-lo.',
      last_reader: 'Este é o último membro ativo com a chave deste número. Conceda acesso a outra pessoa antes de removê-lo.',
      invalid_workspace_profile: 'Use um nome de até 80 caracteres e escolha uma imagem válida para o avatar.',
      not_authorized: 'Você não tem permissão para fazer esta alteração neste espaço de trabalho.',
      invite_invalid: 'Este convite não é válido, já foi utilizado ou expirou.',
      invite_email_mismatch: 'Este convite pertence a outro email. Entre com o email convidado. O convite continua válido.',
      personal_workspace: 'O workspace pessoal é exclusivo da sua conta. Crie um workspace Team para convidar pessoas.',
      invite_unavailable: 'Este convite não permite recuperar o código original. Gere um novo convite.',
    }
    throw new WorkspaceError(data?.code ?? 'request_failed', messages[data?.code] ? t(messages[data.code]!) : t('Não foi possível concluir ({status}).', { status: response.status }))
  }
  return data as T
}

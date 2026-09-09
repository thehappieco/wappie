import { endpoint } from './endpoint'
import { credential } from '../state/archive'
import { t } from '../ui/i18n'

export interface Workspace { id: string; name: string; avatar?: string; role: string; status: string }
export interface Member { id: string; email: string; role: string; status: string; last_owner?: boolean }
export interface Permission { device_id: string; user_id: string; read: boolean; send: boolean; manage: boolean; has_key: boolean }

export async function workspaceRequest<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const auth = credential()
  if (!auth || auth.kind !== 'session') throw new Error(t('Entre com sua conta para gerenciar o espaço.'))
  const response = await fetch(endpoint(auth.serverURL, `/v1/auth/workspaces${path}`), {
    method, headers: { Authorization: `Bearer ${auth.token}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const data = response.status === 204 ? undefined : await response.json()
  if (!response.ok) {
    const messages: Record<string, string> = {
      last_owner: 'O espaço de trabalho precisa manter um proprietário ativo. Promova outra pessoa antes de alterar este acesso.',
      invalid_workspace_profile: 'Use um nome de até 80 caracteres e escolha uma imagem válida para o avatar.',
      not_authorized: 'Você não tem permissão para fazer esta alteração neste espaço de trabalho.',
      invite_invalid: 'Este convite não é válido, já foi utilizado ou expirou.',
    }
    throw new Error(messages[data?.code] ? t(messages[data.code]!) : t('Não foi possível concluir ({status}).', { status: response.status }))
  }
  return data as T
}

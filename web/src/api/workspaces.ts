import { endpoint } from './endpoint'
import { credential } from '../state/archive'

export interface Workspace { id: string; name: string; role: string; status: string }
export interface Member { id: string; email: string; role: string; status: string }
export interface Permission { device_id: string; user_id: string; read: boolean; send: boolean; manage: boolean; has_key: boolean }

export async function workspaceRequest<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const auth = credential()
  if (!auth || auth.kind !== 'session') throw new Error('Entre com sua conta para gerenciar o espaço.')
  const response = await fetch(endpoint(auth.serverURL, `/v1/auth/workspaces${path}`), {
    method, headers: { Authorization: `Bearer ${auth.token}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const data = response.status === 204 ? undefined : await response.json()
  if (!response.ok) throw new Error(data?.message || `Não foi possível concluir (${response.status}).`)
  return data as T
}

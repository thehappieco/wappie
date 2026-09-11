import { credential } from '../state/archive'
import { endpoint } from './endpoint'
import { t } from '../ui/i18n'

export interface UserProfile { id: string; email: string; name: string; avatar: string }
export async function profileRequest(profile?: Pick<UserProfile, 'name' | 'avatar'>): Promise<UserProfile> {
  const auth = credential()
  if (auth?.kind !== 'session') throw new Error(t('Entre com sua conta para gerenciar o espaço.'))
  const response = await fetch(endpoint(auth.serverURL, '/v1/auth/profile'), {
    method: profile ? 'PUT' : 'GET', cache: 'no-store',
    headers: { Authorization: `Bearer ${auth.token}`, 'Content-Type': 'application/json' },
    ...(profile ? { body: JSON.stringify(profile) } : {}),
  })
  const data = await response.json()
  if (!response.ok) throw new Error(t('Não foi possível atualizar o perfil. Confira o nome e a imagem e tente novamente.'))
  return data as UserProfile
}

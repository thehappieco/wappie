import { t } from './i18n'

export function deletionLabel(isGroup: boolean, deletion: { byAuthor: boolean; byAdmin?: boolean }): string {
  if (deletion.byAuthor || !isGroup) return t('Apagada por quem enviou')
  if (deletion.byAdmin) return t('Apagada por um administrador do grupo')
  return t('Mensagem apagada')
}

<script setup lang="ts">
import { t } from '../ui/i18n'
import { computed, onBeforeUnmount, ref, watch } from 'vue'

import type { GroupChange, GroupMember } from '../api/protocol'
import { people, state, wantIdentity } from '../state/archive'
import { groups, loadGroup, loadingGroup } from '../state/groups'
import { canChangeGroup, changeGroupParticipants, leaveGroup, participantsFromText, participantsValidation, type ActionOutcome } from '../state/conversationActions'
import { displayFallback } from '../state/jid'
import { stamp } from '../ui/format'
import AvatarBadge from './AvatarBadge.vue'
import Modal from './Modal.vue'

const emit = defineEmits<{ close: [] }>()

const chatKey = computed(() => state.openChatKey)
const group = computed(() => groups.get(chatKey.value))
const busy = computed(() => loadingGroup.key === chatKey.value)
const changing = ref(false)
const adding = ref(false)
const participants = ref('')
const confirmation = ref<{ action: 'remove' | 'leave'; member?: GroupMember }>()
const outcome = ref<ActionOutcome>()
let disposed = false
const canManage = computed(() => canChangeGroup('add'))
const canLeave = computed(() => canChangeGroup('leave'))
const uncertain = computed(() => Boolean(outcome.value?.uncertain))
const ownDevice = computed(() => state.devices.find(device => device.id === state.deviceID))
function isOwnMember(member: GroupMember): boolean {
  return [member.key, member.pn, member.lid].some(value => value && [ownDevice.value?.pn, ownDevice.value?.lid].includes(value))
}
async function addMembers() {
  if (changing.value || uncertain.value || !canManage.value) return
  const list = participantsFromText(participants.value)
  const error = participantsValidation(list)
  if (error) { outcome.value = { ok: false, error }; return }
  changing.value = true; outcome.value = undefined
  try {
    const result = await changeGroupParticipants('add', list)
    if (disposed || result.stale) return
    outcome.value = result
    if (result.ok) { participants.value = ''; adding.value = false }
  } finally { changing.value = false }
}
async function confirmAction() {
  const selected = confirmation.value
  if (!selected || changing.value || uncertain.value) return
  changing.value = true; outcome.value = undefined
  try {
    const result = selected.action === 'leave' ? await leaveGroup() : await changeGroupParticipants('remove', [selected.member!.pn || selected.member!.lid || selected.member!.key])
    if (disposed || result.stale) return
    outcome.value = result
    if (result.ok) confirmation.value = undefined
  } finally { changing.value = false }
}
watch(() => [state.deviceID, state.tenantID, state.openChatKey], () => emit('close'))
onBeforeUnmount(() => { disposed = true })

function nameOf(key: string | undefined, lid?: string, pn?: string): string {
  if (!key && !lid && !pn) return t('alguém')
  const named = people().knownName(lid) || people().knownName(pn) || people().knownName(key)
  if (named) return named
  // Nothing here can name them yet. Asking is what stage one added; until an
  // answer comes back the identifier is drawn, which is honest.
  wantIdentity(key || lid || pn, lid, pn)
  return displayFallback(key || lid || pn || '')
}

function memberName(m: GroupMember): string {
  return nameOf(m.key, m.lid, m.pn)
}

/**
 * A change, in words.
 *
 * "Quem retirou" is the question this table exists to answer, so the author is
 * the subject of the sentence wherever WhatsApp gave one — and where it did
 * not, the sentence says so instead of attributing it to somebody.
 */
function describe(c: GroupChange): string {
  const who = c.actor_key ? nameOf(c.actor_key, c.actor_lid, c.actor_pn) : ''
  const whom = c.subject_key ? nameOf(c.subject_key, c.subject_lid, c.subject_pn) : ''
  switch (c.action) {
    case 'snapshot':
      return t('início do registro — {v0}', { v0: c.detail || 'composição anotada' })
    case 'add':
      return who ? t('{who} adicionou {whom}', { who, whom }) : t('{whom} entrou', { whom })
    case 'remove':
      return who ? t('{who} retirou {whom}', { who, whom }) : t('{whom} saiu', { whom })
    case 'promote':
      return who ? t('{who} tornou {whom} administrador', { who, whom }) : t('{v0} virou admin', { v0: whom })
    case 'demote':
      return who ? t('{v0} tirou o admin de {v1}', { v0: who, v1: whom }) : t('{v0} deixou de ser admin', { v0: whom })
    case 'name':
      return who ? t('{v0} mudou o nome do grupo', { v0: who }) : t('o nome do grupo mudou')
    case 'topic':
      return who ? t('{v0} mudou a descrição', { v0: who }) : t('a descrição mudou')
    case 'ephemeral':
      return t('mensagens temporárias: {v0}', { v0: c.detail || 'alteradas' })
    case 'announce':
      return t('quem pode enviar: {v0}', { v0: c.detail || 'alterado' })
    case 'locked':
      return t('quem edita os dados: {v0}', { v0: c.detail || 'alterado' })
    default:
      return c.action
  }
}
</script>

<template>
  <Modal
    :title="t('Grupo')"
    :subtitle="group ? t('{count} participantes', { count: group.members.length }) : ''"
    @close="emit('close')"
  >
    <template #actions>
      <button class="icon-btn" @click="loadGroup(chatKey)" :title="t('Atualizar')" :disabled="busy || changing">
        ↻
      </button>
    </template>

    <div v-if="busy && !group" class="sealed">{{ t('Perguntando ao WhatsApp…') }}</div>
    <div v-else-if="!group" class="sealed">{{ t('Nada sobre este grupo ainda.') }}</div>

    <template v-else>
      <div v-if="outcome?.error" class="alert" role="alert">{{ outcome.error }}</div>
      <div v-if="outcome?.ok" class="group-action-notice" role="status">
        <p>{{ t('O WhatsApp confirmou a alteração.') }}</p>
        <p v-if="outcome.failed?.length">{{ t('Não foi possível alterar estes participantes: {participants}.', { participants: outcome.failed.join(', ') }) }}</p>
      </div>
      <div v-if="group.permissions_known && !group.is_member" class="group-action-notice">{{ t('Este número não participa mais do grupo. O histórico continua disponível.') }}</div>
      <div v-else-if="!group.permissions_known" class="note">{{ t('Atualize o grupo para confirmar sua permissão no WhatsApp.') }}</div>
      <section v-if="confirmation" class="group-confirm" role="alertdialog" aria-labelledby="group-confirm-title">
        <h3 id="group-confirm-title">{{ confirmation.action === 'leave' ? t('Sair do grupo?') : t('Remover participante?') }}</h3>
        <p>{{ confirmation.action === 'leave' ? t('Este número deixará de receber novas mensagens do grupo. O histórico salvo será mantido.') : t('Remover {name} deste grupo no WhatsApp?', { name: memberName(confirmation.member!) }) }}</p>
        <div class="group-action-buttons"><button type="button" class="ghost" :disabled="changing" @click="confirmation = undefined">{{ t('Cancelar') }}</button><button type="button" class="group-danger" :disabled="changing || uncertain" @click="confirmAction">{{ changing ? t('Aguarde a confirmação…') : confirmation.action === 'leave' ? t('Sair do grupo') : t('Remover participante') }}</button></div>
      </section>
      <section class="section">
        <div class="group-members-title"><h3>{{ t('Participantes ({v0})', { v0: group.members.length }) }}</h3><button v-if="canManage" class="ghost" type="button" :disabled="changing || uncertain || Boolean(confirmation)" @click="adding = !adding">{{ t('Adicionar') }}</button></div>
        <form v-if="adding && canManage" class="group-add-members" @submit.prevent="addMembers">
          <label for="group-add-participants">{{ t('Novos participantes') }}</label>
          <textarea id="group-add-participants" v-model="participants" rows="3" :disabled="changing || uncertain" :placeholder="t('Um número com código do país por linha')" />
          <small>{{ t('Adicione até 32 participantes por vez.') }}</small>
          <div class="group-action-buttons"><button class="ghost" type="button" :disabled="changing" @click="adding = false">{{ t('Cancelar') }}</button><button class="primary" type="submit" :disabled="changing || uncertain">{{ changing ? t('Aguarde a confirmação…') : t('Adicionar participantes') }}</button></div>
        </form>
        <div class="sealed" v-if="!group.refreshed" style="font-size: 12px"> {{ t('Da última vez que o aparelho conseguiu perguntar. Ele não está conectado agora.') }} </div>
        <div v-for="m in group.members" :key="m.key" class="reader">
          <AvatarBadge small :contact-key="m.key" :name="memberName(m)" />
          <div style="flex: 1; min-width: 0">
            <div class="who">{{ memberName(m) }}</div>
            <div class="times">{{ m.key }}</div>
          </div>
          <span v-if="m.is_super_admin" class="flag edited">{{ t('criador') }}</span>
          <span v-else-if="m.is_admin" class="flag edited">{{ t('admin') }}</span>
          <button v-if="canManage && !isOwnMember(m) && !m.is_super_admin" type="button" class="group-remove" :disabled="changing || uncertain || Boolean(confirmation)" :aria-label="t('Remover {name}', { name: memberName(m) })" @click="confirmation = { action: 'remove', member: m }; adding = false">
            <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M16 7h6M11 20H2v-2a5 5 0 0 1 10 0v2M7 3a4 4 0 1 1 0 8 4 4 0 0 1 0-8Z"/></svg>
          </button>
        </div>
      </section>

      <button v-if="canLeave" class="group-leave" type="button" :disabled="changing || uncertain || Boolean(confirmation)" @click="confirmation = { action: 'leave' }; adding = false">{{ t('Sair do grupo') }}</button>

      <section class="section">
        <h3>{{ t('Histórico') }}</h3>
        <!-- Said plainly. WhatsApp does not deliver a group's past, so before
             this date nothing is known — and an empty list is not a group
             nothing ever happened to. A reader cannot tell those apart by
             looking, so the panel tells them. -->
        <div class="note" v-if="group.since"> {{ t('Registrado a partir de {v0}. O WhatsApp não entrega o que aconteceu antes disso, e este histórico não inventa.', { v0: stamp(new Date(group.since)) }) }} </div>
        <div class="sealed" v-if="!group.changes?.length" style="font-size: 12.5px"> {{ t('Nada registrado ainda.') }} </div>
        <div v-for="(c, i) in group.changes ?? []" :key="i" class="version">
          <div class="body">{{ describe(c) }}</div>
          <div class="when">{{ stamp(new Date(c.ts)) }}</div>
        </div>
      </section>
    </template>
  </Modal>
</template>

<style scoped>
.group-members-title { display: flex; gap: 12px; align-items: center; justify-content: space-between; margin-bottom: 14px; }
.group-members-title h3 { margin: 0; } .group-members-title button, .group-action-buttons button { min-height: 44px; border-radius: 10px; padding: 8px 14px; }
.group-add-members { display: grid; gap: 10px; padding: 16px; border: 1px solid var(--line); border-radius: 12px; margin-bottom: 18px; }
.group-add-members label { font-size: 13px; font-weight: 600; } .group-add-members textarea { font-size: 16px; resize: vertical; } .group-add-members small { color: var(--text-dim); }
.group-action-buttons { display: flex; justify-content: flex-end; gap: 10px; flex-wrap: wrap; } .group-confirm { padding: 18px; border: 1px solid var(--danger); border-radius: 14px; margin-bottom: 20px; } .group-confirm h3 { margin: 0 0 10px; } .group-confirm p { color: var(--text-dim); line-height: 1.6; }
.group-danger { color: var(--on-danger); background: var(--danger); } .group-leave { width: 100%; min-height: 46px; color: var(--danger); border: 1px solid var(--line); border-radius: 12px; margin: 5px 0 24px; }
.group-remove { display: grid; place-items: center; flex-shrink: 0; width: 42px; height: 42px; border-radius: 10px; color: var(--danger); } .group-remove:hover { background: var(--bg-hover); }
.group-action-notice { background: var(--bg-active); color: var(--text); padding: 14px 16px; border-radius: 12px; margin-bottom: 16px; font-size: 13px; line-height: 1.55; } .group-action-notice p { margin: 0 0 5px; }
button:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
</style>

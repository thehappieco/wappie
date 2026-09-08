<script setup lang="ts">
import { computed } from 'vue'

import type { GroupChange, GroupMember } from '../api/protocol'
import { people, state, wantIdentity } from '../state/archive'
import { groups, loadGroup, loadingGroup } from '../state/groups'
import { displayFallback } from '../state/jid'
import { stamp } from '../ui/format'
import AvatarBadge from './AvatarBadge.vue'
import Modal from './Modal.vue'

const emit = defineEmits<{ close: [] }>()

const chatKey = computed(() => state.openChatKey)
const group = computed(() => groups.get(chatKey.value))
const busy = computed(() => loadingGroup.key === chatKey.value)

function nameOf(key: string | undefined, lid?: string, pn?: string): string {
  if (!key && !lid && !pn) return 'alguém'
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
      return `início do registro — ${c.detail || 'composição anotada'}`
    case 'add':
      return who ? `${who} adicionou ${whom}` : `${whom} entrou`
    case 'remove':
      return who ? `${who} retirou ${whom}` : `${whom} saiu`
    case 'promote':
      return who ? `${who} tornou ${whom} admin` : `${whom} virou admin`
    case 'demote':
      return who ? `${who} tirou o admin de ${whom}` : `${whom} deixou de ser admin`
    case 'name':
      return who ? `${who} mudou o nome do grupo` : 'o nome do grupo mudou'
    case 'topic':
      return who ? `${who} mudou a descrição` : 'a descrição mudou'
    case 'ephemeral':
      return `mensagens temporárias: ${c.detail || 'alteradas'}`
    case 'announce':
      return `quem pode enviar: ${c.detail || 'alterado'}`
    case 'locked':
      return `quem edita os dados: ${c.detail || 'alterado'}`
    default:
      return c.action
  }
}
</script>

<template>
  <Modal
    :title="'Grupo'"
    :subtitle="group ? `${group.members.length} participantes` : ''"
    @close="emit('close')"
  >
    <template #actions>
      <button class="icon-btn" @click="loadGroup(chatKey)" title="Atualizar" :disabled="busy">
        ↻
      </button>
    </template>

    <div v-if="busy && !group" class="sealed">Perguntando ao WhatsApp…</div>
    <div v-else-if="!group" class="sealed">Nada sobre este grupo ainda.</div>

    <template v-else>
      <section class="section">
        <h3>Participantes ({{ group.members.length }})</h3>
        <div class="sealed" v-if="!group.refreshed" style="font-size: 12px">
          Da última vez que o aparelho conseguiu perguntar. Ele não está conectado agora.
        </div>
        <div v-for="m in group.members" :key="m.key" class="reader">
          <AvatarBadge small :contact-key="m.key" :name="memberName(m)" />
          <div style="flex: 1; min-width: 0">
            <div class="who">{{ memberName(m) }}</div>
            <div class="times">{{ m.key }}</div>
          </div>
          <span v-if="m.is_super_admin" class="flag edited">criador</span>
          <span v-else-if="m.is_admin" class="flag edited">admin</span>
        </div>
      </section>

      <section class="section">
        <h3>Histórico</h3>
        <!-- Said plainly. WhatsApp does not deliver a group's past, so before
             this date nothing is known — and an empty list is not a group
             nothing ever happened to. A reader cannot tell those apart by
             looking, so the panel tells them. -->
        <div class="note" v-if="group.since">
          Registrado a partir de {{ stamp(new Date(group.since)) }}. O WhatsApp não entrega o que
          aconteceu antes disso, e este arquivo não inventa.
        </div>
        <div class="sealed" v-if="!group.changes?.length" style="font-size: 12.5px">
          Nada registrado ainda.
        </div>
        <div v-for="(c, i) in group.changes ?? []" :key="i" class="version">
          <div class="body">{{ describe(c) }}</div>
          <div class="when">{{ stamp(new Date(c.ts)) }}</div>
        </div>
      </section>
    </template>
  </Modal>
</template>

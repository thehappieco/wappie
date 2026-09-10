<script setup lang="ts">
import { t } from '../ui/i18n'
import { computed, ref } from 'vue'

import { state } from '../state/archive'
import { playable as isPlayable } from '../state/ticks'
import { receiptEvidence } from '../state/receiptEvidence'
import ReadersModal from './ReadersModal.vue'
import AppIcon from './AppIcon.vue'
import { stamp, typeLabel } from '../ui/format'
import { deletionLabel } from '../ui/deletionLabel'
import { reactionSummary } from '../ui/reactionGroups'

const emit = defineEmits<{ close: [] }>()

const message = computed(() => state.timeline.find((m) => m.uid === state.selectedUID))
const history = computed(() => state.history)
const currentReactions = computed(() => reactionSummary(message.value?.reactions ?? []))

/** The revision on screen, so the panel can mark which of the versions it is. */
const currentRevision = computed(() => {
  const versions = history.value?.versions ?? []
  return versions.length ? versions[versions.length - 1].revision : 0
})
/**
 * Which version's receipts are being shown. Undefined closes the dialog.
 *
 * Always a version, never the message as a whole. There used to be a -1 for
 * "everything", and it was the one that misled: a reader's delivery time is the
 * earliest across every version, so on a corrected message it answered "did
 * this reach them at all" while sitting under a heading about one revision.
 *
 * A dialog rather than an expander: the list is people, times and devices,
 * which is a page of its own and not a paragraph in the middle of a message's
 * history.
 */
const readersFor = ref<number | undefined>(undefined)

/** Whether this message can produce a played receipt at all. */
const playable = computed(() => (message.value ? isPlayable(message.value) : false))

/** Per-version totals count explicit evidence only, matching the readers dialog. */
function receiptLabel(revision: number): string {
  const rows = (history.value?.readers ?? []).filter((r) => !r.fromMe)
  const got = rows.filter((r) => r.revisions.get(revision)?.delivered).length
  const read = rows.filter((r) => receiptEvidence(r.revisions.get(revision)).read).length
  if (!rows.length) return t('nenhum recibo para esta versão')
  return t('{delivered} receberam · {read} leram', { delivered: got, read })
}
/**
 * replacedAt is when the reaction at i was superseded.
 *
 * By the same person's next reaction, not by the next row: the list is in time
 * order across everybody, so the row below is usually somebody else entirely.
 * WhatsApp allows one standing reaction per party, so the next one that party
 * sent is the one that replaced this.
 */
function replacedAt(i: number): Date | undefined {
  const all = history.value?.reactions ?? []
  const who = all[i]?.who
  return all.slice(i + 1).find((r) => r.who === who)?.at
}
</script>

<template>
  <aside class="panel">
    <div class="topbar">
      <div class="grow">
        <h2>{{ t('O que o WhatsApp esconde') }}</h2>
        <div class="sub" v-if="message">{{ typeLabel(message.type) }} · {{ message.senderName }}</div>
      </div>
      <button class="icon-btn" type="button" @click="emit('close')" :title="t('Fechar')" :aria-label="t('Fechar')">
        <AppIcon name="close" :size="20" />
      </button>
    </div>

    <div class="panel-body">
      <section v-if="message && (currentReactions.total || history?.reactions.length)" class="section current-reactions" aria-labelledby="current-reactions-title">
        <div class="reaction-section-heading"><h3 id="current-reactions-title">{{ t('Reações atuais') }}</h3><span class="reaction-total">{{ currentReactions.total }}</span></div>
        <p class="reaction-explanation">{{ t('Quem está reagindo agora. As alterações anteriores continuam no histórico abaixo.') }}</p>
        <div v-if="!currentReactions.total" class="sealed">{{ t('Nenhuma reação ativa.') }}</div>
        <div v-for="group in currentReactions.groups" :key="group.key" class="current-reaction-group">
          <div class="current-reaction-heading"><span class="current-reaction-emoji" aria-hidden="true">{{ group.emoji }}</span><strong>{{ group.count === 1 ? t('Uma reação') : t('{count} reações', { count: group.count }) }}</strong><span class="reaction-group-description">{{ group.emoji }}</span></div>
          <ul class="current-reactors">
            <li v-for="(reaction, index) in group.reactions" :key="index" :class="{ self: reaction.fromMe }">
              <AppIcon name="users" :size="16" /><span>{{ reaction.fromMe ? t('Você') : reaction.who || t('Participante não identificado') }}</span><small v-if="reaction.fromMe">{{ t('Sua reação') }}</small>
            </li>
          </ul>
        </div>
      </section>

      <div v-if="state.historyLoading" class="sealed">{{ t('Montando a história desta mensagem…') }}</div>
      <div v-else-if="state.historyError" class="alert">{{ state.historyError }}</div>

      <template v-else-if="history">
        <!-- Versions. This is the product: an edit does not replace anything
             here, it adds a link to a chain. -->
        <section class="section">
          <h3 class="history-heading"><AppIcon name="pencil" :size="16" class="history-edited" />{{ t('Versões ({v0})', { v0: history.versions.length }) }}</h3>
          <div
            v-for="version in history.versions"
            :key="version.revision"
            class="version"
            :class="{ current: version.revision === currentRevision }"
          >
            <div class="version-heading"><div class="rev"> {{ t('revisão {v0}', { v0: version.revision }) }} <template v-if="version.revision === 0"> {{ t('· original') }}</template>
              <template v-else-if="version.revision === currentRevision"> {{ t('· atual') }}</template>
            </div><button class="version-info" type="button" aria-haspopup="dialog" :title="t('Confirmações da versão {revision}: {summary}', { revision: version.revision, summary: receiptLabel(version.revision) })" :aria-label="t('Confirmações da versão {revision}: {summary}', { revision: version.revision, summary: receiptLabel(version.revision) })" @click="readersFor = version.revision"><AppIcon name="info" :size="18" /></button></div>
            <div class="body" v-if="version.bodyState === 'ok'">{{ version.body || '—' }}</div>
            <div class="tampered" v-else-if="version.bodyState === 'tampered'"> {{ t('⚠ ADULTERADO OU CHAVE ERRADA') }} </div>
            <!-- Absent and locked are different facts. A location or a photo
                 simply has no text, and calling that a missing key sends
                 someone hunting for a problem that is not there. -->
            <div class="sealed" v-else-if="version.bodyState === 'absent'"> {{ t('sem texto{v0}', { v0: message ? ` — ${typeLabel(message.type)}` : '' }) }}
            </div>
            <div class="sealed" v-else>{{ t('selado — chave indisponível') }}</div>
            <div class="when">
              {{ stamp(version.from) }}
              <template v-if="version.until"> {{ t('até {v0}', { v0: stamp(version.until) }) }}</template>
            </div>

            <!-- Who acknowledged THIS version, in a dialog rather than
                 inline. Always per version, and there is no general list
                 beside it any more: a reader's flat `delivered` is the
                 earliest across every version, so under a revision heading it
                 claims the correction arrived on the strength of the original
                 having done so. Every version is a stanza with a WhatsApp id
                 of its own and collects its own delivery receipts, and that is
                 the number worth showing. -->
          </div>
          <div v-if="history.versions.length === 1" class="sealed" style="font-size: 12.5px"> {{ t('Nunca editada.') }} </div>
        </section>

        <!-- Deletion. The content above survives it, which is the whole point. -->
        <section class="section" v-if="history.deletion">
          <h3 class="history-heading"><AppIcon name="trash" :size="16" class="history-deleted" />{{ t('Apagada') }}</h3>
          <div class="card">
            <div class="title" style="color: var(--danger)">
              {{
                deletionLabel(message?.isGroup ?? false, history.deletion)
              }}
            </div>
            <div class="dim">{{ stamp(history.deletion.at) }}</div>
            <div class="dim"> {{ t('O conteúdo continua acima. O WhatsApp removeu a mensagem; o histórico não.') }} </div>
          </div>
        </section>

        <!-- Reactions, including the ones nobody can see any more. -->
        <!-- A timeline, not a list. The archive kept every reaction row, and
             the sequence is the part WhatsApp does not show: a heart, changed
             to a laugh an hour later, then taken back. -->
        <section class="section" v-if="history.reactions.length">
          <h3>{{ t('Histórico de reações ({count})', { count: history.reactions.length }) }}</h3>
          <div
            v-for="(reaction, i) in history.reactions"
            :key="i"
            class="reader"
            :style="{ opacity: reaction.superseded || reaction.revoked ? 0.55 : 1 }"
          >
            <span style="font-size: 20px">{{ reaction.emoji || '∅' }}</span>
            <div style="flex: 1">
              <div class="who">{{ reaction.who }}</div>
              <div class="times">
                <template v-if="reaction.at">{{ stamp(reaction.at) }}</template>
                <template v-else>{{ t('sem data') }}</template>
                <template v-if="reaction.revoked"> {{ t('· removida') }}<template v-if="reaction.revokedAt"> {{ t('em {v0}', { v0: stamp(reaction.revokedAt) }) }}</template
                  >
                </template>
                <template v-else-if="reaction.superseded"> {{ t('· trocada') }}<template v-if="replacedAt(i)"> {{ t('em {v0}', { v0: stamp(replacedAt(i)!) }) }}</template>
                </template>
                <template v-else-if="!reaction.emoji">{{ t('· retirada (emoji vazio)') }}</template>
                <template v-else>{{ t('· em pé') }}</template>
              </div>
            </div>
          </div>
        </section>

        <!-- No general "quem recebeu e leu" here on purpose. It used to sit
             beside the per-version lists and answer a different question with
             the same words: a reader's delivery time is the earliest across
             every version, so on a corrected message it reported the original
             arriving as though the correction had. Receipts belong to a
             version; the button on each version above is where they are. -->
        <div
          class="sealed"
          v-if="!history.readers.length"
          style="font-size: 12.5px; margin-top: 6px"
        > {{ t('Nenhum recibo arquivado. Em modo discreto o aparelho não devolve recibos, e o que os outros mandam só chega enquanto ele está ligado.') }} </div>
      </template>

      <!-- The routing metadata, which travels readable so the server can
           paginate. Shown plainly rather than hidden, because pretending it is
           private would be the dishonest choice. -->
      <section class="section" v-if="message">
        <h3>{{ t('Metadados') }}</h3>
        <dl class="kv">
          <dt>{{ t('uid') }}</dt>
          <dd>{{ message.uid }}</dd>
          <dt>{{ t('id no WhatsApp') }}</dt>
          <dd>{{ message.waID }}</dd>
          <dt>{{ t('sequência') }}</dt>
          <dd>{{ message.seq }}</dd>
          <dt>{{ t('tipo') }}</dt>
          <dd>{{ message.type }}</dd>
          <dt>{{ t('remetente') }}</dt>
          <dd>{{ message.senderKey || t('(você)') }}</dd>
          <dt>{{ t('enviada em') }}</dt>
          <dd>{{ stamp(message.ts) }}</dd>
          <dt v-if="message.expiresAt">{{ t('expira em') }}</dt>
          <dd v-if="message.expiresAt">{{ stamp(message.expiresAt) }}</dd>
          <dt v-if="message.replyTo">{{ t('responde a') }}</dt>
          <dd v-if="message.replyTo">{{ message.replyTo }}</dd>
          <dt v-if="message.media">{{ t('anexo') }}</dt>
          <dd v-if="message.media">
            {{ message.media.type }} · {{ message.media.status }}
            <template v-if="message.media.mimetype"> · {{ message.media.mimetype }}</template>
          </dd>
        </dl>
      </section>

      <div v-if="!message && !state.historyLoading" class="sealed"> {{ t('Clique em uma mensagem para ver a história dela.') }} </div>
    </div>
  </aside>

  <ReadersModal
    v-if="readersFor !== undefined"
    :revision="readersFor"
    :playable="playable"
    @close="readersFor = undefined"
  />
</template>

<style scoped>
.reaction-section-heading { display: flex; align-items: center; justify-content: space-between; gap: 10px; }.reaction-section-heading h3 { margin-bottom: 0; }.reaction-total { display: grid; place-items: center; min-width: 26px; height: 24px; padding-inline: 6px; border-radius: 8px; background: var(--bg-active); color: var(--text); font-size: 12px; font-weight: 650; font-variant-numeric: tabular-nums; }.reaction-explanation { color: var(--text-dim); font-size: 12px; line-height: 1.5; margin: 8px 0 14px; }
.current-reaction-group { margin-top: 9px; border: 1px solid var(--line); border-radius: 12px; overflow: hidden; }.current-reaction-heading { display: flex; align-items: center; gap: 9px; padding: 10px 12px; background: var(--bg-raised); font-size: 12px; }.current-reaction-emoji { display: inline-flex; justify-content: center; min-width: 26px; font-size: 21px; line-height: 1.2; }.reaction-group-description { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }.current-reactors { margin: 0; padding: 3px 12px; list-style: none; }.current-reactors li { display: flex; align-items: center; gap: 9px; min-height: 39px; padding-block: 7px; color: var(--text); font-size: 13px; }.current-reactors li+li { border-top: 1px solid var(--line); }.current-reactors svg { color: var(--text-dim); flex-shrink: 0; }.current-reactors span { min-width: 0; overflow-wrap: anywhere; }.current-reactors small { margin-inline-start: auto; color: var(--text-dim); font-size: 11px; white-space: nowrap; }
.history-heading { display: flex; align-items: center; gap: 7px; }.history-edited { color: #08704b; }.history-deleted { color: #b32732; }
:root[data-theme='dark'] .history-edited, :root[data-surface='chat'][data-incognito='true'] .history-edited { color: #65d6a2; }
:root[data-theme='dark'] .history-deleted, :root[data-surface='chat'][data-incognito='true'] .history-deleted { color: #ff939b; }
.version-heading { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin: -4px 0 2px; }
.version-info { display: grid; place-items: center; flex-shrink: 0; width: 32px; height: 32px; padding: 0; border: 0; border-radius: 50%; color: var(--message-info); background: transparent; }
.version-info:hover { background: color-mix(in srgb, var(--message-info) 12%, transparent); }
.version-info:focus-visible { outline: 2px solid var(--message-info); outline-offset: 2px; }
@media (pointer: coarse) { .version-info { width: 44px; height: 44px; } }
</style>

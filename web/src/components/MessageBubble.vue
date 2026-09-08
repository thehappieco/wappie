<script setup lang="ts">
import { computed, ref } from 'vue'

import { nowTick } from '../state/actions'
import { discardFailed, loadHistory, people, state, type MessageView } from '../state/archive'
import { expiryLabel } from '../state/ephemeral'
import { displayFallback, formatPhone, parseJID, SERVER_LID, SERVER_USER } from '../state/jid'
import { hhmm, runs, stamp, typeLabel, unmatchedMentions } from '../ui/format'
import MediaBlock from './MediaBlock.vue'
import MessageActions from './MessageActions.vue'
import MessageTicks from './MessageTicks.vue'
import PayloadBlock from './PayloadBlock.vue'

const props = defineProps<{ message: MessageView; showSender: boolean }>()
const emit = defineEmits<{
  (e: 'reply', waID: string): void
  (e: 'edit', uid: string): void
}>()

/**
 * The message this one answers, if it is on the page.
 *
 * Matched on the WhatsApp id, because that is what a reply points at — a uid is
 * this archive's own name for a row and the sender never saw one.
 */
const quoted = computed(() =>
  props.message.replyTo
    ? state.timeline.find((v) => v.waID === props.message.replyTo)
    : undefined,
)

const m = computed(() => props.message)
const selected = computed(() => state.selectedUID === m.value.uid)

const mentions = computed(() => m.value.payload?.mentions ?? [])
const textRuns = computed(() => (m.value.body ? runs(m.value.body, mentions.value) : []))

/**
 * Mentions the text has no place for, shown as a footnote below it.
 *
 * Everything else is inline, which is what WhatsApp does and what a reader
 * expects: the point of a mention is seeing, in the sentence, that it was
 * about you.
 */
const trailing = computed(() => unmatchedMentions(m.value.body ?? '', mentions.value))

/** The mention whose identity popover is open, if any. */
const openMention = ref('')

function toggleMention(jid: string) {
  openMention.value = openMention.value === jid ? '' : jid
}

function mentionText(jid: string): string {
  return '@' + (people().nameFor(jid) || displayFallback(jid))
}

/**
 * What is behind a mention: the two halves of an identity, either of which may
 * be absent. A LID exists precisely so a phone number never has to appear, so
 * "sem telefone" is an ordinary answer and not a gap to apologise for.
 */
function mentionIdentity(jid: string): string[] {
  const known = people().find(jid)
  const server = parseJID(jid).server
  const lid = known?.lid || (server === SERVER_LID ? jid : '')
  const pn = known?.pn || (server === SERVER_USER ? jid : '')
  const out: string[] = []
  if (lid) out.push(lid)
  out.push(pn ? formatPhone(pn) : 'sem telefone')
  return out
}

/**
 * "temporária" while the timer runs, "expirada" once it has passed.
 *
 * Driven by nowTick, which advances every ten seconds, so a message crosses
 * from one to the other on screen rather than at the next reload.
 */
const expiry = computed(() => expiryLabel(m.value, nowTick.value))

const forwardedLabel = computed(() =>
  m.value.forwardingScore >= 5 ? 'encaminhada muitas vezes' : 'encaminhada',
)
</script>

<template>
  <div class="msg" :class="m.fromMe ? 'out' : 'in'">
    <!-- A div rather than a button, and not for style: this element already
         contains buttons of its own from MediaBlock, and a button inside a
         button is invalid — browsers recover from it differently, and the inner
         click is the one that gets lost. -->
    <div
      class="bubble"
      role="button"
      tabindex="0"
      :class="{ on: selected, revoked: m.deleted }"
      @click="loadHistory(m)"
      @keydown.enter.prevent="loadHistory(m)"
      @keydown.space.prevent="loadHistory(m)"
      :title="stamp(m.ts)"
    >
      <MessageActions
        v-if="!m.pending && !m.deleted"
        :message="m"
        @reply="emit('reply', $event)"
        @edit="emit('edit', $event)"
      />

      <!-- The quoted message. m.replyTo has been on the view all along and
           nothing drew it, so a reply looked like an unrelated remark. -->
      <div v-if="quoted" class="quote">
        <div class="quote-who">{{ quoted.fromMe ? 'você' : quoted.senderName }}</div>
        <div class="quote-body" v-if="quoted.bodyState === 'ok' && quoted.body">
          {{ quoted.body }}
        </div>
        <div class="quote-body sealed" v-else>{{ typeLabel(quoted.type) }}</div>
      </div>
      <!-- Honest about the limit: the quoted message may be older than the page
           that is loaded, and saying so beats drawing nothing. -->
      <div v-else-if="m.replyTo" class="quote">
        <div class="quote-body sealed">resposta a uma mensagem de uma página anterior</div>
      </div>
      <!-- In the status feed the author is the whole point: consecutive posts
           are by different people, and unlabelled they read as one rambling
           stranger. -->
      <div v-if="showSender && !m.fromMe && (m.isGroup || m.isStatus)" class="sender">
        {{ m.senderName }}
      </div>

      <div v-if="m.forwarded" class="flag" style="margin-bottom: 3px; display: inline-block">
        ↪ {{ forwardedLabel }}
      </div>

      <MediaBlock v-if="m.media" :message="m" />
      <PayloadBlock v-if="m.payload" :payload="m.payload" :message="m" />

      <!-- The body. Four different things can be true of it and a reader has to
           be able to tell them apart. -->
      <div v-if="m.bodyState === 'ok' && m.body" class="text">
        <template v-for="(run, i) in textRuns" :key="i">
          <a v-if="run.href" :href="run.href" target="_blank" rel="noreferrer noopener">{{
            run.text
          }}</a>
          <!-- A mention renders as the name, in the sentence, the way the
               sender's client drew it. The number is what actually travelled;
               clicking says which identity it was. -->
          <button
            v-else-if="run.mention"
            class="mention"
            type="button"
            @click.stop="toggleMention(run.mention)"
          >
            {{ mentionText(run.mention) }}
            <span v-if="openMention === run.mention" class="mention-id">
              <span v-for="line in mentionIdentity(run.mention)" :key="line">{{ line }}</span>
            </span>
          </button>
          <template v-else>{{ run.text }}</template>
        </template>
      </div>
      <div v-else-if="m.bodyState === 'tampered'" class="tampered">
        ⚠ ADULTERADO OU CHAVE ERRADA
      </div>
      <div v-else-if="m.bodyState === 'locked'" class="sealed">selado — chave indisponível</div>
      <!-- A slot where a message should be. The phone masked this one from
           linked devices, so it is on the handset and will never be here — and
           an archive that promises completeness owes the reader the hole. -->
      <div v-else-if="m.type === 'placeholder'" class="sealed">
        esta mensagem ficou só no celular — o WhatsApp não a entregou aos aparelhos vinculados
      </div>
      <!-- An unsupported message names the protobuf field it carried. It is
           the only clue there is: the payload is sealed, so without the name
           nobody can say what this build would need to learn to read it. -->
      <div v-else-if="!m.media && !m.payload" class="sealed">
        {{ typeLabel(m.type) }}<template v-if="m.unsupported"> — {{ m.unsupported }}</template>
      </div>

      <!-- Only the ones the text could not hold. Repeating every mention below
           a message that already highlights them is noise. -->
      <div v-if="trailing.length" class="dim mentions-extra">
        menciona
        <button
          v-for="jid in trailing"
          :key="jid"
          class="mention"
          type="button"
          @click.stop="toggleMention(jid)"
        >
          {{ mentionText(jid) }}
          <span v-if="openMention === jid" class="mention-id">
            <span v-for="line in mentionIdentity(jid)" :key="line">{{ line }}</span>
          </span>
        </button>
      </div>

      <div class="reactions" v-if="m.reactions.length">
        <span v-for="(r, i) in m.reactions" :key="i" class="reaction" :title="r.who">
          {{ r.emoji }}
        </span>
      </div>

      <!-- A message that has left this tab and not come back from the archive
           yet. It is shown because waiting for a round trip before drawing what
           somebody just typed reads as the message being lost. -->
      <div v-if="m.pending === 'sending'" class="flag">enviando…</div>
      <!-- With a way out of it. A line that never went holds on to whatever it
           was going to send — for an attachment, the whole file — and without
           this there is nothing to do about it but reload the tab. -->
      <div v-else-if="m.pending === 'failed'" class="flag hot" :title="m.failure">
        não enviou — {{ m.failure }}
        <button class="link" @click.stop="discardFailed(m.waID)">descartar</button>
      </div>
      <!-- Sent and not written down. The message is on the recipient's phone;
           this archive will never have a row for it, and saying so is the whole
           point of an archive that claims to be complete. -->
      <div
        v-else-if="m.pending === 'unarchived'"
        class="flag hot"
        title="O servidor enviou a mensagem mas não conseguiu arquivá-la."
      >
        enviada, fora do arquivo
      </div>

      <div class="meta">
        <span v-if="m.viewOnce" class="flag hot">ver uma vez</span>
        <!-- Amber while it is still coming, plain once it has passed: an
             expired message is a statement about the past, not a warning. -->
        <span
          v-if="expiry"
          class="flag"
          :class="{ hot: expiry === 'temporária' }"
          :title="m.expiresAt ? stamp(m.expiresAt) : ''"
          >{{ expiry }}</span
        >
        <!-- Both of these are the point of the archive, so they are stated on
             the message itself rather than only in the panel. -->
        <span v-if="m.edited" class="flag edited">
          editada{{ m.versionCount > 2 ? ` ${m.versionCount - 1}×` : '' }}
        </span>
        <span v-if="m.deleted" class="flag revoked">apagada</span>
        <span>{{ hhmm(m.ts) }}</span>
        <MessageTicks :message="m" />
      </div>
    </div>
  </div>
</template>

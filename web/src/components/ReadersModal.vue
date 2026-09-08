<script setup lang="ts">
import { computed, ref } from 'vue'

import { people, state, type ReaderDeviceView, type ReaderView } from '../state/archive'
import { stamp } from '../ui/format'
import AvatarBadge from './AvatarBadge.vue'
import Modal from './Modal.vue'

// Who acknowledged ONE version of a message.
//
// Always one version, never the message as a whole, and that is the change this
// file exists to record. The panel used to offer both, and the general list was
// the one that lied: `delivered` on a reader is the earliest across every
// version — the answer to "did this reach them at all" — so a message edited
// twice showed the correction as delivered on the strength of the original
// having been. Under a revision heading that is not a rounding error, it is the
// opposite of what the archive knows.
//
// The three lists have different evidential weight and are drawn differently:
//
//   - Recebido is exact. Every version is a stanza with a WhatsApp id of its
//     own and collects its own delivery receipts, which is the whole reason
//     edits are stored as rows rather than folded into the original.
//   - Lido is usually exact too. Editing a message makes it unread again on the
//     recipient's phone, and reading it afresh sends a receipt naming the
//     edit's own stanza — so the receipt names the revision. The chip hedges
//     only where the archive genuinely had to infer, which is our own devices:
//     this client marks a whole line read under the original's id whatever
//     text is on screen.
//   - Tocado only appears when there is a third step to report. Drawing an
//     empty "Tocado" under a sentence invites the reading that nobody played
//     it, when nothing ever could have.

const props = defineProps<{
  revision: number
  /**
   * Whether this message's TYPE can produce a played receipt.
   *
   * A hint, not the whole answer — see playedApplies. The type rule and what
   * clients actually send do not quite line up, and the archive is the tie
   * breaker.
   */
  playable: boolean
}>()
const emit = defineEmits<{ close: [] }>()

const readers = computed(() => state.history?.readers ?? [])
const versions = computed(() => state.history?.versions.length ?? 0)

/** Which reader's devices are expanded. */
const open = ref('')

function toggle(key: string) {
  open.value = open.value === key ? '' : key
}

/** What one party acknowledged about this revision, or nothing. */
function at(r: ReaderView | ReaderDeviceView) {
  return r.revisions.get(props.revision)
}

/** Our own devices, kept apart: "you" is not somebody the message reached. */
const ours = computed(() => readers.value.filter((r) => r.fromMe))
const others = computed(() => readers.value.filter((r) => !r.fromMe))

const delivered = computed(() => others.value.filter((r) => at(r)?.delivered))
const read = computed(() => others.value.filter((r) => at(r)?.read))
const played = computed(() => others.value.filter((r) => at(r)?.played))

function nameOf(r: ReaderView): string {
  return r.fromMe ? 'você (outro aparelho)' : r.name || people().nameFor(r.key)
}

function deviceLabel(d: ReaderDeviceView): string {
  return d.agent > 0 ? `aparelho ${d.agent}.${d.device}` : `aparelho ${d.device}`
}

/**
 * The lists, in the order the ticks go through them.
 *
 * Built here rather than inline in the template so each is a real computed: an
 * array literal in a v-for is rebuilt on every render, and the reactivity that
 * redraws a time as a receipt arrives would be rebuilding the list rather than
 * updating it.
 */
const groups = computed(() => {
  const all = [
    { label: 'Recebido', list: delivered.value, at: (r: ReaderView) => at(r)?.delivered, sure: true },
    { label: 'Lido', list: read.value, at: (r: ReaderView) => at(r)?.read, sure: false },
  ]
  if (playedApplies.value) {
    all.push({ label: 'Tocado', list: played.value, at: (r: ReaderView) => at(r)?.played, sure: false })
  }
  return all
})

/**
 * Whether to draw the third list at all.
 *
 * The type rule says voice notes and view-once media and nothing else, because
 * a photograph never earns a third tick and a section waiting forever for one
 * reads as nobody having played it.
 *
 * But the rule and the traffic disagree at one edge, and in the direction that
 * matters here: this client reports a played receipt when any sound finishes,
 * ordinary audio included, and WhatsApp's own clients are under no obligation
 * to match either rule. So an archived played receipt overrides the type — a
 * receipt that exists must never be hidden by a predicate that says it should
 * not. The type rule then only decides what to do when there is nothing to
 * show, which is the one case it can be wrong about harmlessly.
 */
const playedApplies = computed(() => props.playable || played.value.length > 0)

const empty = computed(() => ({
  Recebido: 'Ninguém confirmou ter recebido esta versão.',
  Lido: 'Ninguém leu esta versão.',
  Tocado: 'Ninguém tocou esta versão.',
}))
</script>

<template>
  <Modal
    :title="versions > 1 ? `Revisão ${revision}` : 'Quem recebeu e leu'"
    :subtitle="`${others.length} destinatários com recibo`"
    @close="emit('close')"
  >
    <div v-if="readers.length === 0" class="sealed" style="font-size: 12.5px">
      Nenhum recibo arquivado para esta mensagem. Em modo discreto o aparelho não devolve recibos,
      e o que os outros mandam só chega enquanto ele está ligado.
    </div>

    <template v-else>
      <div class="note" v-if="versions > 1">
        Cada versão é uma mensagem própria no WhatsApp e junta os próprios recibos, então tudo aqui
        é sobre este texto e não sobre a mensagem. Uma edição volta a marcar a mensagem como não
        lida, e quem lê de novo confirma o id da edição — por isso "lido" costuma vir confirmado, e
        só aparece como deduzido quando o recibo é de um aparelho seu.
      </div>

      <section class="section" v-for="group in groups" :key="group.label">
        <h3>{{ group.label }} ({{ group.list.length }})</h3>
        <div class="sealed" v-if="!group.list.length" style="font-size: 12.5px">
          {{ empty[group.label as keyof typeof empty] }}
        </div>
        <div v-for="r in group.list" :key="r.key" class="reader">
          <AvatarBadge small :contact-key="r.key" :name="nameOf(r)" />
          <div style="flex: 1; min-width: 0">
            <div class="who">{{ nameOf(r) }}</div>
            <div class="times">{{ stamp(group.at(r)) }}</div>
            <!-- One person, several phones. The time above is the earliest
                 across them, because that is when the person got it; the rest
                 is here because a second timestamp is the only evidence a
                 second device exists at all. -->
            <button
              v-if="r.devices.length > 1"
              class="link"
              type="button"
              @click="toggle(r.key + group.label)"
            >
              {{ open === r.key + group.label ? 'ocultar' : r.devices.length + ' aparelhos' }}
            </button>
            <div v-if="open === r.key + group.label" class="devices">
              <div v-for="d in r.devices" :key="d.key" class="device">
                <div class="dim">{{ deviceLabel(d) }}</div>
                <!-- This device's record of THIS version. A device that never
                     received the correction shows nothing here, which is the
                     fact, rather than the message's first delivery time. -->
                <div class="times">
                  <template v-if="at(d)?.delivered">entregue {{ stamp(at(d)!.delivered) }}</template>
                  <template v-else>não recebeu esta versão</template>
                  <template v-if="at(d)?.read"><br />lida {{ stamp(at(d)!.read) }}</template>
                  <template v-if="at(d)?.played">
                    <br />tocada {{ stamp(at(d)!.played) }}
                  </template>
                </div>
              </div>
            </div>
          </div>
          <!-- Only on the read, and only ever on the read: a delivery receipt
               names this version's own stanza, so there is nothing to qualify. -->
          <span
            v-if="!group.sure && group.label === 'Lido'"
            class="saw"
            :class="at(r)?.confirmed ? 'sure' : 'inferred'"
            :title="
              at(r)?.confirmed
                ? 'o recibo de leitura nomeia esta versão'
                : 'deduzido: este aparelho marca a linha inteira pelo id original'
            "
            >{{ at(r)?.confirmed ? 'confirmado' : 'deduzido' }}</span
          >
        </div>
      </section>

      <!-- Ours, apart. Since reading marks messages automatically, our own
           devices now report reads back into this same projection, and folding
           them in would make "you" look like somebody the message reached. -->
      <section class="section" v-if="ours.length">
        <h3>Seus outros aparelhos</h3>
        <div v-for="r in ours" :key="r.key" class="reader">
          <div style="flex: 1; min-width: 0">
            <div class="who">{{ nameOf(r) }}</div>
            <div class="times">
              <template v-if="at(r)?.delivered">entregue {{ stamp(at(r)!.delivered) }}</template>
              <template v-else>não recebeu esta versão</template>
              <template v-if="at(r)?.read"><br />lida {{ stamp(at(r)!.read) }}</template>
            </div>
          </div>
        </div>
      </section>
    </template>
  </Modal>
</template>

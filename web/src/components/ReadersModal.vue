<script setup lang="ts">
import { t } from '../ui/i18n'
import { computed, ref } from 'vue'

import { people, state, type ReaderDeviceView, type ReaderView } from '../state/archive'
import { receiptEvidence } from '../state/receiptEvidence'
import { stamp } from '../ui/format'
import AvatarBadge from './AvatarBadge.vue'
import Modal from './Modal.vue'

// Only explicit per-version evidence enters these lists. A receipt absent from
// the archive does not establish whether somebody read or received the message.

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
  return receiptEvidence(r.revisions.get(props.revision))
}

/** Our own devices, kept apart: "you" is not somebody the message reached. */
const ours = computed(() => readers.value.filter((r) => r.fromMe))
const others = computed(() => readers.value.filter((r) => !r.fromMe))

const delivered = computed(() => others.value.filter((r) => at(r)?.delivered))
const read = computed(() => others.value.filter((r) => at(r)?.read))
const played = computed(() => others.value.filter((r) => at(r)?.played))

function nameOf(r: ReaderView): string {
  return r.fromMe ? t('você (outro aparelho)') : r.name || people().nameFor(r.key)
}

function deviceLabel(d: ReaderDeviceView): string {
  return t('Aparelho {device}', { device: d.agent > 0 ? `${d.agent}.${d.device}` : d.device })
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
    { key: 'delivered', label: t('Recebido'), empty: t('Sem confirmação de entrega desta versão.'), list: delivered.value, at: (r: ReaderView) => at(r).delivered },
    { key: 'read', label: t('Lido'), empty: t('Sem confirmação de leitura desta versão.'), list: read.value, at: (r: ReaderView) => at(r).read },
  ]
  if (playedApplies.value) {
    all.push({ key: 'played', label: t('Tocado'), empty: t('Sem confirmação de reprodução desta versão.'), list: played.value, at: (r: ReaderView) => at(r).played })
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

</script>

<template>
  <Modal
    :title="versions > 1 ? t('Revisão {v0}', { v0: revision }) : t('Quem recebeu e leu')"
    :subtitle="t('{v0} destinatários com recibo', { v0: others.length })"
    @close="emit('close')"
  >
    <div v-if="readers.length === 0" class="sealed" style="font-size: 12.5px"> {{ t('Nenhum recibo arquivado para esta mensagem. Em modo discreto o aparelho não devolve recibos, e o que os outros mandam só chega enquanto ele está ligado.') }} </div>

    <template v-else>
      <div class="note">{{ t('Mostramos apenas confirmações recebidas para esta versão. Sem recibo, não é possível saber se a pessoa leu.') }}</div>

      <section class="section" v-for="group in groups" :key="group.key">
        <h3>{{ group.label }} ({{ group.list.length }})</h3>
        <div class="sealed" v-if="!group.list.length" style="font-size: 12.5px">
          {{ group.empty }}
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
              {{ open === r.key + group.label ? t('ocultar') : r.devices.length + t(' aparelhos') }}
            </button>
            <div v-if="open === r.key + group.label" class="devices">
              <div v-for="d in r.devices" :key="d.key" class="device">
                <div class="dim">{{ deviceLabel(d) }}</div>
                <!-- This device's record of THIS version. A device that never
                     received the correction shows nothing here, which is the
                     fact, rather than the message's first delivery time. -->
                <div class="times">
                  <template v-if="at(d)?.delivered">{{ t('entregue {v0}', { v0: stamp(at(d)!.delivered) }) }}</template>
                  <template v-else>{{ t('Sem confirmação de entrega desta versão.') }}</template>
                  <template v-if="at(d)?.read"><br />{{ t('lida {v0}', { v0: stamp(at(d)!.read) }) }}</template>
                  <template v-if="at(d)?.played">
                    <br />{{ t('tocada {v0}', { v0: stamp(at(d)!.played) }) }}
                  </template>
                </div>
              </div>
            </div>
          </div>
          <span v-if="group.key === 'read'" class="saw sure" :title="t('o recibo de leitura nomeia esta versão')">{{ t('confirmado') }}</span>
        </div>
      </section>

      <!-- Ours, apart. Since reading marks messages automatically, our own
           devices now report reads back into this same projection, and folding
           them in would make "you" look like somebody the message reached. -->
      <section class="section" v-if="ours.length">
        <h3>{{ t('Seus outros aparelhos') }}</h3>
        <div v-for="r in ours" :key="r.key" class="reader">
          <div style="flex: 1; min-width: 0">
            <div class="who">{{ nameOf(r) }}</div>
            <div class="times">
              <template v-if="at(r)?.delivered">{{ t('entregue {v0}', { v0: stamp(at(r)!.delivered) }) }}</template>
              <template v-else>{{ t('Sem confirmação de entrega desta versão.') }}</template>
              <template v-if="at(r)?.read"><br />{{ t('lida {v0}', { v0: stamp(at(r)!.read) }) }}</template>
              <template v-else-if="r.read"><br />{{ t('Há um recibo de leitura da mensagem, sem confirmação desta versão.') }}</template>
            </div>
          </div>
        </div>
      </section>
    </template>
  </Modal>
</template>

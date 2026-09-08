<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch, watchEffect } from 'vue'

import type { Session } from './state/session'
import { installMobileNavigation } from './ui/mobileNavigation'
import { start, state, stop } from './state/archive'
import AdminView from './components/AdminView.vue'
import ChatList from './components/ChatList.vue'
import ConversationView from './components/ConversationView.vue'
import ForensicPanel from './components/ForensicPanel.vue'
import GroupPanel from './components/GroupPanel.vue'
import SignInView from './components/SignInView.vue'

const showPanel = computed(() => Boolean(state.selectedUID))
const mobileQuery = window.matchMedia('(max-width: 760px), (max-height: 500px) and (pointer: coarse)')
const isMobile = ref(mobileQuery.matches)
const screenDepth = computed(() => !isMobile.value || state.phase !== 'ready' || state.view !== 'archive'
  ? 0 : !state.openChatKey ? 0 : showPanel.value || state.groupPanel ? 2 : 1)

function closeTo(depth: number) {
  if (depth < 1) {
    state.openChatKey = ''
    state.openChatName = ''
  }
  if (depth < 2) {
    closePanel()
    state.groupPanel = false
  }
}

const navigation = installMobileNavigation({ getDepth: () => screenDepth.value, closeTo })
watch(screenDepth, () => navigation.sync(), { flush: 'sync' })

function updateViewport() {
  isMobile.value = mobileQuery.matches
  const viewport = window.visualViewport
  // Respect pinch zoom; the keyboard changes height without changing scale.
  if (viewport && viewport.scale !== 1) return
  document.documentElement.style.setProperty('--app-height', `${viewport?.height ?? window.innerHeight}px`)
  document.documentElement.style.setProperty('--app-top', `${viewport?.offsetTop ?? 0}px`)
}

onMounted(() => {
  updateViewport()
  window.addEventListener('resize', updateViewport)
  mobileQuery.addEventListener('change', updateViewport)
  window.visualViewport?.addEventListener('resize', updateViewport)
  window.visualViewport?.addEventListener('scroll', updateViewport)
})

async function opened(session: Session) {
  await start(session)
}

function closePanel() {
  state.selectedUID = ''
  state.history = null
}

/**
 * The palette follows the discreet posture.
 *
 * On the root element rather than on the shell, because the page background is
 * painted by `body`, and a dark app inside a light page is worse than either.
 *
 * Read from `state.quiet` deliberately, and not re-derived from the device's
 * receipt_mode. That flag is where the server's answer lands, and it is the
 * same value that opens and closes the read-receipt and typing gates
 * (applyReceiptMode). Deriving the colour separately would let the screen and
 * the behaviour disagree — a grey window while receipts are still going out is
 * worse than no colour change at all, because the whole point of the palette is
 * that somebody can tell the posture at a glance and act on it.
 *
 * Nothing is set before an archive is open: the sign-in screen has no device
 * and no posture to report.
 */
watchEffect(() => {
  const root = document.documentElement
  if (state.phase === 'ready' && state.quiet) root.dataset.theme = 'quiet'
  else delete root.dataset.theme
})

onBeforeUnmount(() => {
  navigation.dispose()
  window.removeEventListener('resize', updateViewport)
  mobileQuery.removeEventListener('change', updateViewport)
  window.visualViewport?.removeEventListener('resize', updateViewport)
  window.visualViewport?.removeEventListener('scroll', updateViewport)
  document.documentElement.style.removeProperty('--app-height')
  document.documentElement.style.removeProperty('--app-top')
  delete document.documentElement.dataset.theme
  stop()
})
</script>

<template>
  <SignInView v-if="state.phase === 'locked'" @opened="opened" />

  <div v-else-if="state.phase === 'connecting'" class="empty app-loading" role="status" aria-live="polite">
    <div>
      <div class="loading-spinner" aria-hidden="true" />
      <div class="big">Abrindo suas conversas…</div>
      <div>Preparando uma conexão segura.</div>
    </div>
  </div>

  <div v-else-if="state.phase === 'error'" class="unlock">
    <div class="unlock-card">
      <h1>Não deu para conectar</h1>
      <div class="alert">{{ state.error }}</div>
      <button class="primary" @click="stop">Voltar</button>
    </div>
  </div>

  <AdminView v-else-if="state.view === 'admin'" @read="state.view = 'archive'" />

  <div v-else class="shell" :class="{ 'with-panel': showPanel, 'chat-open': Boolean(state.openChatKey) }">
    <ChatList />
    <ConversationView v-if="state.openChatKey" @back="closeTo(0)" />
    <section v-else class="conversation">
      <div class="empty">
        <div>
          <div class="big">{{ state.chats.length }} conversas arquivadas</div>
          <div>Escolha uma à esquerda. Clique em qualquer mensagem para ver a história dela.</div>
        </div>
      </div>
    </section>
    <ForensicPanel v-if="showPanel" @close="closePanel" />
    <!-- The group is a dialog over the page rather than a column beside it:
         a panel is part of the layout, so its content competes for height with
         the message list and moves the composer around. -->
    <GroupPanel v-if="state.groupPanel" @close="state.groupPanel = false" />
  </div>
</template>

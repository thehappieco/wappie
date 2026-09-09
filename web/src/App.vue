<script setup lang="ts">
import { t } from './ui/i18n'
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

// Privacy is a device mode; appearance remains the reader's explicit preference.
watchEffect(() => {
  const root = document.documentElement
  if (state.phase === 'ready' && state.quiet) root.dataset.incognito = 'true'
  else delete root.dataset.incognito
})

onBeforeUnmount(() => {
  navigation.dispose()
  window.removeEventListener('resize', updateViewport)
  mobileQuery.removeEventListener('change', updateViewport)
  window.visualViewport?.removeEventListener('resize', updateViewport)
  window.visualViewport?.removeEventListener('scroll', updateViewport)
  document.documentElement.style.removeProperty('--app-height')
  document.documentElement.style.removeProperty('--app-top')
  delete document.documentElement.dataset.incognito
  stop()
})
</script>

<template>
  <SignInView v-if="state.phase === 'locked'" @opened="opened" />

  <div v-else-if="state.phase === 'connecting'" class="empty app-loading" role="status" aria-live="polite">
    <div>
      <div class="loading-spinner" aria-hidden="true" />
      <div class="big">{{ t('Abrindo suas conversas…') }}</div>
      <div>{{ t('Preparando uma conexão segura.') }}</div>
    </div>
  </div>

  <div v-else-if="state.phase === 'error'" class="unlock">
    <div class="unlock-card">
      <h1>{{ t('Não deu para conectar') }}</h1>
      <div class="alert">{{ state.error }}</div>
      <button class="primary" @click="stop">{{ t('Voltar') }}</button>
    </div>
  </div>

  <AdminView v-else-if="state.view === 'admin'" @read="state.view = 'archive'" />

  <div v-else class="shell" :class="{ 'with-panel': showPanel, 'chat-open': Boolean(state.openChatKey) }">
    <ChatList />
    <ConversationView v-if="state.openChatKey" @back="closeTo(0)" />
    <section v-else class="conversation">
      <div class="empty">
        <div>
          <div class="big">{{ t('{v0} conversas no histórico', { v0: state.chats.length }) }}</div>
          <div>{{ t('Escolha uma conversa para começar. As ações da mensagem incluem resposta, reações e informações.') }}</div>
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

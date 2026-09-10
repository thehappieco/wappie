<script setup lang="ts">
import { t } from './ui/i18n'
import { computed, onBeforeUnmount, onMounted, ref, watch, watchEffect } from 'vue'

import { restoreAccountSession, type Session } from './state/session'
import { browserSessionWasCleared, observeBrowserSession } from './state/sessionBridge'
import { installMobileNavigation } from './ui/mobileNavigation'
import { applyPrivacyAppearance } from './ui/preferences'
import { start, state, stop } from './state/archive'
import AdminView from './components/AdminView.vue'
import ChatList from './components/ChatList.vue'
import ConversationView from './components/ConversationView.vue'
import ForensicPanel from './components/ForensicPanel.vue'
import GroupPanel from './components/GroupPanel.vue'
import SignInView from './components/SignInView.vue'

const showPanel = computed(() => Boolean(state.selectedUID))
const restoring = ref(true)
const opening = ref(false)
const restoreError = ref('')
const persistenceNotice = ref('')
let activePersistenceID: string | undefined
let activePersistenceEpoch: string | undefined
let pendingPersistenceID: string | undefined
let restoreAttempt = 0
let disposed = false
const unobserveSession = observeBrowserSession(change => {
  if (change.id !== activePersistenceID && change.id !== pendingPersistenceID) return
  restoreAttempt++
  pendingPersistenceID = undefined
  activePersistenceID = undefined
  restoring.value = false
  opening.value = false
  restoreError.value = ''
  stop({ logout: false })
})
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
  void restore()
})

async function opened(session: Session) {
  const attempt = ++restoreAttempt
  opening.value = true
  // The previous logout may still be clearing persistent storage. Its late
  // notification cannot cancel the different login now being opened.
  activePersistenceID = undefined
  activePersistenceEpoch = undefined
  pendingPersistenceID = session.persistenceID
  persistenceNotice.value = session.notice ?? ''
  try { await session.remember?.() }
  catch { persistenceNotice.value = t('Este navegador não permitiu guardar a sessão. Você poderá precisar entrar novamente ao recarregar a página.') }
  if (disposed || attempt !== restoreAttempt || session.persistenceID && browserSessionWasCleared(session.persistenceID, session.persistenceEpoch)) {
    if (attempt === restoreAttempt) opening.value = false
    session.dispose?.(); return
  }
  pendingPersistenceID = undefined
  activePersistenceID = session.persistenceID
  activePersistenceEpoch = session.persistenceEpoch
  const starting = start(session)
  opening.value = false
  await starting
}

async function restore() {
  const attempt = ++restoreAttempt
  opening.value = false
  restoring.value = true
  restoreError.value = ''
  try {
    const workspace = new URLSearchParams(location.search).get('workspace') || undefined
    const session = await restoreAccountSession(workspace, id => { if (attempt === restoreAttempt) pendingPersistenceID = id })
    if (disposed || attempt !== restoreAttempt) { session?.dispose?.(); return }
    if (session?.persistenceID && browserSessionWasCleared(session.persistenceID, session.persistenceEpoch)) { session.dispose?.(); return }
    pendingPersistenceID = undefined
    if (session) {
      activePersistenceID = session.persistenceID
      activePersistenceEpoch = session.persistenceEpoch
      persistenceNotice.value = session.notice ?? ''
      if (session.notice && workspace && session.account?.tenantID !== workspace) {
        const url = new URL(location.href)
        url.searchParams.set('workspace', session.account?.tenantID ?? '')
        url.searchParams.delete('device')
        history.replaceState(history.state, '', url)
      }
      await start(session)
    }
  } catch {
    if (attempt === restoreAttempt && !disposed) restoreError.value = t('Não foi possível restaurar sua sessão agora. Verifique sua conexão e tente novamente.')
  } finally {
    if (attempt === restoreAttempt) restoring.value = false
  }
}

function checkRememberedSession() {
  if (!activePersistenceID || !browserSessionWasCleared(activePersistenceID, activePersistenceEpoch)) return
  restoreAttempt++
  activePersistenceID = undefined
  pendingPersistenceID = undefined
  restoring.value = false
  opening.value = false
  restoreError.value = ''
  stop({ logout: false })
}

function returnedToPage(event: PageTransitionEvent) {
  checkRememberedSession()
  if (event.persisted && state.phase !== 'locked') {
    stop({ logout: false })
    void restore()
  }
}

window.addEventListener('focus', checkRememberedSession)
window.addEventListener('pageshow', returnedToPage)

function closePanel() {
  state.selectedUID = ''
  state.history = null
}

// A discreet device changes the chat palette, never the workspace console.
watchEffect(() => applyPrivacyAppearance(state))

onBeforeUnmount(() => {
  disposed = true
  restoreAttempt++
  unobserveSession()
  window.removeEventListener('focus', checkRememberedSession)
  window.removeEventListener('pageshow', returnedToPage)
  navigation.dispose()
  window.removeEventListener('resize', updateViewport)
  mobileQuery.removeEventListener('change', updateViewport)
  window.visualViewport?.removeEventListener('resize', updateViewport)
  window.visualViewport?.removeEventListener('scroll', updateViewport)
  document.documentElement.style.removeProperty('--app-height')
  document.documentElement.style.removeProperty('--app-top')
  delete document.documentElement.dataset.incognito
  delete document.documentElement.dataset.surface
  stop({ logout: false })
})
</script>

<template>
  <div v-if="opening" class="empty app-loading" role="status" aria-live="polite">
    <div><div class="loading-spinner" aria-hidden="true" /><div class="big">{{ t('Preparando sua sessão…') }}</div></div>
  </div>
  <div v-else-if="restoring || restoreError" class="empty app-loading" role="status" aria-live="polite">
    <div>
      <template v-if="restoring"><div class="loading-spinner" aria-hidden="true" /><div class="big">{{ t('Restaurando sua sessão…') }}</div></template>
      <template v-else><p class="alert">{{ restoreError }}</p><button class="primary" @click="restore">{{ t('Tentar novamente') }}</button></template>
    </div>
  </div>

  <SignInView v-else-if="state.phase === 'locked'" @opened="opened" />

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
      <button class="primary" @click="stop()">{{ t('Voltar') }}</button>
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
  <div v-if="persistenceNotice && state.phase !== 'locked'" class="alert session-notice" role="status">
    {{ persistenceNotice }}
    <button class="ghost small" type="button" @click="persistenceNotice = ''">{{ t('Fechar') }}</button>
  </div>
</template>

<style scoped>
.session-notice { position: fixed; z-index: 100; top: 12px; left: 50%; transform: translateX(-50%); max-width: min(600px, calc(100vw - 32px)); }
</style>

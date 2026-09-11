<script setup lang="ts">
import { t } from '../ui/i18n'
import { computed, nextTick, onMounted, ref, watch } from 'vue'

import {
  admin,
  canAdminister,
  load,
  openDetail,
  stopDevice,
  startDevice,
  preparePairing,
} from '../state/admin'
import { archiveOpener, credential, preferredReadableDevice, readableDevices, selectDevice, state, stop } from '../state/archive'
import type { DeviceInfo } from '../api/protocol'
import { bytes, count, since, stamp } from '../ui/format'
import { showWorkspaceView } from '../ui/workspaceNavigation'
import DeviceSheet from './DeviceSheet.vue'
import DeviceAvatar from './DeviceAvatar.vue'
import { formatPhone, parseJID } from '../state/jid'
import Reproject from './Reproject.vue'
import PairDialog from './PairDialog.vue'
import AccountPanel from './AccountPanel.vue'
import TokenPanel from './TokenPanel.vue'
import WorkspacePanel from './WorkspacePanel.vue'
import WorkspaceSwitcher from './WorkspaceSwitcher.vue'
import ConsoleDialog from './ConsoleDialog.vue'
import { currentWorkspace, loadWorkspaceContext, workspaceState } from '../state/workspaces'
import { initials } from '../state/jid'
import SubscriptionPanel from '@subscription'
import TrialStatus from '@trial-status'
import AppearanceMenu from './AppearanceMenu.vue'
import AppIcon, { type IconName } from './AppIcon.vue'

const readable = computed(() => readableDevices())
const workspaceName = computed(() => currentWorkspace.value?.name ?? '')
const mobileNav = ref(false)
const profileName = computed(() => workspaceState.profile?.name || state.account || state.label)
const profileAvatar = computed(() => workspaceState.profile?.avatar || '')
const section = ref('devices')
const visited = ref(new Set(['devices']))
const content = ref<HTMLElement>()
const appError = ref('')
const openingApp = ref(false)
const roleLabels = computed<Record<string, string>>(() => ({ owner: t('Proprietário'), admin: t('Administrador'), member: t('Membro'), service: t('Integração') }))
interface Section { id: string; label: string; description: string; icon: IconName; visible: boolean }
const sections = computed<Section[]>(() => [
  { id: 'devices', label: t('Números'), description: t('Conecte e acompanhe os números do WhatsApp do seu espaço de trabalho.'), icon: 'devices', visible: true },
  { id: 'members', label: t('Membros'), description: t('Convide pessoas e organize os papéis da sua equipe.'), icon: 'users', visible: canAdminister() && credential()?.kind === 'session' && currentWorkspace.value?.kind !== 'personal' },
  { id: 'tokens', label: t('Integrações'), description: t('Crie e acompanhe as chaves de acesso dos seus sistemas.'), icon: 'key', visible: canAdminister() },
  { id: 'billing', label: t('Assinatura'), description: t('Acompanhe a capacidade do espaço e o histórico da assinatura.'), icon: 'wallet', visible: canAdminister() },
  { id: 'account', label: t('Minha conta'), description: t('Proteja sua conta e gerencie suas formas de acesso.'), icon: 'settings', visible: Boolean(state.account) },
  { id: 'diagnostics', label: t('Diagnóstico'), description: t('Consulte o processamento e a compatibilidade do histórico de conversas.'), icon: 'clock', visible: true },
].filter((item) => item.visible) as Section[])
const current = computed(() => sections.value.find((item) => item.id === section.value) ?? sections.value[0]!)
const navigationSections = computed(() => sections.value.filter(item => item.id !== 'account'))
const online = computed(() => state.devices.filter((device) => device.running).length)
const totalMessages = computed(() => Object.values(admin.stats).reduce((total, stat) => total + (stat.messages ?? 0), 0))
const appDevice = computed(() => preferredReadableDevice(true))

function canRead(device: DeviceInfo): boolean {
  return credential()?.kind === 'api_key' || readable.value.has(device.id)
}

function show(id: string) {
  if (!sections.value.some((item) => item.id === id)) return
  section.value = id
  mobileNav.value = false
  visited.value.add(id)
  void nextTick(() => content.value?.scrollTo({ top: 0 }))
}

watch(sections, (available) => {
  if (!available.some((item) => item.id === section.value)) show('devices')
})

async function returnToApp() {
  if (!appDevice.value || openingApp.value) return
  openingApp.value = true
  appError.value = ''
  try { await read(appDevice.value) }
  catch { appError.value = t('Não foi possível abrir as conversas. Tente novamente.') }
  finally { openingApp.value = false }
}

const emit = defineEmits<{ (e: 'read', deviceID: string): void }>()

onMounted(() => {
  void loadWorkspaceContext()
  if (state.connected) void load()
  const billingReturn = new URLSearchParams(window.location.search).get('billing')
  if (billingReturn && ['success', 'cancel', 'portal', 'change'].includes(billingReturn)) show('billing')
})

function pendingDevice(device: DeviceInfo): boolean { return !device.pn && !device.lid && !device.last_connected_at }

function deviceIdentity(device: DeviceInfo): string {
  return device.pn ? formatPhone(parseJID(device.pn).user) : device.lid || t('Número ainda não conectado')
}

function statusLabel(device: DeviceInfo): string {
  if (device.paused) return t('Sincronização pausada')
  if (pendingDevice(device)) return t('Vínculo pendente')
  switch (device.status) {
    case 'online':
      return device.running ? t('Conectado') : t('Reconectando…')
    case 'offline':
      return t('Desconectado')
    case 'pairing':
      return t('Aguardando vínculo')
    case 'new':
      return t('nunca pareado')
    case 'logged_out':
      return t('desconectado no celular')
    case 'banned':
      return t('bloqueado pelo WhatsApp')
    default:
      return device.status
  }
}

/**
 * statusTone separates "nothing is wrong" from "nothing is happening".
 *
 * The row's status is a column, written by whichever process last moved the
 * device; running is computed here and now from this process's registry. When
 * they disagree — the database says online and nobody is holding the connection
 * — that is its own state and deserves its own colour. It was borrowing the one
 * used for a device WhatsApp has thrown out, which reads as far worse than it is.
 */
function statusTone(device: DeviceInfo): string {
  if (device.paused) return 'off'
  if (pendingDevice(device)) return 'warn'
  if (device.status === 'online' && device.running) return 'live'
  if (device.status === 'online') return 'stale'
  if (device.status === 'banned' || device.status === 'logged_out') return 'bad'
  if (device.status === 'pairing') return 'warn'
  return 'off'
}

function when(iso: string | undefined): Date | undefined {
  return iso ? new Date(iso) : undefined
}

/** Read opens the archive of a device this session holds a key for. */
async function read(device: DeviceInfo) {
  if (!canRead(device)) return
  appError.value = ''
  if (location.hostname === 'console.wappie.thehappie.co') {
    showWorkspaceView('archive', state.tenantID, device.id)
    return
  }
  try {
    if (device.id !== state.deviceID || !archiveOpener() || state.actionError) await selectDevice(device.id)
    if (showWorkspaceView('archive', state.tenantID, device.id)) emit('read', device.id)
  } catch (err) {
    appError.value = err instanceof Error ? err.message : t('Não foi possível abrir as conversas. Tente novamente.')
  }
}
</script>

<template>
  <div class="console console-app">
    <aside class="console-sidebar" :aria-label="t('Navegação do console')">
      <a class="console-brand" href="https://wappie.thehappie.co/" :aria-label="t('Wappie, página do produto')">
        <span class="brand-mark"><AppIcon name="message" :size="25" /></span>
        <span><strong>{{ t('Wappie') }}</strong><small>{{ t('Console') }}</small></span>
      </a>
      <WorkspaceSwitcher />
      <nav class="console-nav" :aria-label="t('Seções')">
        <button v-for="item in navigationSections" :key="item.id" type="button" class="console-nav-item"
          :class="{ active: section === item.id }" :aria-current="section === item.id ? 'page' : undefined"
          @click="show(item.id)">
          <AppIcon :name="item.icon" :size="20" /><span>{{ item.label }}</span>
          <span v-if="item.id === 'devices'" class="nav-count">{{ state.devices.length }}</span>
        </button>
      </nav>
      <div class="console-profile">
        <button type="button" class="profile-trigger" :aria-label="t('Minha conta')" @click="show('account')"><img v-if="profileAvatar" :src="profileAvatar" alt="" /><span v-else class="profile-initials">{{ initials(profileName) }}</span><span class="profile-text"><strong>{{ profileName }}</strong><small>{{ state.account || roleLabels[state.role] }}</small></span><AppIcon name="chevron-down" :size="15" /></button>
        <button class="profile-signout" type="button" @click="stop()"><AppIcon name="logout" :size="17" /><span>{{ t('Sair da conta') }}</span></button>
      </div>
    </aside>

    <div class="console-main">
      <header class="console-header">
        <button class="icon-btn mobile-menu" type="button" :aria-label="t('Abrir menu')" aria-haspopup="dialog" :aria-expanded="mobileNav" @click="mobileNav = true"><svg width="23" height="23" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16" /></svg></button>
        <div class="grow"><div class="console-breadcrumb">{{ t('Console') }} <span>/</span> {{ workspaceName || t('Seu espaço de trabalho') }}</div><h1>{{ current.label }}</h1></div>
        <AppearanceMenu />
        <button class="ghost console-app-link" type="button" :disabled="!appDevice || openingApp"
          :title="appDevice ? t('Abrir o aplicativo de mensagens') : t('A leitura de um número precisa estar liberada para sua conta')" @click="returnToApp">
          <AppIcon name="message" :size="19" /><span>{{ t('Mensagens') }}</span>
        </button>
        <button class="mobile-profile" type="button" :aria-label="t('Minha conta')" @click="show('account')"><img v-if="profileAvatar" :src="profileAvatar" alt="" /><span v-else>{{ initials(profileName) }}</span></button>
      </header>

      <main ref="content" class="console-content" :aria-label="current.label">
        <div class="console-section-intro"><p>{{ current.description }}</p><span class="connection-label" :class="{ connected: state.connected }"><i />{{ state.connected ? t('Servidor conectado') : t('Sem conexão ao servidor') }}</span></div>
        <TrialStatus v-if="canAdminister() && section !== 'billing'" @open="show('billing')" />
        <div v-if="admin.error || appError" class="alert" role="alert">{{ appError || admin.error }}</div>
        <div v-if="admin.removed" class="removed" role="status"> {{ t('Número removido: {v0} mensagens, {v1} conversas e {v2} anexos apagados.', { v0: count(admin.removed.messages), v1: count(admin.removed.chats), v2: count(admin.removed.media) }) }} <template v-if="admin.removed.note"> {{ admin.removed.note }}.</template>
        </div>

        <div v-show="section === 'devices'" class="console-section">
          <div class="console-overview">
            <article><span>{{ t('Números cadastrados') }}</span><strong>{{ state.devices.length }}</strong><small>{{ t('no espaço de trabalho') }}</small></article>
            <article><span>{{ t('Conectados agora') }}</span><strong>{{ online }}<i class="summary-status" :class="{ live: online > 0 }" /></strong><small>{{ t('sincronizando com o WhatsApp') }}</small></article>
            <article><span>{{ t('Mensagens no histórico') }}</span><strong>{{ admin.statsLoaded ? count(totalMessages) : '—' }}</strong><small>{{ t('nos números disponíveis') }}</small></article>
          </div>
          <div class="device-section-title"><h2>{{ t('Seus números') }}</h2><button class="ghost small" type="button" :disabled="admin.loading || !state.connected" @click="load"><AppIcon name="refresh" :size="16" /> {{ t('Atualizar') }}</button></div>
          <p v-if="admin.loading && !state.devices.length" class="dim" role="status">{{ t('Carregando números…') }}</p>
          <section class="cards" :aria-label="t('Números do WhatsApp')">
            <article v-for="device in state.devices" :key="device.id" class="device">
              <div class="head"><DeviceAvatar :device="device" /><div class="grow"><div class="name">{{ device.label || device.push_name || t('Número sem nome') }}</div><div class="sub">{{ deviceIdentity(device) }}</div></div><span class="device-status" :class="statusTone(device)"><i />{{ device.running ? t('Online') : statusLabel(device) }}</span></div>
              <div v-if="device.push_name" class="who">{{ device.push_name }}</div>
              <dl class="counts">
                <div><dt>{{ t('Conversas') }}</dt><dd>{{ admin.statsLoaded ? count(admin.stats[device.id]?.chats) : '…' }}</dd></div>
                <div><dt>{{ t('Mensagens') }}</dt><dd>{{ admin.statsLoaded ? count(admin.stats[device.id]?.messages) : '…' }}</dd></div>
                <div><dt>{{ t('Anexos') }}</dt><dd>{{ admin.statsLoaded ? count(admin.stats[device.id]?.media) : '…' }}<span v-if="admin.stats[device.id]?.media_bytes" class="dim"> · {{ bytes(admin.stats[device.id].media_bytes) }}</span></dd></div>
                <div><dt>{{ t('Última mensagem') }}</dt><dd>{{ stamp(when(admin.stats[device.id]?.last_at)) }}</dd></div>
              </dl>
              <p v-if="!canRead(device)" class="device-access-note"><AppIcon name="shield" :size="15" />{{ t('Sua conta ainda não tem acesso à leitura.') }}</p>
              <p v-else-if="device.last_connected_at" class="device-access-note">{{ t('Conectou {v0}', { v0: since(when(device.last_connected_at)) }) }}</p>
              <p v-if="pendingDevice(device)" class="device-access-note">{{ t('O vínculo não foi concluído. Gere outro QR code ou exclua este número em Detalhes.') }}</p>
              <div class="row-actions">
                <button v-if="!pendingDevice(device)" class="ghost device-read" :disabled="!canRead(device)" @click="read(device)"><AppIcon name="message" :size="16" /> {{ t('Conversas') }}</button>
                <button class="ghost" :disabled="admin.deviceBusy" @click="openDetail(device.id)">{{ t('Detalhes') }}</button>
                <button v-if="device.can_manage && pendingDevice(device)" class="ghost" :disabled="admin.deviceBusy || !state.connected" @click="preparePairing(device)">{{ t('Vincular número') }}</button>
                <button v-else-if="device.can_manage && device.running" class="ghost device-stop" :disabled="admin.deviceBusy || !state.connected" @click="stopDevice(device.id)">{{ t('Pausar sincronização') }}</button>
                <button v-else-if="device.can_manage" class="ghost" :disabled="admin.deviceBusy || !state.connected" @click="startDevice(device.id)">{{ t('Retomar sincronização') }}</button>
              </div>
            </article>
            <div v-if="!state.devices.length && !admin.loading" class="empty-card"><AppIcon name="devices" :size="32" /><h3>{{ t('Conecte seu primeiro número') }}</h3><p class="dim">{{ t('Os números do WhatsApp do seu espaço de trabalho aparecerão aqui.') }}</p></div>
          </section>
          <PairDialog />
        </div>

        <WorkspacePanel v-if="visited.has('members')" v-show="section === 'members'" />
        <TokenPanel v-if="canAdminister() && visited.has('tokens')" v-show="section === 'tokens'" />
        <SubscriptionPanel v-if="canAdminister() && visited.has('billing')" v-show="section === 'billing'" />
        <AccountPanel v-if="state.account && visited.has('account')" v-show="section === 'account'" />
        <Reproject v-if="visited.has('diagnostics')" v-show="section === 'diagnostics'" />
      </main>
    </div>
    <ConsoleDialog v-if="mobileNav" :title="t('Wappie')" drawer @close="mobileNav = false">
      <div class="mobile-navigation"><WorkspaceSwitcher /><nav class="console-nav" :aria-label="t('Seções')"><button v-for="item in navigationSections" :key="item.id" type="button" class="console-nav-item" :class="{active:section === item.id}" :aria-current="section === item.id ? 'page' : undefined" @click="show(item.id)"><AppIcon :name="item.icon" :size="21" /><span>{{ item.label }}</span><span v-if="item.id === 'devices'" class="nav-count">{{ state.devices.length }}</span></button></nav><div class="mobile-account-area"><button type="button" class="profile-trigger" @click="show('account')"><img v-if="profileAvatar" :src="profileAvatar" alt="" /><span v-else class="profile-initials">{{ initials(profileName) }}</span><span class="profile-text"><strong>{{ profileName }}</strong><small>{{ state.account }}</small></span></button><button class="console-nav-item" type="button" @click="stop()"><AppIcon name="logout" :size="20" />{{ t('Sair da conta') }}</button></div></div>
    </ConsoleDialog>
    <DeviceSheet v-if="admin.detail || admin.detailError || admin.detailLoading" />
  </div>
</template>

<style scoped>
.console-app {
  --console-accent: #087f67;
  --console-tint: #e7f4ef;
  --console-border: color-mix(in srgb, var(--text) 15%, var(--bg-panel));
  height: 100%; max-width: none; margin: 0; padding: 0; gap: 0; overflow: hidden;
  display: grid; grid-template-columns: 236px minmax(0, 1fr); color: var(--text); background: var(--bg);
}
.console-sidebar { min-width: 0; display: flex; flex-direction: column; gap: 26px; padding: 28px 16px 18px; background: var(--bg-panel); border-right: 1px solid var(--console-border); overflow: auto; }
.console-brand { display: flex; align-items: center; gap: 10px; padding: 0 12px; color: var(--text); text-decoration: none; }
.brand-mark { width: 40px; height: 40px; display: grid; place-items: center; background: #087f67; border-radius: 12px; color: #fff; }
.console-brand strong { display: block; font-size: 22px; letter-spacing: -.7px; line-height: 1.15; }
.console-brand small { font-size: 11px; letter-spacing: 1.2px; text-transform: uppercase; color: var(--text-dim); }
.workspace-context { display: flex; align-items: center; gap: 10px; padding: 12px; border: 1px solid var(--console-border); border-radius: 10px; }
.workspace-context > div, .console-profile > div { min-width: 0; }
.workspace-context strong, .workspace-context span { display: block; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
.workspace-context strong { font-size: 13px; font-weight: 600; }
.workspace-context span { font-size: 11px; color: var(--text-dim); margin-top: 4px; }
.console-nav { display: flex; flex-direction: column; gap: 5px; }
.console-nav-item { display: flex; gap: 12px; align-items: center; width: 100%; min-height: 44px; padding: 10px 12px; border-radius: 9px; color: var(--text-dim); font-size: 13px; font-weight: 550; text-align: left; white-space: nowrap; }
.console-nav-item:hover { background: var(--bg-hover); color: var(--text); }
.console-nav-item.active { background: var(--console-tint); color: var(--console-accent); font-weight: 650; }
.nav-count { margin-left: auto; padding: 1px 6px; font-size: 11px; border-radius: 5px; background: var(--bg-panel); }
.console-profile { margin-top:auto;padding:14px 0 0;border-top:1px solid var(--console-border);display:grid;gap:8px; }.profile-signout { display:flex;align-items:center;gap:10px;min-height:36px;padding:8px 4px;color:var(--text-dim);font-size:11px;text-align:left; }

.console-profile strong { font-size: 12px; font-weight: 500; }
.console-main { display: flex; flex-direction: column; min-height: 0; min-width: 0; }
.console-header { display: flex; align-items: center; gap: 12px; min-height: 96px; padding: 20px 36px; border-bottom: 1px solid var(--console-border); background: var(--bg-panel); flex-shrink: 0; }
.console-breadcrumb { font-size: 11px; color: var(--text-dim); overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
.console-breadcrumb span { margin: 0 7px; color: var(--text-faint); }
.console-header h1 { margin: 7px 0 0; font-size: 25px; font-weight: 650; letter-spacing: -.7px; line-height: 1.15; }
.console-app-link { display: inline-flex; align-items: center; gap: 8px; min-height: 40px; font-size: 12px; white-space: nowrap; }
.mobile-menu,.mobile-profile { display:none; }.mobile-profile { width:36px;height:36px;border-radius:50%;background:var(--accent-dim);color:var(--accent);font-weight:600; }.mobile-profile img { width:100%;height:100%;border-radius:inherit;object-fit:cover; }
.profile-trigger { display:flex;gap:10px;align-items:center;min-width:0;flex:1;text-align:left;padding:7px 0; }.profile-trigger img,.profile-initials { width:35px;height:35px;border-radius:50%;flex:none;object-fit:cover; }.profile-initials { display:grid;place-items:center;background:var(--accent-dim);color:var(--accent);font-size:13px;font-weight:600; }.profile-text { min-width:0;flex:1; }.profile-text strong,.profile-text small { display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis; }.profile-text strong { font-size:12px;font-weight:600; }.profile-text small { font-size:10px;color:var(--text-dim);margin-top:4px; }.mobile-navigation { display:flex;flex-direction:column;gap:22px;min-height:70dvh; }.mobile-navigation .console-nav-item { min-height:48px; }.mobile-account-area { margin-top:auto;border-top:1px solid var(--line);padding-top:14px;display:grid;gap:12px; }.mobile-account-area .profile-trigger { padding:10px; }
.console-content { padding: 28px 36px 48px; min-height: 0; overflow-y: auto; overscroll-behavior: contain; scrollbar-gutter: stable; }
.console-content > :not(:first-child) { margin-top: 20px; }
.console-section-intro { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }
.console-section-intro p { color: var(--text-dim); font-size: 13px; margin: 0; line-height: 1.6; }
.connection-label { display: flex; align-items: center; gap: 6px; color: var(--text-dim); font-size: 10px; flex-shrink: 0; margin-top: 4px; }
.connection-label i, .summary-status, .device-status i { width: 6px; height: 6px; border-radius: 50%; background: var(--text-faint); flex-shrink: 0; }
.connection-label.connected i, .summary-status.live, .device-status.live i { background: #16a879; }
.console-section { display: grid; gap: 18px; }
.console-overview { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; }
.console-overview article { padding: 20px; background: var(--bg-raised); border: 1px solid var(--console-border); border-radius: 12px; }
.console-overview span { color: var(--text-dim); font-size: 11px; }
.console-overview strong { display: flex; align-items: center; gap: 10px; font-size: 30px; font-weight: 600; letter-spacing: -1px; margin-top: 10px; line-height: 1.2; }
.console-overview small { display: block; color: var(--text-dim); font-size: 10px; margin-top: 6px; }
.summary-status { width: 8px; height: 8px; }
.device-section-title { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 6px; }
.device-section-title h2 { font-size: 15px; margin: 0; font-weight: 600; }
.device-section-title button { display: flex; align-items: center; gap: 6px; }
.cards { grid-template-columns: repeat(auto-fit, minmax(min(100%, 320px), 1fr)); gap: 16px; }
.device { padding: 20px; gap: 16px; border-color: var(--console-border); }
.device .head { align-items: flex-start; gap: 10px; }
.device-card-icon { width: 40px; height: 40px; border-radius: 10px; display: grid; place-items: center; background: var(--bg-active); color: var(--text-dim); flex-shrink: 0; }
.device .name { font-size: 14px; }
.device .sub { font-size: 11px; margin-top: 5px; }
.device-status { display: inline-flex; align-items: center; gap: 5px; max-width: 150px; padding: 4px 7px; background: var(--bg-hover); border-radius: 6px; color: var(--text-dim); font-size: 10px; line-height: 1.3; }
.device-status.bad { color: var(--danger); }
.device-status.bad i { background: var(--danger); }
.device-status.warn i, .device-status.stale i { background: var(--warn); }
.counts { padding-top: 16px; border-top: 1px solid var(--console-border); gap: 14px; }
.counts dt { font-size: 10px; color: var(--text-dim); text-transform: none; letter-spacing: 0; }
.counts dd { font-size: 14px; margin-top: 5px; }
.device-access-note { display: flex; align-items: center; gap: 6px; color: var(--text-dim); font-size: 11px; line-height: 1.5; margin: 0; }
.row-actions { margin-top: auto; }
.row-actions button { font-size: 11px; padding: 8px 10px; }
.device-read { display: inline-flex; align-items: center; gap: 6px; color: var(--console-accent); }
.device-stop { margin-left: auto; }
.empty-card { background: var(--bg-panel); color: var(--text-dim); padding: 36px; }
.empty-card h3 { color: var(--text); font-size: 17px; margin-bottom: 6px; }
.console-app :deep(.console-panel) { border-color: var(--console-border); padding: 24px; gap: 16px; }
.console-app :deep(.console-panel h2) { font-size: 17px; font-weight: 600; }
.console-app :deep(.console-panel p) { line-height: 1.65; margin: 0; }
.console-app :deep(.console-panel input:not([type='checkbox']):not([type='radio'])),
.console-app :deep(.console-panel textarea), .console-app :deep(.console-panel select),
.console-app :deep(.sheet input:not([type='checkbox']):not([type='radio'])), .console-app :deep(.sheet select) {
  min-height: 42px; border: 1px solid var(--console-border); border-radius: 8px; background: var(--bg-input); color: var(--text); font: inherit; font-size: 13px;
}
.console-app :deep(input::placeholder), .console-app :deep(textarea::placeholder) { color: var(--text-dim); opacity: 1; }
.console-app :deep(input:-webkit-autofill) { -webkit-text-fill-color: var(--text); -webkit-box-shadow: 0 0 0 1000px var(--bg-input) inset; caret-color: var(--text); }
.console-app :deep(select option) { background: var(--bg-input); color: var(--text); }
.console-app :deep(input:focus-visible), .console-app :deep(select:focus-visible), .console-app :deep(textarea:focus-visible) { outline: 2px solid var(--console-accent); outline-offset: 2px; }
.console-app :deep(.inline) { flex-wrap: wrap; }
.console-app :deep(.inline input) { flex: 1 1 240px; min-width: 0; }
.console-app :deep(.grid) { font-size: 12px; }
.console-app :deep(.grid th) { font-size: 10px; font-weight: 600; color: var(--text-dim); padding: 12px 10px; text-align: left; border-bottom: 1px solid var(--console-border); }
.console-app :deep(.grid td) { padding: 14px 10px; border-color: var(--console-border); }
.console-app :deep(.console-panel button) { min-height: 36px; }
:global(:root[data-theme='dark'] .console-app) { --console-accent: #52d4ae; --console-tint: #173b32; }
.workspace-avatar { width: 34px; height: 34px; border-radius: 10px; object-fit: cover; flex-shrink: 0; }
@media (max-width: 1020px) {
  .console-app { grid-template-columns: 208px minmax(0, 1fr); }
  .console-sidebar { padding: 22px 12px 16px; }
  .console-header { padding: 20px 24px; }
  .console-content { padding: 24px; }
  .console-overview article { padding: 16px; }
  .connection-label { display: none; }
}
@media (max-width: 760px) {
  .console-app { display:flex; }
  .console-sidebar { display:none; }
  .console-main { flex:1; }
  .console-header { min-height:78px;padding:14px;gap:10px; }
  .console-header h1 { font-size:20px;margin-top:5px; }
  .console-breadcrumb { font-size:10px;max-width:200px; }
  .console-breadcrumb > span { margin:0 4px; }
  .console-app-link { min-height:40px;width:40px;padding:8px;justify-content:center; }
  .console-app-link span { display:none; }
  .mobile-menu { display:grid;place-items:center;flex:none; }
  .mobile-profile { display:grid;place-items:center;flex:none; }
  .console-header :deep(.appearance-trigger) { padding:8px; }
  .console-content { padding:18px 14px calc(28px + env(safe-area-inset-bottom));scrollbar-gutter:auto; }
  .console-section-intro p { font-size:12px; }
  .console-overview { gap:8px; }
  .console-overview article { padding:13px 10px; }
  .console-overview span { font-size:10px;display:block;line-height:1.4;min-height:28px; }
  .console-overview strong { font-size:23px;gap:6px; }
  .console-overview small { display:none; }
  .device { padding:17px; }
  .device-status { max-width:96px; }
  .console-app :deep(.console-panel) { padding:18px 16px; }
  .console-app :deep(.console-panel input:not([type='checkbox']):not([type='radio'])),.console-app :deep(.console-panel textarea),.console-app :deep(.console-panel select) { font-size:16px; }
}
</style>

<script setup lang="ts">
import { computed, onMounted } from 'vue'

import {
  admin,
  canAdminister,
  load,
  openDetail,
  stopDevice,
} from '../state/admin'
import { readableDevices, selectDevice, state, stop } from '../state/archive'
import type { DeviceInfo } from '../api/protocol'
import { bytes, count, since, stamp } from '../ui/format'
import DeviceSheet from './DeviceSheet.vue'
import Reproject from './Reproject.vue'
import PairDialog from './PairDialog.vue'
import AccountPanel from './AccountPanel.vue'
import TokenPanel from './TokenPanel.vue'
import WorkspacePanel from './WorkspacePanel.vue'
import SubscriptionPanel from '@subscription'

const readable = computed(() => readableDevices())

const emit = defineEmits<{ (e: 'read', deviceID: string): void }>()

onMounted(() => {
  if (state.connected) void load()
})

function statusLabel(device: DeviceInfo): string {
  switch (device.status) {
    case 'online':
      return device.running ? 'conectado' : 'marcado como online, mas ninguém está conectado'
    case 'offline':
      return 'desligado'
    case 'pairing':
      return 'pareando'
    case 'new':
      return 'nunca pareado'
    case 'logged_out':
      return 'desconectado no celular'
    case 'banned':
      return 'bloqueado pelo WhatsApp'
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
  if (location.hostname === 'console.wappie.thehappie.co') {
    const url = new URL('https://app.wappie.thehappie.co/')
    url.searchParams.set('workspace', state.tenantID)
    url.searchParams.set('device', device.id)
    location.assign(url.toString())
    return
  }
  await selectDevice(device.id)
  emit('read', device.id)
}
</script>

<template>
  <div class="console">
    <header class="console-top">
      <div class="grow">
        <h1>Wappie · Console</h1>
        <div class="sub">
          {{ state.account || state.label }}
          <template v-if="state.role"> · {{ state.role }}</template>
          <template v-if="!state.connected"> · sem conexão</template>
        </div>
      </div>
      <button class="ghost" v-if="state.deviceID" @click="emit('read', state.deviceID)">
        Ver conversas
      </button>
      <button class="ghost" @click="stop">Sair</button>
    </header>

    <div class="alert" v-if="admin.error">{{ admin.error }}</div>

    <div class="removed" v-if="admin.removed">
      Aparelho removido: {{ count(admin.removed.messages) }} mensagens,
      {{ count(admin.removed.chats) }} conversas e {{ count(admin.removed.media) }} anexos foram
      apagados junto.
      <template v-if="admin.removed.note"> {{ admin.removed.note }}.</template>
    </div>

    <WorkspacePanel />

    <section class="cards">
      <article v-for="device in state.devices" :key="device.id" class="device">
        <div class="head">
          <span class="dot" :class="statusTone(device)" />
          <div class="grow">
            <div class="name">{{ device.label || 'sem nome' }}</div>
            <div class="sub">
              {{ statusLabel(device) }}
              <template v-if="device.last_connected_at">
                · conectou {{ since(when(device.last_connected_at)) }}
              </template>
            </div>
          </div>
          <span v-if="!readable.has(device.id)" class="pill locked" title="Sua conta não tem a chave deste aparelho">
            selado
          </span>
        </div>

        <div class="who">
          {{ device.pn || device.lid || 'sem identidade ainda' }}
          <template v-if="device.push_name"> · {{ device.push_name }}</template>
        </div>

        <dl class="counts">
          <div>
            <dt>conversas</dt>
            <dd>{{ admin.statsLoaded ? count(admin.stats[device.id]?.chats) : '…' }}</dd>
          </div>
          <div>
            <dt>mensagens</dt>
            <dd>{{ admin.statsLoaded ? count(admin.stats[device.id]?.messages) : '…' }}</dd>
          </div>
          <div>
            <dt>anexos</dt>
            <dd>
              {{ admin.statsLoaded ? count(admin.stats[device.id]?.media) : '…' }}
              <span class="dim" v-if="admin.stats[device.id]?.media_bytes">
                {{ bytes(admin.stats[device.id].media_bytes) }}
              </span>
            </dd>
          </div>
          <div>
            <dt>última</dt>
            <dd>{{ stamp(when(admin.stats[device.id]?.last_at)) }}</dd>
          </div>
        </dl>

        <div class="row-actions">
          <button class="ghost" :disabled="!readable.has(device.id)" @click="read(device)">
            Abrir arquivo
          </button>
          <button class="ghost" @click="openDetail(device.id)">Detalhes</button>
          <button class="ghost" v-if="device.running" @click="stopDevice(device.id)">
            Desligar
          </button>
        </div>
      </article>

      <div class="empty-card" v-if="!state.devices.length && !admin.loading">
        <p>Nenhum número do WhatsApp ligado a este espaço ainda.</p>
        <p class="dim">
          Ao parear, a chave que abre o arquivo é criada neste navegador e selada para as contas
          escolhidas. O servidor recebe só a metade pública.
        </p>
      </div>
    </section>

    <PairDialog />

    <Reproject />

    <TokenPanel v-if="canAdminister()" />
    <SubscriptionPanel v-if="canAdminister()" />
    <AccountPanel />

    <DeviceSheet v-if="admin.detail || admin.detailError || admin.detailLoading" />
  </div>
</template>

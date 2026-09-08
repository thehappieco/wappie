<script setup lang="ts">
import { computed } from 'vue'

import type { DeviceInfo } from '../api/protocol'
import { nowTick } from '../state/actions'
import { openChat, people, selectDevice, state, stop, type ChatView } from '../state/archive'
import { typingIn } from '../state/presence'
import { formatPhone, parseJID } from '../state/jid'
import { kindLabel, listStamp, typeLabel } from '../ui/format'
import AvatarBadge from './AvatarBadge.vue'
import QuietSwitch from './QuietSwitch.vue'

/**
 * What to call one device.
 *
 * The label is what a person typed, so it wins; then the name WhatsApp reports;
 * then the number. All three can be empty — a device paired a minute ago has
 * connected to nothing and knows nothing about itself yet — and saying that is
 * better than an empty header.
 */
function deviceName(device: DeviceInfo): string {
  if (device.label) return device.label
  if (device.push_name) return device.push_name
  if (device.pn) return formatPhone(parseJID(device.pn).user)
  if (device.lid) return 'aparelho sem número'
  return 'aparelho sem nome'
}

/**
 * The WhatsApp account on screen.
 *
 * This is the headline rather than the account, because it is the answer to
 * "whose messages am I reading". The account is who you are, which changes far
 * less often and is one click away in the console.
 */
const openDevice = computed(() => state.devices.find((d) => d.id === state.deviceID))

/**
 * Which WhatsApp account this is, as an identifier rather than a nickname.
 *
 * The number when there is one. A LID is shown as a LID and not formatted as a
 * phone number, because it is not one — withholding the number is the entire
 * reason LID exists, and printing it like a number would be a lie in the shape
 * of a fact.
 */
function deviceIdentity(device: DeviceInfo): string {
  if (device.pn) return formatPhone(parseJID(device.pn).user)
  if (device.lid) return `LID ${parseJID(device.lid).user}`
  return 'sem identidade ainda'
}

/**
 * The status feed is listed apart from the conversations.
 *
 * It is not one: it is dozens of unrelated people posting to the same address,
 * and left in the list it sits permanently at the top — status arrives all day
 * — pushing real conversations down.
 */
const statusFeed = computed(() => state.chats.find((c) => c.isStatus))

const visible = computed(() => {
  const conversations = state.chats.filter((c) => !c.isStatus)
  const needle = state.chatFilter.trim().toLocaleLowerCase('pt-BR')
  if (!needle) return conversations
  return conversations.filter(
    (c) => c.name.toLocaleLowerCase('pt-BR').includes(needle) || c.key.includes(needle),
  )
})

/**
 * What one row says under the name.
 *
 * A control row is described rather than quoted — "editou" is the useful thing
 * to know, and quoting the new text would show an edit as if it were a new
 * message. Otherwise the opened body, and failing that the type.
 */
/**
 * Somebody typing displaces the last message, which is what WhatsApp does and
 * what a person scanning the sidebar is actually looking for. It is the only
 * thing in this list that is true for a few seconds rather than until something
 * changes it, so it expires on read.
 */
function typingLine(chat: ChatView): string {
  const who = typingIn(chat.key, nowTick.value)
  if (who.length === 0) return ''
  const recording = who.some((t) => t.media === 'audio')
  if (!chat.isGroup) return recording ? 'gravando áudio…' : 'digitando…'
  if (who.length > 1) return `${who.length} pessoas digitando…`
  const name = people().nameFor(who[0].senderLID || who[0].senderPN || who[0].senderKey)
  return recording ? `${name} gravando áudio…` : `${name} digitando…`
}

function preview(chat: ChatView): string {
  const acted = kindLabel(chat.lastKind)
  if (acted) return acted
  if (chat.previewState === 'tampered') return '⚠ adulterado'
  if (chat.preview) return chat.preview
  return typeLabel(chat.lastType)
}
function openConsole() {
  if (location.hostname === 'app.wappie.thehappie.co') {
    const url = new URL('https://console.wappie.thehappie.co/')
    url.searchParams.set('workspace', state.tenantID)
    location.assign(url.toString())
    return
  }
  state.view = 'admin'
}
</script>

<template>
  <aside class="sidebar">
    <div class="topbar">
      <div class="grow">
        <h2>{{ openDevice ? deviceName(openDevice) : 'nenhum aparelho' }}</h2>
        <div class="sub">
          <span class="dot" :class="state.connected ? 'live' : 'off'" />
          <template v-if="state.connected">ao vivo</template>
          <template v-else-if="state.reconnectIn > 0">
            reconectando em {{ state.reconnectIn }}s
          </template>
          <template v-else-if="state.closedReason">reconectando…</template>
          <template v-else>desconectado</template>
          · {{ state.contactsLoaded }} contatos
        </div>
        <!-- The number, in the same line style as the contact count. It takes
             the slot the account was using: the account is who you are, it
             changes far less often, and the console one button away already
             shows it. This line answers whose WhatsApp is on screen. -->
        <div class="sub">{{ openDevice ? deviceIdentity(openDevice) : '' }}</div>
      </div>
        <QuietSwitch />
      <button class="icon-btn" title="Aparelhos e chaves" @click="openConsole">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="5" y="2" width="14" height="20" rx="2" />
          <path d="M12 18h.01" />
        </svg>
      </button>
      <button class="icon-btn" title="Fechar o arquivo" @click="stop">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" />
        </svg>
      </button>
    </div>

    <div class="search" v-if="state.devices.length > 1">
      <select
        :value="state.deviceID"
        @change="selectDevice(($event.target as HTMLSelectElement).value)"
      >
        <option v-for="device in state.devices" :key="device.id" :value="device.id">
          {{ deviceName(device) }} — {{ device.status }}{{ device.running ? ' (ligado)' : '' }}
        </option>
      </select>
    </div>

    <div class="banner" v-if="state.unreadable">
      Sua conta não tem a chave deste aparelho, então o conteúdo continua selado. Quem tem acesso a
      ele precisa conceder o seu.
    </div>

    <div class="search">
      <input v-model="state.chatFilter" placeholder="Buscar conversa" aria-label="Buscar conversa" />
    </div>

    <button
      v-if="statusFeed"
      class="chat-row status-row"
      :class="{ on: statusFeed.key === state.openChatKey }"
      @click="openChat(statusFeed.key)"
    >
      <div class="status-ring">◔</div>
      <div class="body">
        <div class="line">
          <span class="name">Status</span>
          <span class="when">{{ listStamp(statusFeed.lastTS) }}</span>
        </div>
        <div class="line">
          <span class="preview">publicações de contatos, que somem em 24h no WhatsApp</span>
        </div>
      </div>
    </button>

    <div class="chat-list">
      <button
        v-for="chat in visible"
        :key="chat.key"
        class="chat-row"
        :class="{ on: chat.key === state.openChatKey }"
        @click="openChat(chat.key)"
      >
        <AvatarBadge :contact-key="chat.avatarKey" :name="chat.name" :is-group="chat.isGroup" />
        <div class="body">
          <div class="line">
            <span class="name">
              {{ chat.name }}
              <span v-if="chat.nameState === 'tampered'" class="tampered">⚠ ADULTERADO</span>
            </span>
            <span class="when">{{ listStamp(chat.lastTS) }}</span>
          </div>
          <div class="line">
            <span v-if="typingLine(chat)" class="preview typing">{{ typingLine(chat) }}</span>
            <span v-else class="preview">{{ preview(chat) }}</span>
            <span v-if="chat.unread" class="badge">{{ chat.unread }}</span>
          </div>
        </div>
      </button>

      <div v-if="!visible.length" class="empty" style="height: auto; padding: 30px">
        {{ state.chats.length ? 'Nada com esse nome.' : 'Nenhuma conversa neste aparelho.' }}
      </div>
    </div>
  </aside>
</template>

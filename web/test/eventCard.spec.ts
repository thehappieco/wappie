import { createRenderer, createSSRApp, nextTick, reactive, ssrContextKey } from 'vue'
import { renderToString } from 'vue/server-renderer'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { CalendarEvent } from '../src/api/protocol'
import EventCard from '../src/components/EventCard.vue'
import { locale } from '../src/ui/i18n'

afterEach(() => { vi.restoreAllMocks(); locale.value = 'pt' })

describe('calendar event card', () => {
  it.each(['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>', 'https://trusted.example@other.example/call', '//example.test/call'])('never turns an unsafe received link into a navigation: %s', async join_link => {
    const html = await renderToString(createSSRApp(EventCard, { event: { name: 'Reunião', join_link } }))
    expect(html).not.toContain('<a ')
  })

  it('keeps external navigation explicit and suppresses joining canceled events', async () => {
    const event = { name: 'Reunião', join_link: 'https://call.whatsapp.com/video/abc?x=1' }
    const html = await renderToString(createSSRApp(EventCard, { event }))
    expect(html).toContain('href="https://call.whatsapp.com/video/abc?x=1"')
    expect(html).toContain('rel="noopener noreferrer"')
    expect(html).toContain('referrerpolicy="no-referrer"')
    expect(await renderToString(createSSRApp(EventCard, { event: { ...event, is_canceled: true } }))).not.toContain('<a ')
  })

  it('tolerates malformed received timestamps and escapes event text', async () => {
    const html = await renderToString(createSSRApp(EventCard, { event: {
      name: '<img src=x onerror=alert(1)>', start_time: 'invalid', end_time: '2026-10-10T15:30:00Z',
      location: { lat: 0, lon: 0, name: 'Sala 1', address: 'Rua das Flores, 12' },
    } }))
    expect(html).not.toContain('<img')
    expect(html).not.toContain('Invalid Date')
    expect(html).not.toContain('Início do evento')
    expect(html).toContain('datetime="2026-10-10T15:30:00.000Z"')
    expect(html).toContain('Rua das Flores, 12')
    expect(html).not.toContain('Conferir no mapa')
  })

  it('keeps UTC identity in a local calendar file and releases URLs after edits and unmount', async () => {
    const blobs: Blob[] = []
    vi.spyOn(URL, 'createObjectURL').mockImplementation(blob => { blobs.push(blob as Blob); return `blob:test-${blobs.length}` })
    const revoke = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {})
    interface Node { parent: Node | null; children: Node[] }
    const node = (): Node => ({ parent: null, children: [] })
    const renderer = createRenderer<Node, Node>({
      createElement: node, createText: node, createComment: node, patchProp() {}, setText() {}, setElementText() {}, parentNode: n => n.parent, nextSibling: () => null,
      insert(n, parent) { n.parent = parent; parent.children.push(n) }, remove(n) { if (n.parent) n.parent.children = n.parent.children.filter(child => child !== n) },
    })
    const event = reactive<CalendarEvent>({ name: 'Reunião', start_time: '2026-10-10T12:30:00-03:00', join_link: 'javascript:alert(1)' })
    const app = renderer.createApp({ ...EventCard, render: () => null }, { event, uid: 'stable-message' })
    app.provide(ssrContextKey, {})
    app.mount(node())
    try {
      expect(blobs).toHaveLength(1)
      const original = await blobs[0]!.text()
      expect(original).toContain('UID:stable-message@whatserver2\r\n')
      expect(original).toContain('DTSTART:20261010T153000Z\r\n')
      expect(original).not.toContain('javascript:')
      expect(revoke).not.toHaveBeenCalled()
      event.name = 'Reunião alterada'
      await nextTick()
      expect(revoke).toHaveBeenCalledExactlyOnceWith('blob:test-1')
      expect(await blobs[1]!.text()).toContain('SUMMARY:Reunião alterada')
      locale.value = 'en'
      await nextTick()
      expect(blobs).toHaveLength(2)
    } finally { app.unmount() }
    expect(revoke).toHaveBeenLastCalledWith('blob:test-2')
  })
})

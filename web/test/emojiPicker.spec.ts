import { readFileSync } from 'node:fs'
import { compileScript, parse } from '@vue/compiler-sfc'
import { compile, createRenderer, nextTick, ssrContextKey } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'
import EmojiPicker from '../src/components/EmojiPicker.vue'

vi.mock('../src/ui/i18n', () => ({ t: (value: string) => value }))
vi.mock('../src/components/AppIcon.vue', () => ({ default: { render: () => null } }))

// Compile the actual input and its apply/remove buttons, including Vue's event
// modifiers. Calling enter() directly would miss a template-level .prevent
// that consumes the IME's confirmation before the handler can inspect it.
const { descriptor } = parse(readFileSync(new URL('../src/components/EmojiPicker.vue', import.meta.url), 'utf8'))
const template = descriptor.template!.content
const inputMarkup = template.match(/<input v-model="input"[\s\S]*?\/>/)![0]
const applyMarkup = template.match(/<button[^>]*class="emoji-apply"[\s\S]*?<\/button>/)![0]
const removeMarkup = template.match(/<button[^>]*class="emoji-remove"[\s\S]*?<\/button>/)![0]
const render = compile(`<div>${inputMarkup}${applyMarkup}${removeMarkup}</div>`, {
  prefixIdentifiers: true,
  bindingMetadata: compileScript(descriptor, { id: 'emoji-picker-test' }).bindings,
})

class Element extends EventTarget {
  parent: Element | null = null
  children: Element[] = []
  props: Record<string, unknown> = {}
  value = ''
  constructor(readonly tag = '') { super() }
}
const renderer = createRenderer<Element, Element>({
  createElement: tag => new Element(tag), createText: () => new Element(), createComment: () => new Element(),
  setText() {}, setElementText() {}, parentNode: node => node.parent, nextSibling: () => null,
  patchProp(node, key, previous, value) {
    node.props[key] = value
    if (/^on[A-Z]/.test(key) && !key.startsWith('onUpdate:')) {
      const type = key.slice(2).toLowerCase()
      if (previous) node.removeEventListener(type, previous)
      if (value) node.addEventListener(type, value)
    }
  },
  insert(node, parent) { node.parent = parent; parent.children.push(node) },
  remove(node) { if (node.parent) node.parent.children = node.parent.children.filter(child => child !== node) },
})
let unmount: (() => void) | undefined
afterEach(() => { unmount?.(); unmount = undefined })

async function mount(current = '👍', disabled = false) {
  const choose = vi.fn()
  const root = new Element()
  const app = renderer.createApp({ ...EmojiPicker, render }, { current, disabled, onChoose: choose })
  app.provide(ssrContextKey, {})
  app.mount(root); unmount = () => app.unmount()
  await nextTick()
  const elements = () => root.children.flatMap(node => node.children)
  const input = elements().find(node => node.tag === 'input')!
  const apply = elements().find(node => node.props.class === 'emoji-apply')!
  const remove = () => elements().find(node => node.props.class === 'emoji-remove')
  async function type(value: string) { input.value = value; input.dispatchEvent(new Event('input')); await nextTick() }
  function enter(isComposing = false) {
    const event = new Event('keydown', { cancelable: true })
    Object.defineProperties(event, { key: { value: 'Enter' }, isComposing: { value: isComposing } })
    input.dispatchEvent(event)
    return event
  }
  return { input, apply, remove, type, enter, choose }
}

describe('emoji picker native input bindings', () => {
  it('preserves IME Enter and only sends after composition has ended and Enter is pressed again', async () => {
    const ui = await mount()
    ui.input.dispatchEvent(new Event('compositionstart'))
    await ui.type('👩🏽‍💻')
    expect(ui.enter(true).defaultPrevented).toBe(false)
    // Some keyboards signal composition only through compositionstart/end.
    expect(ui.enter(false).defaultPrevented).toBe(false)
    expect(ui.choose).not.toHaveBeenCalled()
    ui.input.dispatchEvent(new Event('compositionend'))
    await nextTick()
    expect(ui.choose).not.toHaveBeenCalled()
    expect(ui.enter().defaultPrevented).toBe(true)
    expect(ui.choose).toHaveBeenCalledExactlyOnceWith('👩🏽‍💻')
  })

  it('also respects isComposing before a compositionstart event has arrived', async () => {
    const ui = await mount()
    await ui.type('❤️')
    expect(ui.enter(true).defaultPrevented).toBe(false)
    expect(ui.choose).not.toHaveBeenCalled()
  })

  it('never treats an empty or invalid input as withdrawal, including Enter', async () => {
    const ui = await mount()
    for (const value of ['', ' ', 'text', '👍👍', '🏻', '👩🏽‍']) {
      await ui.type(value)
      ui.enter()
      expect(ui.apply.props.disabled).toBe(true)
    }
    expect(ui.choose).not.toHaveBeenCalled()
    ui.remove()!.dispatchEvent(new Event('click'))
    expect(ui.choose).toHaveBeenCalledExactlyOnceWith('')
  })

  it('canonicalizes a complete presentation alias when applying and has no removal without a current reaction', async () => {
    const ui = await mount('')
    expect(ui.remove()).toBeUndefined()
    await ui.type('❤')
    expect(ui.apply.props.disabled).toBe(false)
    ui.apply.dispatchEvent(new Event('click'))
    expect(ui.choose).toHaveBeenCalledExactlyOnceWith('❤️')
  })

  it('cannot emit a reaction or removal while the device is unavailable', async () => {
    const ui = await mount('👍', true)
    await ui.type('❤️')
    ui.enter(); ui.apply.dispatchEvent(new Event('click')); ui.remove()!.dispatchEvent(new Event('click'))
    expect(ui.input.props.disabled).toBe(true)
    expect(ui.apply.props.disabled).toBe(true)
    expect(ui.remove()!.props.disabled).toBe(true)
    expect(ui.choose).not.toHaveBeenCalled()
  })
})

type Key = Pick<KeyboardEvent, 'key' | 'shiftKey' | 'isComposing' | 'keyCode'>

/** Touch keyboards keep Enter for line breaks; composing text never sends. */
export function enterSends(event: Key, touchKeyboard: boolean): boolean {
  return event.key === 'Enter' && !event.shiftKey && !event.isComposing &&
    event.keyCode !== 229 && !touchKeyboard
}

import { effectScope, nextTick, ref, type EffectScope } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Permission } from '../src/api/workspaces'
import { useWorkspacePermissions } from '../src/state/workspacePermissions'

const scopes: EffectScope[] = []
const permission = (device: string, user: string, read = true): Permission => ({
  device_id: device, user_id: user, read, send: true, manage: false, has_key: read,
})
function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}
function setup(request: (device: string) => Promise<Permission[]>) {
  const scope = effectScope()
  scopes.push(scope)
  const device = ref('')
  const access = scope.run(() => useWorkspacePermissions(device, request))!
  return { device, access, scope }
}
afterEach(() => { scopes.splice(0).forEach((scope) => scope.stop()) })

describe('the permissions shown for a selected number', () => {
  it('clears the previous number immediately and displays only the new number and its own members', async () => {
    const second = deferred<Permission[]>()
    const { device, access } = setup((id) => id === 'first'
      ? Promise.resolve([permission('first', 'ana')])
      : second.promise)
    device.value = 'first'
    await nextTick()
    expect(access.permissions.value[0]?.user_id).toBe('ana')

    device.value = 'second'
    expect(access.permissions.value).toEqual([])
    expect(access.loading.value).toBe(true)
    second.resolve([permission('first', 'ana'), permission('second', 'bruno', false)])
    await nextTick()
    expect(access.permissions.value).toEqual([permission('second', 'bruno', false)])
    expect(access.loading.value).toBe(false)
  })

  it('ignores an older reply that arrives after a different number has finished loading', async () => {
    const first = deferred<Permission[]>()
    const second = deferred<Permission[]>()
    const { device, access } = setup((id) => id === 'first' ? first.promise : second.promise)
    device.value = 'first'
    device.value = 'second'
    second.resolve([permission('second', 'bruno')])
    await nextTick()
    first.resolve([permission('first', 'ana')])
    await nextTick()
    expect(access.permissions.value).toEqual([permission('second', 'bruno')])
    expect(access.loading.value).toBe(false)
  })

  it('does not replace the selected number with a late error from the previous request', async () => {
    const first = deferred<Permission[]>()
    const { device, access } = setup((id) => id === 'first' ? first.promise : Promise.resolve([permission('second', 'bruno')]))
    device.value = 'first'
    device.value = 'second'
    await nextTick()
    first.reject(new Error('resposta antiga'))
    await nextTick()
    expect(access.error.value).toBe('')
    expect(access.permissions.value).toEqual([permission('second', 'bruno')])
  })

  it('lets the user retry a failed request without selecting another number', async () => {
    const request = vi.fn<(device: string) => Promise<Permission[]>>()
      .mockRejectedValueOnce(new Error('temporariamente indisponível'))
      .mockResolvedValueOnce([permission('first', 'ana')])
    const { device, access } = setup(request)
    device.value = 'first'
    await nextTick()
    expect(access.error.value).toBe('temporariamente indisponível')
    expect(access.loading.value).toBe(false)
    access.refresh()
    await nextTick()
    expect(request).toHaveBeenLastCalledWith('first')
    expect(access.error.value).toBe('')
    expect(access.permissions.value).toEqual([permission('first', 'ana')])
  })

  it('drops results after the console is unmounted or the selection is cleared', async () => {
    const pending = deferred<Permission[]>()
    const { device, access, scope } = setup(() => pending.promise)
    device.value = 'first'
    device.value = ''
    expect(access.permissions.value).toEqual([])
    expect(access.loading.value).toBe(false)
    scope.stop()
    pending.resolve([permission('first', 'ana')])
    await nextTick()
    expect(access.permissions.value).toEqual([])
  })
})

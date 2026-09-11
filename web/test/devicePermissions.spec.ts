import { describe, expect, it, vi } from 'vitest'
import { changeDevicePermission, PermissionChangeError } from '../src/state/devicePermissions'

function operations() { return {current:vi.fn(() => true), grant:vi.fn(async () => {}), revoke:vi.fn(async () => {}), save:vi.fn(async () => {})} }
describe('number permissions and encrypted access', () => {
  it('delivers a key before enabling reading in the ACL', async () => {
    const order:string[] = [], work = operations()
    work.grant.mockImplementation(async () => { order.push('grant') })
    work.save.mockImplementation(async () => { order.push('save') })
    expect(await changeDevicePermission({read:true,has_key:false},work)).toBe(true)
    expect(order).toEqual(['grant','save']); expect(work.revoke).not.toHaveBeenCalled()
  })
  it('does not disable reading if the server refuses removal of the last reader', async () => {
    const work = operations(); work.revoke.mockRejectedValue(new Error('last_device_reader'))
    await expect(changeDevicePermission({read:false,has_key:true},work)).rejects.toMatchObject({message:'last_device_reader',keyChanged:false})
    expect(work.save).not.toHaveBeenCalled()
  })
  it('does not report a granted ACL after password/key sharing fails', async () => {
    const work = operations(); work.grant.mockRejectedValue(new Error('incorrect password'))
    await expect(changeDevicePermission({read:true,has_key:false},work)).rejects.toMatchObject({keyChanged:false})
    expect(work.save).not.toHaveBeenCalled()
  })
  it('exposes partial success when the key changed but the ACL update failed', async () => {
    const work = operations(); work.save.mockRejectedValue(new Error('offline'))
    const failure = await changeDevicePermission({read:true,has_key:false},work).catch(error => error)
    expect(failure).toBeInstanceOf(PermissionChangeError)
    expect(failure).toMatchObject({keyChanged:true,message:'offline'})
    expect(work.grant).toHaveBeenCalledOnce()
  })
  it('does not send a previous workspace permission after switching while sharing a key', async () => {
    const work = operations(); work.grant.mockImplementation(async () => { work.current.mockReturnValue(false) })
    expect(await changeDevicePermission({read:true,has_key:false},work)).toBe(false)
    expect(work.save).not.toHaveBeenCalled()
  })
  it('changes send/manage without unnecessarily replacing an existing reader key', async () => {
    const work = operations()
    expect(await changeDevicePermission({read:true,has_key:true},work)).toBe(true)
    expect(work.grant).not.toHaveBeenCalled(); expect(work.revoke).not.toHaveBeenCalled(); expect(work.save).toHaveBeenCalledOnce()
  })
})

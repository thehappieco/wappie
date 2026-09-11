import { beforeEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
const mock = vi.hoisted(() => ({ request:vi.fn(), profile:vi.fn(), identity:{account:'owner@example.test',tenantID:'team-one',phase:'ready'} }))
vi.mock('../src/api/workspaces', () => ({workspaceRequest:mock.request}))
vi.mock('../src/api/profile', () => ({profileRequest:mock.profile}))
vi.mock('../src/state/archive', async () => { const {reactive} = await import('vue'); return {credential:() => ({kind:'session'}),state:reactive(mock.identity)} })
import { state } from '../src/state/archive'
import { currentWorkspace, loadWorkspaceContext, loadWorkspaceMembers, saveUserProfile, workspaceState } from '../src/state/workspaces'
const oldProfile = {id:'owner',email:'owner@example.test',name:'Old owner',avatar:'data:old'}
const team = {id:'team-one',name:'Team one',kind:'team',role:'owner',status:'active'}
function deferred<T>() { let resolve!:(value:T)=>void; const promise = new Promise<T>(done => {resolve=done}); return {promise,resolve} }
beforeEach(() => {
  state.account = `person-${Math.random()}@example.test`; state.tenantID='team-one'; state.phase='ready'; vi.resetAllMocks()
  mock.request.mockResolvedValue({workspaces:[team]}); mock.profile.mockResolvedValue(oldProfile)
})
describe('workspace context isolation', () => {
  it('shares one in-flight profile/workspace read between the sidebar and account panel', async () => {
    const waiting = deferred<typeof oldProfile>(); mock.profile.mockReturnValue(waiting.promise)
    const first = loadWorkspaceContext(), second = loadWorkspaceContext()
    expect(mock.request).toHaveBeenCalledOnce(); expect(mock.profile).toHaveBeenCalledOnce()
    waiting.resolve(oldProfile); await Promise.all([first,second])
    expect(currentWorkspace.value?.name).toBe('Team one')
  })
  it('never shows an old user avatar or workspace when their requests finish after signout', async () => {
    const waiting = deferred<typeof oldProfile>(); mock.profile.mockReturnValue(waiting.promise)
    const first = loadWorkspaceContext(); state.account='different@example.test'; state.tenantID='personal-two'
    waiting.resolve(oldProfile); await first
    expect(workspaceState.profile).toBeNull(); expect(workspaceState.spaces).toEqual([])
  })
  it('does not show a saved profile from the previous identity after switching accounts', async () => {
    const waiting = deferred<typeof oldProfile>(); mock.profile.mockReturnValue(waiting.promise)
    const saving = saveUserProfile('Edited','data:avatar'); state.account='someone-else@example.test'
    waiting.resolve(oldProfile); await saving
    expect(workspaceState.profile).toBeNull()
  })
  it('discards member/key metadata that belongs to a workspace already left', async () => {
    const waiting = deferred<{members:unknown[]}>(); mock.request.mockReturnValue(waiting.promise)
    const loading = loadWorkspaceMembers(); state.tenantID='other-team'
    waiting.resolve({members:[{id:'private-person',email:'private@example.test',device_access:[{device_id:'private-number',has_key:true}]}]})
    expect(await loading).toEqual([]); expect(workspaceState.members).toEqual([])
  })
  it('retains workspace metadata and a visible error if just the profile request fails', async () => {
    mock.profile.mockRejectedValue(new Error('Profile unavailable'))
    await loadWorkspaceContext(); await nextTick()
    expect(workspaceState.spaces).toHaveLength(1); expect(workspaceState.profile).toBeNull(); expect(workspaceState.error).toBe('Profile unavailable')
  })
})

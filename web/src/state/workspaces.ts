import { computed, reactive, watch } from 'vue'
import { workspaceRequest, type Member, type Workspace } from '../api/workspaces'
import { profileRequest, type UserProfile } from '../api/profile'
import { credential, state } from './archive'

export const workspaceState = reactive({ spaces: [] as Workspace[], profile: null as UserProfile | null, members: [] as Member[], loading: false, error: '', revision: 0 })
export const currentWorkspace = computed(() => workspaceState.spaces.find(space => space.id === state.tenantID))
let generation = 0
let pending: Promise<void> | undefined
watch([() => state.account, () => state.tenantID, () => state.phase === 'locked'], () => {
  generation++; pending = undefined
  Object.assign(workspaceState, { spaces: [], profile: null, members: [], loading: false, error: '', revision: workspaceState.revision + 1 })
}, { flush: 'sync' })
export async function loadWorkspaceContext(force = false): Promise<void> {
  if (credential()?.kind !== 'session') return
  if (pending) return pending
  if (!force && workspaceState.profile && workspaceState.spaces.length) return
  const current = generation
  workspaceState.loading = true; workspaceState.error = ''
  const task = (async () => {
    const results = await Promise.allSettled([workspaceRequest<{ workspaces: Workspace[] }>(''), profileRequest()])
    if (generation !== current) return
    if (results[0].status === 'fulfilled') workspaceState.spaces = results[0].value.workspaces ?? []
    else workspaceState.error = results[0].reason instanceof Error ? results[0].reason.message : String(results[0].reason)
    if (results[1].status === 'fulfilled') workspaceState.profile = results[1].value
    else if (!workspaceState.error) workspaceState.error = results[1].reason instanceof Error ? results[1].reason.message : String(results[1].reason)
    workspaceState.loading = false
  })()
  pending = task
  try { await task } finally { if (pending === task) pending = undefined }
}
export async function loadWorkspaceMembers(): Promise<Member[]> {
  const current = generation
  const reply = await workspaceRequest<{ members: Member[] }>('/members')
  if (generation !== current) return []
  workspaceState.members = reply.members ?? []
  return workspaceState.members
}
export function workspaceChanged(): void { workspaceState.revision++ }
export async function saveUserProfile(name: string, avatar: string): Promise<void> {
  const current = generation
  const profile = await profileRequest({ name, avatar })
  if (generation === current) workspaceState.profile = profile
}

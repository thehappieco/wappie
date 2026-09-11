import { createRenderer, nextTick, reactive, ref, ssrContextKey } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Member } from '../src/api/workspaces'

const mocks = vi.hoisted(() => ({ request:vi.fn(), context:vi.fn(), members:vi.fn(), changed:vi.fn(), keys:vi.fn(), state:{} as Record<string,unknown>, workspaceState:{} as Record<string,unknown>, admin:{} as Record<string,unknown> }))
vi.mock('../src/state/archive', () => ({state:mocks.state}))
vi.mock('../src/api/workspaces', () => ({workspaceRequest:mocks.request}))
vi.mock('../src/state/workspaces', () => ({currentWorkspace:ref({id:'team',name:'Team',kind:'team'}),workspaceState:mocks.workspaceState,loadWorkspaceContext:mocks.context,loadWorkspaceMembers:mocks.members,workspaceChanged:mocks.changed}))
vi.mock('../src/state/admin', () => ({admin:mocks.admin,loadKeys:mocks.keys,openDetail:vi.fn()}))
vi.mock('../src/ui/i18n', () => ({ t:(text:string, values:Record<string,string>={})=>text.replace(/\{(\w+)\}/g,(_,key)=>values[key]??''),intlLocale:()=> 'pt-BR' }))
interface Node {parent:Node|null;children:Node[]}
const node=():Node=>({parent:null,children:[]})
const renderer=createRenderer<Node,Node>({createElement:node,createText:node,createComment:node,patchProp(){},setText(){},setElementText(){},parentNode:n=>n.parent,nextSibling:()=>null,insert(n,parent){n.parent=parent;parent.children.push(n)},remove(){}})
interface Form { members:Member[]; removing:Member|null; error:string; notice:string; busy:boolean; originals:Record<string,{role:string;status:string}>; canRemove(member:Member):boolean; askRemove(member:Member):void; cancelRemove():void; removeMember():Promise<void>; load():Promise<void> }
const person:Member={id:'member',email:'member@example.test',name:'Taylor Reed',role:'member',status:'active',device_access:[]}
let unmount:(()=>void)|undefined
mocks.state=reactive({account:'owner@example.test',tenantID:'team',role:'owner'})
mocks.workspaceState=reactive({profile:{id:'self'},revision:0,members:[] as Member[]})
mocks.admin=reactive({accounts:[] as {id:string}[],detail:null as {readers:{user_id:string}[]}|null})
const settle=async()=>{for(let i=0;i<5;i++)await nextTick()}
beforeEach(()=>{
  vi.clearAllMocks();Object.assign(mocks.state,{account:'owner@example.test',tenantID:'team',role:'owner'})
  Object.assign(mocks.workspaceState,{profile:{id:'self'},revision:0,members:[{...person}]});Object.assign(mocks.admin,{accounts:[{id:person.id}],detail:{readers:[{user_id:person.id}]}})
  mocks.context.mockResolvedValue(undefined);mocks.members.mockResolvedValue([{...person}]);mocks.request.mockResolvedValue({invites:[]});mocks.keys.mockResolvedValue(undefined)
})
afterEach(()=>{unmount?.();unmount=undefined})
async function mount():Promise<Form>{
  const Component=(await import('../src/components/WorkspacePanel.vue')).default
  const app=renderer.createApp({...Component,render:()=>null});app.provide(ssrContextKey,{})
  const instance=app.mount(node()) as unknown as {$:{setupState:Form}};unmount=()=>app.unmount();await settle();return instance.$.setupState
}
function deferred(){let resolve!:(value:unknown)=>void;return {promise:new Promise(done=>{resolve=done}),resolve:(value:unknown)=>resolve(value)}}
describe('workspace member removal',()=>{
  it('requires explicit confirmation; cancelling sends no removal request',async()=>{
    const form=await mount();mocks.request.mockClear();form.askRemove(form.members[0]!);expect(form.removing?.name).toBe('Taylor Reed');expect(mocks.request).not.toHaveBeenCalled()
    form.cancelRemove();await form.removeMember();expect(form.removing).toBeNull();expect(mocks.request).not.toHaveBeenCalled();expect(form.members).toHaveLength(1)
  })
  it('uses saved roles, protects the final owner and own account, and allows service removal',async()=>{
    const form=await mount();const candidates:Member[]=[person,{...person,id:'owner',role:'owner'},{...person,id:'admin',role:'admin'},{...person,id:'service',role:'service'}]
    for(const member of [...candidates,{...person,id:'self'}])form.originals[member.id]={role:member.role,status:member.status}
    for(const member of candidates)expect(form.canRemove(member)).toBe(true)
    expect(form.canRemove({...person,last_owner:true})).toBe(false);expect(form.canRemove({...person,id:'self'})).toBe(false);expect(form.canRemove({...person,email:'OWNER@example.test'})).toBe(false)
    mocks.state.role='admin';expect(candidates.map(member=>form.canRemove(member))).toEqual([true,false,false,true])
    expect(form.canRemove({...candidates[1]!,role:'member'})).toBe(false)
    expect(form.canRemove({...person,role:'owner'})).toBe(true)
    for(const role of ['member','service','']){mocks.state.role=role;expect(form.canRemove(person)).toBe(false)}
  })
  it.each(['last_owner','last_device_reader'])('keeps the confirmation and member after backend protection %s',async(code)=>{
    const form=await mount();form.askRemove(form.members[0]!);mocks.request.mockRejectedValue(new Error(code));await form.removeMember()
    expect(form.removing?.id).toBe(person.id);expect(form.members).toHaveLength(1);expect(form.error).toBe(code);expect(form.busy).toBe(false);expect(mocks.changed).not.toHaveBeenCalled()
  })
  it('blocks duplicate confirmation and closes only after 204, clearing cached grants',async()=>{
    const form=await mount();const waiting=deferred();form.askRemove(form.members[0]!);mocks.request.mockReturnValue(waiting.promise);mocks.request.mockClear()
    const removing=form.removeMember();form.cancelRemove();await form.removeMember();expect(form.removing?.id).toBe(person.id);expect(form.busy).toBe(true);expect(mocks.request).toHaveBeenCalledExactlyOnceWith('/members/member','DELETE')
    waiting.resolve(undefined);await removing;expect(form.removing).toBeNull();expect(form.members).toEqual([]);expect(mocks.workspaceState.members).toEqual([]);expect(mocks.admin.accounts).toEqual([]);expect(mocks.admin.detail).toEqual({readers:[]});expect(form.notice).toContain('Taylor Reed');expect(mocks.changed).toHaveBeenCalledOnce();expect(mocks.keys).toHaveBeenCalledOnce()
  })
  it('never reopens a completed deletion when the member list refresh fails',async()=>{
    const form=await mount();form.askRemove(form.members[0]!);mocks.request.mockResolvedValue(undefined);mocks.request.mockClear();await form.removeMember();mocks.members.mockRejectedValue(new Error('Refresh unavailable'));await form.load();await form.removeMember()
    expect(form.error).toBe('Refresh unavailable');expect(form.notice).toContain('Taylor Reed');expect(form.removing).toBeNull();expect(form.members).toEqual([]);expect(mocks.request.mock.calls.filter(([,method])=>method==='DELETE')).toHaveLength(1)
  })
  it.each(['tenantID','account'])('discards a late removal reply after %s changes',async(key)=>{
    const form=await mount();const waiting=deferred();form.askRemove(form.members[0]!);mocks.request.mockReturnValue(waiting.promise);const removing=form.removeMember();mocks.state[key]='other';await nextTick();waiting.resolve(undefined);await removing
    expect(form.removing).toBeNull();expect(form.notice).toBe('');expect(mocks.changed).not.toHaveBeenCalled();expect(mocks.admin.accounts).toEqual([{id:person.id}])
  })
  it('does not mutate shared lists after the panel is unmounted',async()=>{
    const form=await mount();const waiting=deferred();form.askRemove(form.members[0]!);mocks.request.mockReturnValue(waiting.promise);const removing=form.removeMember();unmount!();unmount=undefined;waiting.resolve(undefined);await removing
    expect(mocks.changed).not.toHaveBeenCalled();expect(mocks.admin.accounts).toEqual([{id:person.id}])
  })
})

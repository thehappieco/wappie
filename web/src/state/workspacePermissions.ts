import { ref, watch, type Ref } from 'vue'
import { workspaceRequest, type Permission } from '../api/workspaces'

/** The displayed access list always belongs to the selected WhatsApp number. */
export function useWorkspacePermissions(
  device: Ref<string>,
  request: (deviceID: string) => Promise<Permission[]> = async (deviceID) =>
    (await workspaceRequest<{ permissions: Permission[] }>(`/devices/${deviceID}/permissions`)).permissions ?? [],
) {
  const permissions = ref<Permission[]>([])
  const loading = ref(false)
  const error = ref('')
  const reload = ref(0)

  watch([device, reload], async ([deviceID], _previous, onCleanup) => {
    let current = true
    onCleanup(() => { current = false })
    permissions.value = []
    error.value = ''
    loading.value = Boolean(deviceID)
    if (!deviceID) return
    try {
      const rows = await request(deviceID)
      if (!current || device.value !== deviceID) return
      permissions.value = rows.filter((permission) => permission.device_id === deviceID)
    } catch (err) {
      if (current) error.value = err instanceof Error ? err.message : String(err)
    } finally {
      if (current) loading.value = false
    }
  }, { immediate: true, flush: 'sync' })

  return { permissions, loading, error, refresh: () => { reload.value++ } }
}

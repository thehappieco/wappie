import type { Permission } from '../api/workspaces'

export class PermissionChangeError extends Error {
  constructor(readonly keyChanged: boolean, cause: unknown) {
    super(cause instanceof Error ? cause.message : String(cause), { cause })
    this.name = 'PermissionChangeError'
  }
}

/** Key delivery/revocation precedes the ACL write, so a rejected last-reader
 * removal cannot first disable the reader and leave its number inaccessible. */
export async function changeDevicePermission(
  permission: Pick<Permission, 'read' | 'has_key'>,
  operations: { current: () => boolean; grant: () => Promise<void>; revoke: () => Promise<void>; save: () => Promise<void> },
): Promise<boolean> {
  let keyChanged = false
  try {
    if (!operations.current()) return false
    if (permission.read && !permission.has_key) {
      await operations.grant(); keyChanged = true
    } else if (!permission.read && permission.has_key) {
      await operations.revoke(); keyChanged = true
    }
    if (!operations.current()) return false
    await operations.save()
    return operations.current()
  } catch (error) { throw new PermissionChangeError(keyChanged, error) }
}

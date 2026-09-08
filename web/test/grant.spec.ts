import { describe, expect, it } from 'vitest'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { fileURLToPath, URL } from 'node:url'

import { generateAccountKeys } from '../src/crypto/account'
import { formatUUID, fromBase64, newUUIDv7, parseUUID, toBase64, type Bytes } from '../src/crypto/bytes'
import { importArchiveKey } from '../src/crypto/hpke'
import { grantRow, Kind, openDirect, sealDirect, SealError } from '../src/crypto/seal'

// This is the only thing the browser seals, and it is the one blob whose being
// wrong is invisible.
//
// A key grant is a device's private archive key encrypted to one account. If
// the binding is off by a byte, pairing still succeeds, the row still stores,
// and the archive that device goes on to fill is unreadable by anybody — the
// device key existed for a few milliseconds in a browser tab that has since
// closed. There is no error to notice and nothing to recover.
//
// So this file does two things. It round-trips, which catches the obvious
// breakage. And it writes a vector that Go opens, which is the check that
// matters: the two implementations agree, or one of them fails here rather than
// on somebody's messages.

const vectorPath = fileURLToPath(new URL('../testdata/browser-grant.json', import.meta.url))

describe('sealing a key grant', () => {
  it('opens again with the account key it was sealed to', async () => {
    const tenant = parseUUID(newUUIDv7())
    const device = parseUUID(newUUIDv7())
    const user = parseUUID(newUUIDv7())
    const epoch = 1

    const account = await generateAccountKeys()
    const deviceKey = crypto.getRandomValues(new Uint8Array(32)) as Bytes

    const row = await grantRow(tenant, device, user, epoch)
    const sealed = await sealDirect(
      account.publicKey,
      Kind.DeviceGrant,
      tenant,
      row,
      epoch,
      deviceKey,
    )

    const opened = await openDirect(
      await importArchiveKey(account.privateKey),
      Kind.DeviceGrant,
      tenant,
      row,
      sealed,
    )
    expect(Array.from(opened)).toEqual(Array.from(deviceKey))
  })

  it('does not open for a different account', async () => {
    const tenant = parseUUID(newUUIDv7())
    const device = parseUUID(newUUIDv7())
    const user = parseUUID(newUUIDv7())

    const mine = await generateAccountKeys()
    const theirs = await generateAccountKeys()
    const deviceKey = crypto.getRandomValues(new Uint8Array(32)) as Bytes

    const row = await grantRow(tenant, device, user, 1)
    const sealed = await sealDirect(mine.publicKey, Kind.DeviceGrant, tenant, row, 1, deviceKey)

    await expect(
      openDirect(
        await importArchiveKey(theirs.privateKey),
        Kind.DeviceGrant,
        tenant,
        row,
        sealed,
      ),
    ).rejects.toThrow(SealError)
  })

  it('does not open under another device, with the right key in hand', async () => {
    const tenant = parseUUID(newUUIDv7())
    const device = parseUUID(newUUIDv7())
    const other = parseUUID(newUUIDv7())
    const user = parseUUID(newUUIDv7())

    const account = await generateAccountKeys()
    const deviceKey = crypto.getRandomValues(new Uint8Array(32)) as Bytes

    const sealed = await sealDirect(
      account.publicKey,
      Kind.DeviceGrant,
      tenant,
      await grantRow(tenant, device, user, 1),
      1,
      deviceKey,
    )

    // The row is what carries the device, so presenting the grant as another
    // device's is what has to fail. Without that binding, one operator's key
    // opens another operator's WhatsApp account — which is the entire reason
    // the key is per device.
    await expect(
      openDirect(
        await importArchiveKey(account.privateKey),
        Kind.DeviceGrant,
        tenant,
        await grantRow(tenant, other, user, 1),
        sealed,
      ),
    ).rejects.toThrow(SealError)
  })

  it('keeps a vector Go can open', async () => {
    // A test that writes a file is unusual, and this one earns it: the vector
    // has to be produced by this implementation to be worth anything, and the
    // Go side must be able to read it without a JavaScript toolchain
    // installed. TestABrowserSealedGrantOpensInGo consumes it.
    //
    // It is written once and then left alone. Rewriting on every run would put
    // a fresh ephemeral key in the diff after every `npm test`, and a file that
    // is always dirty is a file somebody eventually adds to .gitignore. To
    // regenerate after changing how a grant is sealed:
    //
    //   WS_REGEN_VECTORS=1 npm test
    //
    // Then run the Go tests. If they still pass, the two implementations agree
    // about the new shape; if they do not, one of them is wrong and this is
    // where it shows.
    const tenant = parseUUID('018f3a2b-0000-7000-8000-000000000001')
    const device = parseUUID('018f3a2b-0000-7000-8000-000000000002')
    const user = parseUUID('018f3a2b-0000-7000-8000-000000000003')
    const epoch = 3

    const row = await grantRow(tenant, device, user, epoch)

    if (process.env.WS_REGEN_VECTORS || !existsSync(vectorPath)) {
      const account = await generateAccountKeys()
      const deviceKey = crypto.getRandomValues(new Uint8Array(32)) as Bytes
      const sealed = await sealDirect(
        account.publicKey,
        Kind.DeviceGrant,
        tenant,
        row,
        epoch,
        deviceKey,
      )
      mkdirSync(dirname(vectorPath), { recursive: true })
      writeFileSync(
        vectorPath,
        JSON.stringify(
          {
            note:
              'Sealed by web/test/grant.spec.ts, opened by Go in ' +
              'internal/crypto/seal/browser_test.go. Regenerate with: ' +
              'cd web && WS_REGEN_VECTORS=1 npm test',
            tenant: formatUUID(tenant),
            device: formatUUID(device),
            user: formatUUID(user),
            epoch,
            account_private_key: toBase64(account.privateKey),
            account_public_key: toBase64(account.publicKey),
            device_key: toBase64(deviceKey),
            grant_row: formatUUID(row),
            sealed: toBase64(sealed),
          },
          null,
          2,
        ) + '\n',
      )
    }

    // Whether it was just written or read from the repository, it has to say
    // what it claims — otherwise the Go test is opening a fixture nothing here
    // stands behind.
    const vector = JSON.parse(readFileSync(vectorPath, 'utf8')) as {
      grant_row: string
      account_private_key: string
      device_key: string
      sealed: string
    }
    expect(vector.grant_row).toBe(formatUUID(row))

    const opened = await openDirect(
      await importArchiveKey(fromBase64(vector.account_private_key)),
      Kind.DeviceGrant,
      tenant,
      row,
      fromBase64(vector.sealed),
    )
    expect(toBase64(opened)).toBe(vector.device_key)
  })
})

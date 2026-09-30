// The configuration tags of an AI authorization (docs/mcp-enclave.md §18.7
// step 4). The creator's browser, which holds every covered number's DSK,
// binds the whole authorization (its keys' hashes, functions, features,
// budget, expiry and service account) to each number under a key derived
// from that DSK; the enclave recomputes each tag from the DSK its grant
// opens. At install that makes a bundle Go sealed itself, to the attested
// key with the operator's API key and the person's genuine grants, fail
// (N-AI-1, I3); before any content goes to a provider it makes a grant Go
// swapped since install fail too (I3a, N-AI-1b): the reader fetches grants on
// every call, so a check at install alone would not do.
import { timingSafeEqual } from 'node:crypto'
import { aiConfigScope, aiConfigTag } from '@whatserver2/mcp/bundle'

/**
 * What a record keeps to recompute its tags: the scope's fields as sealed
 * (the bundle's `expires_at` string, not the deadline Go may shorten), the
 * keys' hashes, and the request (or renewal) id and key id they were made
 * under.
 */
export function tagFields(record) {
  return {
    workspace_id: record.workspace_id, service_user_id: record.service_user_id, device_ids: record.device_ids, keys_sha256: record.keys_sha256,
    functions: record.functions, features: record.features, budget: record.budget, expires_at: record.bundle_expires_at, key_mode: record.key_mode,
  }
}

/** `cfg_tag[device]` for `fields` with DSK(device, epoch) (the caller's to zero). */
export function configTag(dsk, fields, { device, namespace, epoch, request, kid }) {
  return aiConfigTag(dsk, { namespace, deviceID: device, epoch, config: aiConfigScope(fields, { deviceID: device, epoch, request, kid }) })
}

/** Whether `given` is the tag `dsk` makes for this device, compared in constant time. */
export function tagMatches(dsk, fields, binding, given) {
  const expected = Buffer.from(configTag(dsk, fields, binding))
  const presented = Buffer.from(typeof given === 'string' ? given : '')
  return expected.length === presented.length && timingSafeEqual(expected, presented)
}

/**
 * I3a: the record's stored tag for `device`, recomputed with the DSK that
 * opened this content (`keys`, the reader's `{dsk, namespace, epoch}`), at
 * the epoch and namespace the record was installed with.
 */
export function recordTagHolds(record, device, keys) {
  if (!keys || keys.epoch !== record.epochs?.[device] || keys.namespace !== record.ns?.[device]) return false
  return tagMatches(keys.dsk, tagFields(record), { device, namespace: keys.namespace, epoch: keys.epoch, request: record.request, kid: record.kid }, record.cfg_tags?.[device])
}

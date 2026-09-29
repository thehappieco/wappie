// A zip archive seen as an OOXML or ODF package: parts by name (OOXML part
// names are case-insensitive), XML parts decoded, relationship targets
// resolved. Only internal targets are ever followed: a relationship with
// TargetMode="External" (a link, a remote image) is never read or fetched,
// and a target outside the package is simply absent.

import { Inflater } from './zip.mjs'
import { decodeXml, parseXml } from './xml.mjs'

export class Package {
  constructor(buf, entries, limits) {
    this.inflater = new Inflater(buf, limits)
    this.parts = new Map()
    for (const e of entries) if (!e.directory) this.parts.set(e.name.toLowerCase(), e)
  }

  has(name) {
    return this.parts.has(name.toLowerCase())
  }

  bytes(name) {
    const entry = this.parts.get(name.toLowerCase())
    return entry ? this.inflater.read(entry) : null
  }

  xml(name) {
    const bytes = this.bytes(name)
    return bytes ? decodeXml(bytes) : null
  }

  /** The internal relationships of `part`: Map of Id to resolved part name. */
  relationships(part) {
    const slash = part.lastIndexOf('/')
    const dir = slash === -1 ? '' : part.slice(0, slash + 1)
    const xml = this.xml(`${dir}_rels/${part.slice(slash + 1)}.rels`)
    const out = new Map()
    if (!xml) return out
    parseXml(xml, {
      open(name, attrs) {
        if (name !== 'rel:Relationship' || !attrs.Id || !attrs.Target) return
        if ((attrs.TargetMode ?? 'Internal') !== 'Internal') return
        const target = resolvePart(dir, attrs.Target)
        if (target) out.set(attrs.Id, target)
      },
      text() {},
      close() {},
    })
    return out
  }
}

/** A relationship target relative to `dir`, or null if it leaves the package. */
export function resolvePart(dir, target) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(target)) return null
  const parts = (target.startsWith('/') ? target.slice(1) : dir + target).split('/')
  const out = []
  for (const p of parts) {
    if (p === '' || p === '.') continue
    if (p === '..') {
      if (!out.length) return null
      out.pop()
    } else {
      out.push(p)
    }
  }
  return out.length ? out.join('/') : null
}

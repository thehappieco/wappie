// The office worker's own readers: zip (with the bomb checks), CFB and XML.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { deflateRawSync } from 'node:zlib'
import { readZip, Inflater } from '../lib/zip.mjs'
import { cfbNames, classifyCfb } from '../lib/cfb.mjs'
import { parseXml, decodeXml, unescapeXml, MAX_DEPTH } from '../lib/xml.mjs'
import { resolvePart } from '../lib/package.mjs'
import { sheetName, csvField } from '../lib/csv.mjs'
import { zip } from './corpus.mjs'
import * as XLSX from 'xlsx'

const LIMITS = { entries: 2_000, inflated: 104_857_600, ratio: 100 }

test('readZip lists names, UTF-8 when flagged and CP437 otherwise', () => {
  const buf = zip([
    { name: 'dir/', data: '' },
    { name: 'ünï.txt', data: 'a' },
    { name: Buffer.from([0x80, 0x81, 0xe1, 0xff]).toString('latin1'), data: 'b', cp437: true },
  ])
  const { entries } = readZip(buf, LIMITS)
  assert.deepEqual(entries.map((e) => e.name), ['dir/', 'ünï.txt', 'Çüß '])
  assert.equal(entries[0].directory, true)
})

test('the declared checks refuse before anything is inflated', () => {
  const many = zip(Array.from({ length: 11 }, (_, i) => ({ name: `${i}`, data: '' })))
  assert.throws(() => readZip(many, { ...LIMITS, entries: 10 }), (e) => e.code === 'too_large' && e.what === 'entries')
  const dense = zip([{ name: 'z', data: Buffer.alloc(100_000) }])
  assert.throws(() => readZip(dense, LIMITS), (e) => e.what === 'inflated')
  const total = zip([{ name: 'a', data: 'x'.repeat(600) }, { name: 'b', data: 'y'.repeat(600) }])
  assert.throws(() => readZip(total, { ...LIMITS, inflated: 1_000, ratio: 1_000 }), (e) => e.what === 'inflated')
  const noCompressed = zip([{ name: 'n', data: 'abc', compressed: Buffer.alloc(0), declaredSize: 5 }])
  assert.throws(() => readZip(noCompressed, LIMITS), (e) => e.what === 'inflated')
})

test('inflating counts: a lie about the size or the CRC is caught', () => {
  const data = Buffer.from('x'.repeat(5_000))
  const lying = zip([{ name: 'l', data, declaredSize: 100 }])
  const { entries } = readZip(lying, { ...LIMITS, ratio: 1_000 })
  assert.throws(() => new Inflater(lying, LIMITS).read(entries[0]), (e) => e.what === 'inflated')
  const short = zip([{ name: 's', data, declaredSize: 6_000 }])
  assert.throws(() => new Inflater(short, LIMITS).read(readZip(short, { ...LIMITS, ratio: 1_000 }).entries[0]), (e) => e.code === 'damaged')
  const badCrc = zip([{ name: 'c', data, crc: 1 }])
  assert.throws(() => new Inflater(badCrc, LIMITS).read(readZip(badCrc, { ...LIMITS, ratio: 1_000 }).entries[0]), (e) => e.code === 'damaged')
  const budget = zip([{ name: 'a', data }, { name: 'b', data }])
  const inflater = new Inflater(budget, { inflated: 9_000 })
  const both = readZip(budget, { ...LIMITS, ratio: 1_000 }).entries
  assert.equal(inflater.read(both[0]).length, 5_000)
  assert.throws(() => inflater.read(both[1]), (e) => e.what === 'inflated')
  const encrypted = zip([{ name: 'e', data: 'x', flags: 1 }])
  assert.throws(() => new Inflater(encrypted, LIMITS).read(readZip(encrypted, LIMITS).entries[0]), (e) => e.code === 'encrypted')
  const stored = zip([{ name: 'st', data: 'stored bytes', method: 0 }])
  assert.equal(new Inflater(stored, LIMITS).read(readZip(stored, LIMITS).entries[0]).toString(), 'stored bytes')
  assert.equal(deflateRawSync(Buffer.alloc(1)).length > 0, true)
})

test('a damaged central directory is damaged, never a crash', () => {
  const good = zip([{ name: 'a', data: 'abc' }])
  for (let cut = 1; cut < good.length; cut += 3) {
    try {
      readZip(good.subarray(0, cut), LIMITS)
    } catch (e) {
      assert.ok(['damaged', 'unsupported'].includes(e.code), `cut ${cut}: ${e}`)
    }
  }
})

test('CFB directories: xls, encrypted OOXML, anything else', () => {
  const make = (streams) => {
    const c = XLSX.CFB.utils.cfb_new()
    for (const [n, d] of Object.entries(streams)) XLSX.CFB.utils.cfb_add(c, n, d)
    return XLSX.CFB.write(c, { type: 'buffer' })
  }
  assert.equal(classifyCfb(make({ Workbook: Buffer.alloc(5_000) }), 2_000), 'xls')
  assert.equal(classifyCfb(make({ Book: Buffer.alloc(10) }), 2_000), 'xls')
  assert.equal(classifyCfb(make({ EncryptionInfo: Buffer.alloc(10), EncryptedPackage: Buffer.alloc(10) }), 2_000), 'encrypted')
  assert.equal(classifyCfb(make({ WordDocument: Buffer.alloc(10) }), 2_000), null)
  const names = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`s${i}`, Buffer.alloc(8)]))
  assert.throws(() => cfbNames(make(names), 10), (e) => e.what === 'entries')
  const junk = Buffer.concat([Buffer.from('d0cf11e0a1b11ae1', 'hex'), Buffer.alloc(600, 0xff)])
  assert.throws(() => cfbNames(junk, 2_000), (e) => e.code === 'damaged')
})

function events(xml) {
  const out = []
  parseXml(xml, {
    open: (n, a) => out.push(['open', n, a]),
    text: (s) => out.push(['text', s]),
    close: (n) => out.push(['close', n]),
  })
  return out
}

test('XML: namespaces resolve to canonical prefixes, whatever the document calls them', () => {
  const doc = '<d xmlns="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:q="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><q:t q:val="1" plain="2">x</q:t><p/></d>'
  assert.deepEqual(events(doc), [
    ['open', 'text:d', {}],
    ['open', 'w:t', { 'w:val': '1', plain: '2' }],
    ['text', 'x'],
    ['close', 'w:t'],
    ['open', 'text:p', {}],
    ['close', 'text:p'],
    ['close', 'text:d'],
  ])
  // A declaration on a child is gone once the child closes.
  const scoped = events('<a><b xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:c/></b><w:c/></a>')
  assert.deepEqual(scoped.filter((e) => e[0] === 'open').map((e) => e[1]), ['a', 'b', 'w:c', 'w:c'])
})

test('XML: entities, character references, CDATA and comments', () => {
  assert.equal(unescapeXml('&lt;a&gt; &amp;&quot;&apos; &#65;&#x1F600; &bogus; &#0; &#xD800;'), `<a> &"' A😀 &bogus;  `)
  const out = events('<?xml version="1.0"?><!-- c --><r><![CDATA[<raw>&amp;]]></r>')
  assert.deepEqual(out, [['open', 'r', {}], ['text', '<raw>&amp;'], ['close', 'r']])
  assert.equal(decodeXml(Buffer.from('﻿<a/>', 'utf16le').subarray(0)).includes('<a/>'), true)
  assert.equal(decodeXml(Buffer.from('<?xml version="1.0" encoding="windows-1252"?><a>\xe9</a>', 'latin1')).includes('é'), true)
})

test('XML: DOCTYPE, mismatched tags, truncation and depth are damaged', () => {
  const bad = [
    '<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>',
    '<a><b></a></b>',
    '<a><b>',
    '<a attr="unterminated',
    `${'<a>'.repeat(MAX_DEPTH + 1)}${'</a>'.repeat(MAX_DEPTH + 1)}`,
  ]
  for (const xml of bad) assert.throws(() => events(xml), (e) => e.code === 'damaged', xml.slice(0, 20))
  assert.doesNotThrow(() => events(`${'<a>'.repeat(MAX_DEPTH)}${'</a>'.repeat(MAX_DEPTH)}`))
})

test('relationship targets stay inside the package', () => {
  assert.equal(resolvePart('ppt/', 'slides/slide1.xml'), 'ppt/slides/slide1.xml')
  assert.equal(resolvePart('ppt/slides/', '../media/a.png'), 'ppt/media/a.png')
  assert.equal(resolvePart('ppt/', '/ppt/slides/slide2.xml'), 'ppt/slides/slide2.xml')
  assert.equal(resolvePart('ppt/', '../../etc/passwd'), null)
  assert.equal(resolvePart('word/', 'file:///etc/passwd'), null)
  assert.equal(resolvePart('word/', 'http://169.254.169.254/'), null)
})

test('sheet names fit a SECTION and CSV fields quote what RFC 4180 says', () => {
  assert.equal(sheetName('a\u0000b\u009fc', 0), 'abc')
  assert.equal(sheetName('', 2), 'Sheet3')
  assert.equal(sheetName('x'.repeat(300), 0).length, 100)
  assert.equal(sheetName(`${'x'.repeat(99)}😀`, 0), 'x'.repeat(99))
  assert.ok(Buffer.byteLength(JSON.stringify({ sheet: sheetName('"\\'.repeat(100), 0), rows: 2000, total_rows: 1e6 })) <= 512)
  assert.equal(csvField('plain'), 'plain')
  assert.equal(csvField('a,b'), '"a,b"')
  assert.equal(csvField('say "hi"'), '"say ""hi"""')
  assert.equal(csvField('two\nlines'), '"two\nlines"')
})
